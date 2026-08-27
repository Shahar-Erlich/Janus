from __future__ import annotations

import asyncio
import logging

from app import janus_packet_pb2

from .state import AppState
from .wire import read_framed_message

logger = logging.getLogger(__name__)


async def start_ingest_server(state: AppState) -> asyncio.AbstractServer:
    return await asyncio.start_server(
        lambda reader, writer: _handle_connection(reader, writer, state),
        host=state.settings.tcp_host,
        port=state.settings.tcp_port,
    )


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: AppState,
) -> None:
    peer = writer.get_extra_info("peername")
    logger.info("core connection opened from %s", peer)
    try:
        while True:
            payload = await read_framed_message(
                reader,
                max_frame_bytes=state.settings.tcp_max_frame_bytes,
            )
            event = janus_packet_pb2.PacketDecisionEvent()
            event.ParseFromString(payload)
            state.counters.tcp_messages_received += 1
            try:
                state.ingest_queue.put_nowait(event)
            except asyncio.QueueFull:
                state.counters.queue_dropped += 1
                logger.warning("ingest queue full; dropping packet event")
    except asyncio.IncompleteReadError:
        logger.info("core connection closed from %s", peer)
    except ValueError as exc:
        state.counters.tcp_bad_frames += 1
        logger.warning("bad frame from %s: %s", peer, exc)
    except Exception:
        logger.exception("unexpected ingest error from %s", peer)
    finally:
        writer.close()
        await writer.wait_closed()
