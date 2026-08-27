from __future__ import annotations

import logging

from .state import AppState
from .ws_api import send_live_packet

logger = logging.getLogger(__name__)


async def writer_loop(state: AppState) -> None:
    while True:
        event = await state.ingest_queue.get()
        try:
            await state.db.insert_packet_event(event)
            state.counters.db_writes_ok += 1
            await send_live_packet(state, event)
        except Exception:
            state.counters.db_writes_failed += 1
            logger.exception("failed to persist packet decision event")
        finally:
            state.ingest_queue.task_done()
