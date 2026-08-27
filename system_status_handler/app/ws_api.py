from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app import janus_frontend_pb2

from .dashboard_builders import build_dashboard_overview
from .packet_builders import build_packet_details, build_packet_summary
from .state import AppState

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    state: AppState = websocket.app.state.janus_state
    await websocket.accept()
    state.counters.websocket_clients += 1
    logger.info("frontend websocket connected")

    try:
        while True:
            payload = await websocket.receive_bytes()
            request = janus_frontend_pb2.FrontendRequest()
            request.ParseFromString(payload)
            await _dispatch_request(state, websocket, request)
    except WebSocketDisconnect:
        logger.info("frontend websocket disconnected")
    except Exception:
        logger.exception("frontend websocket error")
    finally:
        state.live_subscribers.discard(websocket)
        state.counters.websocket_clients = max(0, state.counters.websocket_clients - 1)
        state.counters.live_subscribers = len(state.live_subscribers)


async def _dispatch_request(state: AppState, websocket: WebSocket, request: Any) -> None:
    kind = request.WhichOneof("payload")
    if not kind:
        await send_error(websocket, request.request_id, "request payload is missing")
        return

    if kind == "subscribe_live":
        enabled = bool(request.subscribe_live.enabled)
        if enabled:
            state.live_subscribers.add(websocket)
        else:
            state.live_subscribers.discard(websocket)
        state.counters.live_subscribers = len(state.live_subscribers)

        response = janus_frontend_pb2.FrontendResponse(request_id=request.request_id, ok=True)
        response.ack.message = "live subscription enabled" if enabled else "live subscription disabled"
        await websocket.send_bytes(response.SerializeToString())
        return

    if kind == "ping":
        response = janus_frontend_pb2.FrontendResponse(request_id=request.request_id, ok=True)
        response.pong.message = request.ping.message or "pong"
        response.pong.server_time_ms = int(time.time() * 1000)
        await websocket.send_bytes(response.SerializeToString())
        return

    if kind == "recent_packets":
        rows = await state.db.fetch_recent_packets(int(request.recent_packets.limit or 100))
        response = janus_frontend_pb2.FrontendResponse(request_id=request.request_id, ok=True)
        for row in rows:
            response.recent_packets.packets.add().CopyFrom(build_packet_summary(row))
        await websocket.send_bytes(response.SerializeToString())
        return

    if kind == "packet_details":
        row = await state.db.fetch_packet_details(int(request.packet_details.db_event_id))
        if row is None:
            await send_error(websocket, request.request_id, "packet details not found")
            return
        response = janus_frontend_pb2.FrontendResponse(request_id=request.request_id, ok=True)
        response.packet_details.CopyFrom(build_packet_details(row))
        await websocket.send_bytes(response.SerializeToString())
        return

    if kind == "dashboard_overview":
        payload = await state.db.fetch_dashboard_overview()
        response = janus_frontend_pb2.FrontendResponse(request_id=request.request_id, ok=True)
        response.dashboard_overview.CopyFrom(build_dashboard_overview(payload, state.ingest_queue.qsize()))
        await websocket.send_bytes(response.SerializeToString())
        return

    await send_error(websocket, request.request_id, f"unsupported request type: {kind}")


async def send_live_packet(state: AppState, event: Any) -> None:
    if not state.live_subscribers:
        return

    response = janus_frontend_pb2.FrontendResponse(ok=True)
    response.live_packet_event.CopyFrom(event)
    data = response.SerializeToString()

    dead: list[WebSocket] = []
    for websocket in list(state.live_subscribers):
        try:
            await asyncio.wait_for(
                websocket.send_bytes(data),
                timeout=state.settings.frontend_send_timeout_sec,
            )
        except Exception:
            dead.append(websocket)

    for websocket in dead:
        state.live_subscribers.discard(websocket)

    state.counters.live_subscribers = len(state.live_subscribers)


async def send_error(websocket: WebSocket, request_id: str, message: str) -> None:
    response = janus_frontend_pb2.FrontendResponse(
        request_id=request_id,
        ok=False,
        error=message,
    )
    await websocket.send_bytes(response.SerializeToString())
