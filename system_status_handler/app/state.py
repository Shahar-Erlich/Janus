from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket


@dataclass(slots=True)
class RuntimeCounters:
    tcp_messages_received: int = 0
    tcp_bad_frames: int = 0
    queue_dropped: int = 0
    db_writes_ok: int = 0
    db_writes_failed: int = 0
    websocket_clients: int = 0
    live_subscribers: int = 0


@dataclass
class AppState:
    db: Any
    settings: Any
    ingest_queue: asyncio.Queue[Any]
    counters: RuntimeCounters = field(default_factory=RuntimeCounters)
    live_subscribers: set[WebSocket] = field(default_factory=set)
    tcp_server: asyncio.AbstractServer | None = None
    writer_task: asyncio.Task[Any] | None = None
