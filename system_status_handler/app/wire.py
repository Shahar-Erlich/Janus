from __future__ import annotations

import asyncio
import struct
from typing import Final

UINT32_BE: Final[str] = "!I"


def pack_frame(payload: bytes) -> bytes:
    return struct.pack(UINT32_BE, len(payload)) + payload


async def read_framed_message(reader: asyncio.StreamReader, *, max_frame_bytes: int) -> bytes:
    header = await reader.readexactly(4)
    (size,) = struct.unpack(UINT32_BE, header)
    if size <= 0 or size > max_frame_bytes:
        raise ValueError(f"invalid frame size: {size}")
    return await reader.readexactly(size)
