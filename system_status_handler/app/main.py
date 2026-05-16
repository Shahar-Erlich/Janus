from __future__ import annotations

import asyncio
import json
import logging
import string
import ipaddress
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .database import JanusDatabase
from .ingest import start_ingest_server
from .logging_setup import configure_logging
from .settings import settings
from .state import AppState
from .writer import writer_loop
from .ws_api import router as ws_router
from .wire import pack_frame, read_framed_message

configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

RULES_LOCK = asyncio.Lock()
BLACKLIST_LOCK = asyncio.Lock()

class RuleCreateRequest(BaseModel):
    id: str = Field(..., min_length=1, max_length=120)
    desc: str = Field(default="", max_length=400)
    proto: str = Field(default="ANY")
    action: str = Field(default="FLAG")
    offset_mode: str = Field(default="PAYLOAD")
    offset: int = Field(default=0, ge=0)
    length: int = Field(..., ge=1, le=4)
    value_hex: str = Field(..., min_length=2)
    regex: str = Field(default="")
class BlacklistAddressRequest(BaseModel):
    address: str = Field(..., min_length=1, max_length=64)

def _read_icd() -> dict[str, Any]:
    path = Path(settings.icd_path)
    if not path.exists():
        return {
            "version": 1,
            "defaults": {"max_scan_shift_bytes": 64},
            "vf_rules": [],
        }

    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("version", 1)
    data.setdefault("defaults", {"max_scan_shift_bytes": 64})
    data.setdefault("vf_rules", [])
    return data

def _write_rule_json_atomic(data: dict[str, Any]) -> None:
    path = Path(settings.icd_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"

    with open(path, "w", encoding="utf-8") as f:
        f.write(payload)
        f.flush()
def _blacklist_path() -> Path:
    return Path(settings.ip_blacklist_path)


def _ensure_blacklist_file() -> None:
    path = _blacklist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IPv4/IPv6 address")


def _read_blacklist() -> dict[str, Any]:
    _ensure_blacklist_file()
    path = _blacklist_path()

    raw = path.read_text(encoding="utf-8")
    addresses: list[str] = []
    seen: set[str] = set()

    for raw_line in raw.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            normalized = str(ipaddress.ip_address(line))
        except ValueError:
            continue

        if normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)

    return {
        "path": str(path),
        "count": len(addresses),
        "addresses": addresses,
        "raw": raw,
    }


def _write_blacklist(addresses: list[str]) -> None:
    _ensure_blacklist_file()
    path = _blacklist_path()

    unique = sorted(
        set(addresses),
        key=lambda item: int(ipaddress.ip_address(item)),
    )

    payload = "\n".join(unique)
    if payload:
        payload += "\n"

    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(payload, encoding="utf-8")
    tmp_path.replace(path)

def _normalize_rule(payload: RuleCreateRequest) -> dict[str, Any]:
    rule_id = payload.id.strip()
    desc = payload.desc.strip()
    proto = payload.proto.strip().upper()
    action = payload.action.strip().upper()
    offset_mode = payload.offset_mode.strip().upper()
    value_hex = payload.value_hex.strip().upper()
    regex = payload.regex.strip()

    if not rule_id:
        raise HTTPException(status_code=400, detail="id is required")

    if proto not in {"ANY", "TCP", "UDP"}:
        raise HTTPException(status_code=400, detail="proto must be ANY, TCP, or UDP")

    if action not in {"ALLOW", "FLAG", "BLOCK"}:
        raise HTTPException(status_code=400, detail="action must be ALLOW, FLAG, or BLOCK")

    if offset_mode not in {"PAYLOAD", "EXACT"}:
        raise HTTPException(status_code=400, detail="offset_mode must be PAYLOAD or EXACT")

    if len(value_hex) % 2 != 0:
        raise HTTPException(status_code=400, detail="value_hex must have even length")

    if any(ch not in string.hexdigits for ch in value_hex):
        raise HTTPException(status_code=400, detail="value_hex must contain only hex characters")

    if len(value_hex) // 2 != payload.length:
        raise HTTPException(
            status_code=400,
            detail="length must match the number of bytes in value_hex",
        )

    return {
        "id": rule_id,
        "proto": proto,
        "offset_mode": offset_mode,
        "offset": int(payload.offset),
        "length": int(payload.length),
        "value_hex": value_hex,
        "regex": regex,
        "action": action,
        "desc": desc,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = JanusDatabase(settings)
    await db.open()
    await db.ensure_rule_catalog_seeded(settings.icd_path)

    state = AppState(
        db=db,
        settings=settings,
        ingest_queue=asyncio.Queue(maxsize=settings.ingest_queue_maxsize),
    )

    state.writer_task = asyncio.create_task(writer_loop(state), name="janus-db-writer")
    state.tcp_server = await start_ingest_server(state)
    app.state.janus_state = state

    logger.info(
        "system_status_handler started | tcp=%s:%s | ws=%s:%s",
        settings.tcp_host,
        settings.tcp_port,
        settings.ws_host,
        settings.ws_port,
    )

    try:
        yield
    finally:
        if state.tcp_server is not None:
            state.tcp_server.close()
            await state.tcp_server.wait_closed()

        if state.writer_task is not None:
            state.writer_task.cancel()
            try:
                await state.writer_task
            except asyncio.CancelledError:
                pass

        await db.close()
        logger.info("system_status_handler stopped")


app = FastAPI(title="Janus system_status_handler", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ws_router)


@app.get("/healthz")
async def healthz() -> dict[str, object]:
    state: AppState = app.state.janus_state
    db_ok = True
    try:
        await state.db.ping()
    except Exception:
        db_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "db_connected": db_ok,
        "ingest_queue_size": state.ingest_queue.qsize(),
        "tcp_messages_received": state.counters.tcp_messages_received,
        "queue_dropped": state.counters.queue_dropped,
        "db_writes_ok": state.counters.db_writes_ok,
        "db_writes_failed": state.counters.db_writes_failed,
        "websocket_clients": state.counters.websocket_clients,
        "live_subscribers": state.counters.live_subscribers,
    }


@app.get("/rules")
async def list_rules() -> dict[str, Any]:
    return _read_icd()
@app.get("/blacklist")
async def get_blacklist() -> dict[str, Any]:
    async with BLACKLIST_LOCK:
        return _read_blacklist()


@app.post("/blacklist")
async def add_blacklist_address(payload: BlacklistAddressRequest) -> dict[str, Any]:
    normalized = _normalize_ip(payload.address)

    async with BLACKLIST_LOCK:
        data = _read_blacklist()
        addresses = list(data["addresses"])

        if normalized not in addresses:
            addresses.append(normalized)
            _write_blacklist(addresses)

        updated = _read_blacklist()

    return {
        "ok": True,
        "message": "address added to blacklist.txt",
        "address": normalized,
        "count": updated["count"],
    }


@app.delete("/blacklist/{address:path}")
async def delete_blacklist_address(address: str) -> dict[str, Any]:
    normalized = _normalize_ip(address)

    async with BLACKLIST_LOCK:
        data = _read_blacklist()
        addresses = list(data["addresses"])
        updated_addresses = [item for item in addresses if item != normalized]

        _write_blacklist(updated_addresses)
        updated = _read_blacklist()

    return {
        "ok": True,
        "message": "address removed from blacklist.txt",
        "address": normalized,
        "removed": len(updated_addresses) != len(addresses),
        "count": updated["count"],
    }
async def _send_rule_to_cpp(rule: dict[str, Any]) -> dict[str, Any]:
    command = {
        "type": "ADD_RULE",
        "rule": rule,
    }

    payload = json.dumps(command, ensure_ascii=False).encode("utf-8")

    if len(payload) > settings.core_control_max_frame_bytes:
        raise HTTPException(status_code=400, detail="rule command is too large")

    writer: asyncio.StreamWriter | None = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                settings.core_control_host,
                settings.core_control_port,
            ),
            timeout=settings.core_control_timeout_sec,
        )

        writer.write(pack_frame(payload))
        await asyncio.wait_for(
            writer.drain(),
            timeout=settings.core_control_timeout_sec,
        )

        response_payload = await asyncio.wait_for(
            read_framed_message(
                reader,
                max_frame_bytes=settings.core_control_max_frame_bytes,
            ),
            timeout=settings.core_control_timeout_sec,
        )

        response = json.loads(response_payload.decode("utf-8"))

        if not response.get("ok", False):
            raise HTTPException(
                status_code=502,
                detail=response.get("error", "Janus Core rejected rule"),
            )

        return response

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception("failed to send rule to Janus Core")
        raise HTTPException(
            status_code=502,
            detail=f"failed to send rule to Janus Core: {exc}",
        )

    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
@app.post("/rules")
async def create_rule(payload: RuleCreateRequest) -> dict[str, Any]:
    normalized = _normalize_rule(payload)

    async with RULES_LOCK:
        data = _read_icd()
        rules = data.setdefault("vf_rules", [])

        same_id = next(
            (
                r for r in rules
                if str(r.get("id", "")).upper() == normalized["id"].upper()
            ),
            None,
        )

        if same_id is not None:
            raise HTTPException(
                status_code=409,
                detail=f'rule id "{normalized["id"]}" already exists',
            )

        same_anchor = next(
            (
                r for r in rules
                if str(r.get("proto", "")).upper() == normalized["proto"]
                and str(r.get("offset_mode", "")).upper() == normalized["offset_mode"]
                and int(r.get("offset", -1)) == normalized["offset"]
                and int(r.get("length", -1)) == normalized["length"]
                and str(r.get("value_hex", "")).upper() == normalized["value_hex"]
            ),
            None,
        )

        if same_anchor is not None:
            raise HTTPException(
                status_code=409,
                detail="an identical anchor rule already exists",
            )

        # 1. First activate the rule inside the live C++ engine.
        core_response = await _send_rule_to_cpp(normalized)

        # 2. Only after C++ accepts it, persist it to icd.json.
        rules.append(normalized)
        _write_rule_json_atomic(data)

        # 3. Sync DB catalog so dashboard rule names/actions stay correct.
        state: AppState = app.state.janus_state
        try:
            await state.db.ensure_rule_catalog_seeded(settings.icd_path)
        except Exception:
            logger.exception("rule was activated and written to icd.json but DB reseed failed")

    return {
        "ok": True,
        "message": "rule added and activated successfully",
        "rule": normalized,
        "core_response": core_response,
        "total_rules": len(rules),
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.ws_host, port=settings.ws_port)