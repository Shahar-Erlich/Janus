from __future__ import annotations

import json
from typing import Any

from app import janus_frontend_pb2

from .proto_enums import action_value, protocol_value, stage_value, verdict_value


def build_packet_summary(row: dict[str, Any]) -> Any:
    row = dict(row)
    row["engine_path"] = coerce_json(row.get("engine_path") or [])

    msg = janus_frontend_pb2.PacketSummary()
    msg.db_event_id = int(row.get("id", 0))
    msg.ts_unix_ms = int(row.get("ts_unix_ms", 0))
    msg.source_ip = row.get("source_ip") or ""
    msg.source_port = int(row.get("source_port") or 0)
    msg.destination_ip = row.get("destination_ip") or ""
    msg.destination_port = int(row.get("destination_port") or 0)
    msg.protocol = protocol_value(row.get("protocol", "PROTOCOL_UNSPECIFIED"))
    msg.verdict = verdict_value(row.get("verdict", "VERDICT_UNSPECIFIED"))
    msg.flagged = bool(row.get("flagged", False))
    msg.inspected = bool(row.get("inspected", False))
    msg.action_reason = row.get("action_reason") or ""
    msg.engine_path.extend([str(stage) for stage in row.get("engine_path", [])])
    msg.end_to_end_processing_us = int(row.get("end_to_end_processing_us") or 0)
    msg.payload_length = int(row.get("payload_length") or 0)
    msg.packet_id = int(row.get("packet_id") or 0)
    msg.queue_id = int(row.get("queue_id") or 0)
    return msg


def build_packet_details(row: dict[str, Any]) -> Any:
    row = dict(row)
    row["engine_path"] = coerce_json(row.get("engine_path") or [])
    row["processing_trace"] = coerce_json(row.get("processing_trace") or [])
    row["rule_hits"] = coerce_json(row.get("rule_hits") or [])

    msg = janus_frontend_pb2.PacketDetailsResponse()
    msg.packet.CopyFrom(build_packet_summary(row))

    for item in row["processing_trace"]:
        trace = msg.processing_trace.add()
        trace.trace_index = int(item.get("trace_index", 0))
        trace.stage = stage_value(item.get("stage", "ENGINE_STAGE_UNSPECIFIED"))
        trace.started_unix_ms = int(item.get("started_unix_ms") or 0)
        trace.finished_unix_ms = int(item.get("finished_unix_ms") or 0)
        trace.duration_us = int(item.get("duration_us") or 0)
        trace.status = item.get("status") or ""

    for item in row["rule_hits"]:
        hit = msg.rule_hits.add()
        hit.rule_id = int(item.get("rule_id") or 0)
        hit.rule_name = item.get("rule_name") or ""
        hit.rule_desc = item.get("rule_desc") or ""
        hit.protocol = protocol_value(item.get("protocol", "PROTOCOL_UNSPECIFIED"))
        hit.action = action_value(item.get("action", "RULE_ACTION_UNSPECIFIED"))
        hit.offset_mode = item.get("offset_mode") or ""
        hit.offset = int(item.get("offset") or 0)
        hit.length = int(item.get("length") or 0)

    return msg


def coerce_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value
