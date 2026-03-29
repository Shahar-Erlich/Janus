from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app import janus_frontend_pb2

from .dashboard_formatters import (
    active_engine_label,
    add_metric,
    add_summary,
    delta_label,
    display_action_name,
    display_protocol_name,
    display_stage_name,
    display_verdict_name,
    flag_delta_label,
    format_count_short,
    severity_for_action,
    threat_delta_label,
    threat_level,
    threat_tone,
)


def build_dashboard_overview(payload: dict[str, Any], queue_depth: int) -> Any:
    msg = janus_frontend_pb2.DashboardOverviewResponse()
    overview = payload.get("overview", {}) or {}
    traffic = payload.get("traffic", [])
    protocol_distribution = payload.get("protocol_distribution", [])
    stage_latency = payload.get("stage_latency", [])
    top_source_ips = payload.get("top_source_ips", [])
    triggered_rules = payload.get("triggered_rules", [])
    recent_activity = payload.get("recent_activity", [])

    total_packets = int(overview.get("total_packets") or 0)
    allowed_packets = int(overview.get("allowed_packets") or 0)
    dropped_packets = int(overview.get("dropped_packets") or 0)
    flagged_packets = int(overview.get("flagged_packets") or 0)
    avg_us = float(overview.get("avg_processing_us") or 0)

    add_metric(msg, "Total Packets", format_count_short(total_packets), delta_label(total_packets), "positive", False)
    add_metric(msg, "Allowed", format_count_short(allowed_packets), "Stable", "positive", False)
    add_metric(
        msg,
        "Blocked",
        format_count_short(dropped_packets),
        threat_delta_label(dropped_packets, total_packets),
        "negative",
        True,
    )
    add_metric(
        msg,
        "Flagged",
        format_count_short(flagged_packets),
        flag_delta_label(flagged_packets, total_packets),
        "warning",
        False,
    )
    add_metric(msg, "Active Engines", active_engine_label(stage_latency), "100%", "positive", False)
    add_metric(msg, "Avg Latency", f"{avg_us / 1000:.2f}ms", "live", "positive", False)

    for row in traffic:
        point = msg.traffic_series.add()
        minute_bucket = row.get("minute_bucket")
        if isinstance(minute_bucket, datetime):
            point.time_label = minute_bucket.astimezone(timezone.utc).strftime("%H:%M")
        else:
            point.time_label = str(minute_bucket)
        point.total_packets = int(row.get("total_packets") or 0)
        point.allowed_packets = int(row.get("allowed_packets") or 0)
        point.dropped_packets = int(row.get("dropped_packets") or 0)
        point.flagged_packets = int(row.get("flagged_packets") or 0)

    for row in protocol_distribution:
        item = msg.protocol_distribution.add()
        item.name = display_protocol_name(row.get("protocol") or "PROTOCOL_UNSPECIFIED")
        item.total_packets = int(row.get("total_packets") or 0)

    stage_order = {
    "ENGINE_STAGE_PREPROCESS": 0,
    "ENGINE_STAGE_POLICY": 1,
    "ENGINE_STAGE_VECTOR_FILTER": 2,  # displayed as SIMD
    "ENGINE_STAGE_AHO": 3,
    "ENGINE_STAGE_REGEX": 4,
}

ordered_stage_latency = sorted(
    stage_latency,
    key=lambda row: (
        stage_order.get(row.get("stage") or "", 999),
        str(row.get("stage") or ""),
    ),
)

for row in ordered_stage_latency:
    item = msg.detection_results.add()
    item.name = display_stage_name(row.get("stage") or "ENGINE_STAGE_UNSPECIFIED")
    item.total = int(row.get("samples") or 0)
    for row in top_source_ips:
        item = msg.top_source_ips.add()
        total = int(row.get("total_packets") or 0)
        item.ip = row.get("source_ip") or ""
        item.total_packets = total
        item.dropped_packets = int(row.get("dropped_packets") or 0)
        item.flagged_packets = int(row.get("flagged_packets") or 0)
        item.requests_label = f"{format_count_short(total)} req"

    for row in triggered_rules:
        item = msg.triggered_rules.add()
        item.rule_id = int(row.get("rule_id") or 0)
        item.rule_name = row.get("rule_name") or ""
        item.action = display_action_name(row.get("action") or "RULE_ACTION_UNSPECIFIED")
        item.hit_count = int(row.get("hit_count") or 0)
        item.severity = severity_for_action(row.get("action") or "RULE_ACTION_UNSPECIFIED")

    for row in recent_activity:
        item = msg.activity_feed.add()
        item.ts_unix_ms = int(row.get("ts_unix_ms") or 0)
        item.source = row.get("source_ip") or row.get("protocol") or "Core"
        verdict = display_verdict_name(row.get("verdict") or "VERDICT_UNSPECIFIED")
        item.message = row.get("action_reason") or verdict

    add_summary(msg, "Zone", "Trusted Zone", "healthy")
    add_summary(msg, "Core Status", "Healthy", "healthy")
    add_summary(msg, "Queue Depth", f"{queue_depth} / queue", "neutral")
    add_summary(msg, "Threat Level", threat_level(dropped_packets, total_packets), threat_tone(dropped_packets, total_packets))

    return msg
