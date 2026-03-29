from __future__ import annotations

from typing import Any


def add_metric(msg: Any, label: str, value: str, delta: str, tone: str, highlight: bool) -> None:
    metric = msg.metrics.add()
    metric.label = label
    metric.value = value
    metric.delta = delta
    metric.tone = tone
    metric.highlight = highlight


def add_summary(msg: Any, label: str, value: str, tone: str) -> None:
    item = msg.system_summary.add()
    item.label = label
    item.value = value
    item.tone = tone


def format_count_short(value: int) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f}B"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)


def delta_label(value: int) -> str:
    return "Live" if value else "0"


def threat_delta_label(dropped: int, total: int) -> str:
    if total == 0:
        return "Low"
    ratio = dropped / total
    if ratio >= 0.20:
        return "High"
    if ratio >= 0.05:
        return "Medium"
    return "Low"


def flag_delta_label(flagged: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{(flagged / total) * 100:.1f}%"


def active_engine_label(stage_latency: list[dict[str, Any]]) -> str:
    active = len(stage_latency)
    return f"{active}/{active if active else 6}"


def display_protocol_name(value: str) -> str:
    return value.removeprefix("PROTOCOL_")


def display_verdict_name(value: str) -> str:
    return value.removeprefix("VERDICT_").title()


def display_stage_name(value: str) -> str:
    mapping = {
        "ENGINE_STAGE_PREPROCESS": "Preprocess",
        "ENGINE_STAGE_POLICY": "Policy",
        "ENGINE_STAGE_VECTOR_FILTER": "SIMD",
        "ENGINE_STAGE_REGEX": "Regex",
        "ENGINE_STAGE_AHO": "Aho",
        "ENGINE_STAGE_DPI": "DPI",
        "ENGINE_STAGE_ENCAPSULATION": "Encapsulation",
        "ENGINE_STAGE_TRANSMISSION": "Transmission",
        "ENGINE_STAGE_LOGGING": "Logging",
    }
    return mapping.get(value, value.removeprefix("ENGINE_STAGE_").title())


def display_action_name(value: str) -> str:
    return value.removeprefix("RULE_ACTION_").title()


def severity_for_action(value: str) -> str:
    if value == "RULE_ACTION_BLOCK":
        return "Critical"
    if value == "RULE_ACTION_FLAG":
        return "High"
    if value == "RULE_ACTION_ALLOW":
        return "Low"
    return "Medium"


def threat_level(dropped: int, total: int) -> str:
    if total == 0:
        return "Low"
    ratio = dropped / total
    if ratio >= 0.20:
        return "High"
    if ratio >= 0.05:
        return "Medium"
    return "Low"


def threat_tone(dropped: int, total: int) -> str:
    level = threat_level(dropped, total)
    return {"High": "danger", "Medium": "warning", "Low": "healthy"}.get(level, "neutral")
