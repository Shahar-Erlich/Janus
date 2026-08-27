from __future__ import annotations

from typing import Any

from app import janus_common_pb2


def protocol_name(value: int, default: str = "PROTOCOL_UNSPECIFIED") -> str:
    return enum_name(janus_common_pb2.Protocol, value, default)


def verdict_name(value: int, default: str = "VERDICT_UNSPECIFIED") -> str:
    return enum_name(janus_common_pb2.Verdict, value, default)


def stage_name(value: int, default: str = "ENGINE_STAGE_UNSPECIFIED") -> str:
    return enum_name(janus_common_pb2.EngineStage, value, default)


def action_name(value: int, default: str = "RULE_ACTION_UNSPECIFIED") -> str:
    return enum_name(janus_common_pb2.RuleAction, value, default)


def protocol_value(name: str, default: str = "PROTOCOL_UNSPECIFIED") -> int:
    return enum_value(janus_common_pb2.Protocol, name, default)


def verdict_value(name: str, default: str = "VERDICT_UNSPECIFIED") -> int:
    return enum_value(janus_common_pb2.Verdict, name, default)


def stage_value(name: str, default: str = "ENGINE_STAGE_UNSPECIFIED") -> int:
    return enum_value(janus_common_pb2.EngineStage, name, default)


def action_value(name: str, default: str = "RULE_ACTION_UNSPECIFIED") -> int:
    return enum_value(janus_common_pb2.RuleAction, name, default)


def enum_name(enum_wrapper: Any, value: int, default: str) -> str:
    try:
        return enum_wrapper.Name(int(value))
    except ValueError:
        return default


def enum_value(enum_wrapper: Any, name: str, default: str) -> int:
    try:
        return enum_wrapper.Value(name)
    except ValueError:
        return enum_wrapper.Value(default)
