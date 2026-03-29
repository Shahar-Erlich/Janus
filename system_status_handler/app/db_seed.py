from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)


async def ensure_rule_catalog_seeded(
    *,
    pool: AsyncConnectionPool,
    schema: str,
    icd_path: str,
) -> None:
    path = Path(icd_path)
    if not path.exists():
        logger.warning("ICD file not found at %s; rule catalog will be populated lazily", icd_path)
        return

    data = json.loads(path.read_text())
    rules = data.get("vf_rules", [])

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            for rule in rules:
                rule_id = compute_rule_id(rule)
                await cur.execute(
                    f"""
                    INSERT INTO {schema}.rule_catalog
                    (rule_id, rule_name, rule_desc, protocol, action, offset_mode, offset_value, length_value, regex_pattern)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (rule_id) DO UPDATE
                    SET rule_name = EXCLUDED.rule_name,
                        rule_desc = EXCLUDED.rule_desc,
                        protocol = EXCLUDED.protocol,
                        action = EXCLUDED.action,
                        offset_mode = EXCLUDED.offset_mode,
                        offset_value = EXCLUDED.offset_value,
                        length_value = EXCLUDED.length_value,
                        regex_pattern = EXCLUDED.regex_pattern,
                        updated_at = now()
                    """,
                    (
                        rule_id,
                        rule.get("id", f"RULE_{rule_id}"),
                        rule.get("desc", ""),
                        normalize_protocol_text(rule.get("proto", "ANY")),
                        normalize_action_text(rule.get("action", "FLAG")),
                        rule.get("offset_mode", "PAYLOAD"),
                        int(rule.get("offset", 0)),
                        int(rule.get("length", 0)),
                        rule.get("regex", ""),
                    ),
                )
    logger.info("rule_catalog seeded from %s", icd_path)


def compute_rule_id(rule: dict[str, Any]) -> int:
    key = (
        f"{rule.get('id', '')}|{rule.get('proto', 'ANY')}|"
        f"{int(rule.get('offset', 0))}|{int(rule.get('length', 0))}|{rule.get('value_hex', '')}"
    )
    h = 0
    for b in key.encode("utf-8"):
        h = ((h * 31) + b) & 0xFFFFFFFF
    return h & 0x7FFFFFFF


def normalize_protocol_text(value: str) -> str:
    value = (value or "ANY").upper()
    mapping = {
        "ANY": "PROTOCOL_ANY",
        "TCP": "PROTOCOL_TCP",
        "UDP": "PROTOCOL_UDP",
        "HTTP": "PROTOCOL_HTTP",
        "OTHER": "PROTOCOL_OTHER",
    }
    return mapping.get(value, "PROTOCOL_UNSPECIFIED")


def normalize_action_text(value: str) -> str:
    value = (value or "FLAG").upper()
    mapping = {
        "ALLOW": "RULE_ACTION_ALLOW",
        "FLAG": "RULE_ACTION_FLAG",
        "BLOCK": "RULE_ACTION_BLOCK",
    }
    return mapping.get(value, "RULE_ACTION_UNSPECIFIED")
