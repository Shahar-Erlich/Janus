from __future__ import annotations

from typing import Any

from psycopg_pool import AsyncConnectionPool

from .proto_enums import action_name, protocol_name, stage_name, verdict_name


async def insert_packet_event(
    *,
    pool: AsyncConnectionPool,
    schema: str,
    event: Any,
) -> int:
    metadata = event.metadata
    src_ip = metadata.source.ip if metadata.HasField("source") else None
    src_port = int(metadata.source.port) if metadata.HasField("source") else None
    dst_ip = metadata.destination.ip if metadata.HasField("destination") else None
    dst_port = int(metadata.destination.port) if metadata.HasField("destination") else None

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                f"""
                INSERT INTO {schema}.packet_events
                (queue_id, packet_id, ts_unix_ms, payload_length, protocol,
                 src_ip, src_port, dst_ip, dst_port,
                 verdict, flagged, inspected, match_info, end_to_end_processing_us)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (queue_id, packet_id, ts_unix_ms) DO UPDATE
                SET payload_length = EXCLUDED.payload_length,
                    protocol = EXCLUDED.protocol,
                    src_ip = EXCLUDED.src_ip,
                    src_port = EXCLUDED.src_port,
                    dst_ip = EXCLUDED.dst_ip,
                    dst_port = EXCLUDED.dst_port,
                    verdict = EXCLUDED.verdict,
                    flagged = EXCLUDED.flagged,
                    inspected = EXCLUDED.inspected,
                    match_info = EXCLUDED.match_info,
                    end_to_end_processing_us = EXCLUDED.end_to_end_processing_us
                RETURNING id
                """,
                (
                    int(metadata.queue_id),
                    int(metadata.packet_id),
                    int(metadata.ts_unix_ms),
                    int(metadata.payload_length),
                    protocol_name(int(metadata.protocol)),
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    verdict_name(int(event.verdict)),
                    bool(event.flagged),
                    bool(event.inspected),
                    event.match_info,
                    int(event.end_to_end_processing_us),
                ),
            )
            row = await cur.fetchone()
            assert row is not None
            event_id = int(row["id"])

            await cur.execute(
                f"DELETE FROM {schema}.packet_processing_traces WHERE event_id = %s",
                (event_id,),
            )
            await cur.execute(
                f"DELETE FROM {schema}.packet_rule_hits WHERE event_id = %s",
                (event_id,),
            )

            for idx, trace in enumerate(event.processing_trace):
                await cur.execute(
                    f"""
                    INSERT INTO {schema}.packet_processing_traces
                    (event_id, trace_index, stage, started_unix_ms, finished_unix_ms, duration_us, status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        event_id,
                        idx,
                        stage_name(int(trace.stage)),
                        int(trace.started_unix_ms),
                        int(trace.finished_unix_ms),
                        int(trace.duration_us),
                        trace.status,
                    ),
                )

            for idx, hit in enumerate(event.rule_hits):
                await ensure_rule_exists(cur=cur, schema=schema, hit=hit)
                await cur.execute(
                    f"""
                    INSERT INTO {schema}.packet_rule_hits
                    (event_id, hit_index, rule_id)
                    VALUES (%s,%s,%s)
                    ON CONFLICT (event_id, hit_index) DO NOTHING
                    """,
                    (event_id, idx, int(hit.rule_id)),
                )

            return event_id


async def ensure_rule_exists(*, cur: Any, schema: str, hit: Any) -> None:
    await cur.execute(
        f"""
        INSERT INTO {schema}.rule_catalog
        (rule_id, rule_name, rule_desc, protocol, action, offset_mode, offset_value, length_value, regex_pattern)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (rule_id) DO NOTHING
        """,
        (
            int(hit.rule_id),
            hit.rule_name or f"RULE_{int(hit.rule_id)}",
            hit.rule_desc or "",
            protocol_name(int(hit.protocol)) if int(hit.protocol) else "PROTOCOL_UNSPECIFIED",
            action_name(int(hit.action)) if int(hit.action) else "RULE_ACTION_UNSPECIFIED",
            hit.offset_mode or "",
            int(hit.offset),
            int(hit.length),
            "",
        ),
    )
