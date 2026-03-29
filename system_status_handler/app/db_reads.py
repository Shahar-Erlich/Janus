from __future__ import annotations

from typing import Any

from psycopg_pool import AsyncConnectionPool


async def fetch_recent_packets(
    *,
    pool: AsyncConnectionPool,
    schema: str,
    limit: int,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                f"""
                SELECT id, ts_unix_ms, queue_id, packet_id,
                       source_ip, source_port, destination_ip, destination_port,
                       protocol, verdict, flagged, inspected,
                       action_reason, end_to_end_processing_us, payload_length,
                       engine_path
                FROM {schema}.v_front_recent_packets
                LIMIT %s
                """,
                (limit,),
            )
            return list(await cur.fetchall())


async def fetch_packet_details(
    *,
    pool: AsyncConnectionPool,
    schema: str,
    db_event_id: int,
) -> dict[str, Any] | None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                f"""
                SELECT id, ts_unix_ms, queue_id, packet_id,
                       source_ip, source_port, destination_ip, destination_port,
                       protocol, verdict, flagged, inspected,
                       action_reason, end_to_end_processing_us, payload_length,
                       engine_path, processing_trace, rule_hits
                FROM {schema}.v_front_packets
                WHERE id = %s
                """,
                (db_event_id,),
            )
            row = await cur.fetchone()
            return dict(row) if row else None


async def fetch_dashboard_overview(
    *,
    pool: AsyncConnectionPool,
    schema: str,
) -> dict[str, Any]:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(f"SELECT * FROM {schema}.v_dashboard_overview_last_hour")
            overview = await cur.fetchone() or {}

            await cur.execute(
                f"SELECT minute_bucket, total_packets, allowed_packets, dropped_packets, flagged_packets "
                f"FROM {schema}.v_dashboard_traffic_by_minute_last_24h"
            )
            traffic = list(await cur.fetchall())

            await cur.execute(
                f"SELECT protocol, total_packets FROM {schema}.v_dashboard_protocol_distribution_last_hour"
            )
            protocol_distribution = list(await cur.fetchall())

            await cur.execute(
                f"SELECT stage, samples, avg_duration_us, max_duration_us "
                f"FROM {schema}.v_dashboard_stage_latency_last_hour"
            )
            stage_latency = list(await cur.fetchall())

            await cur.execute(
                f"SELECT source_ip, total_packets, dropped_packets, flagged_packets "
                f"FROM {schema}.v_dashboard_top_source_ips_last_hour"
            )
            top_source_ips = list(await cur.fetchall())

            await cur.execute(
                f"SELECT rule_id, rule_name, action, hit_count "
                f"FROM {schema}.v_dashboard_triggered_rules_last_hour"
            )
            triggered_rules = list(await cur.fetchall())

            await cur.execute(
                f"""
                SELECT ts_unix_ms, protocol, verdict, flagged, source_ip, destination_ip, action_reason
                FROM {schema}.v_front_recent_packets
                LIMIT 10
                """
            )
            recent_activity = list(await cur.fetchall())

            return {
                "overview": dict(overview),
                "traffic": traffic,
                "protocol_distribution": protocol_distribution,
                "stage_latency": stage_latency,
                "top_source_ips": top_source_ips,
                "triggered_rules": triggered_rules,
                "recent_activity": recent_activity,
            }
