from __future__ import annotations

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .db_reads import fetch_dashboard_overview, fetch_packet_details, fetch_recent_packets
from .db_seed import ensure_rule_catalog_seeded
from .db_writes import insert_packet_event
from .settings import Settings


class JanusDatabase:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.pool = AsyncConnectionPool(
            conninfo=settings.pg_conninfo,
            min_size=settings.db_pool_min_size,
            max_size=settings.db_pool_max_size,
            open=False,
            kwargs={"autocommit": False, "row_factory": dict_row},
        )

    async def open(self) -> None:
        await self.pool.open()
        await self.ping()

    async def close(self) -> None:
        await self.pool.close()

    async def ping(self) -> None:
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
                await cur.fetchone()

    async def ensure_rule_catalog_seeded(self, icd_path: str) -> None:
        await ensure_rule_catalog_seeded(
            pool=self.pool,
            schema=self.settings.db_schema,
            icd_path=icd_path,
        )

    async def insert_packet_event(self, event: object) -> int:
        return await insert_packet_event(
            pool=self.pool,
            schema=self.settings.db_schema,
            event=event,
        )

    async def fetch_recent_packets(self, limit: int) -> list[dict[str, object]]:
        return await fetch_recent_packets(
            pool=self.pool,
            schema=self.settings.db_schema,
            limit=limit,
        )

    async def fetch_packet_details(self, db_event_id: int) -> dict[str, object] | None:
        return await fetch_packet_details(
            pool=self.pool,
            schema=self.settings.db_schema,
            db_event_id=db_event_id,
        )

    async def fetch_dashboard_overview(self) -> dict[str, object]:
        return await fetch_dashboard_overview(
            pool=self.pool,
            schema=self.settings.db_schema,
        )
