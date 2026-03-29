from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    pg_host: str = os.getenv("PGHOST", "db")
    pg_port: int = int(os.getenv("PGPORT", "5432"))
    pg_database: str = os.getenv("PGDATABASE", "janus")
    pg_user: str = os.getenv("PGUSER", "janus_db")
    pg_password: str = os.getenv("PGPASSWORD", "secret")

    db_schema: str = os.getenv("JANUS_DB_SCHEMA", "janus")

    tcp_host: str = os.getenv("JANUS_TCP_HOST", "0.0.0.0")
    tcp_port: int = int(os.getenv("JANUS_TCP_PORT", "50051"))
    tcp_max_frame_bytes: int = int(os.getenv("JANUS_TCP_MAX_FRAME_BYTES", str(4 * 1024 * 1024)))

    ws_host: str = os.getenv("JANUS_WS_HOST", "0.0.0.0")
    ws_port: int = int(os.getenv("JANUS_WS_PORT", "8000"))

    ingest_queue_maxsize: int = int(os.getenv("JANUS_INGEST_QUEUE_MAXSIZE", "10000"))
    frontend_send_timeout_sec: float = float(os.getenv("JANUS_FRONTEND_SEND_TIMEOUT_SEC", "3.0"))
    icd_path: str = os.getenv("JANUS_ICD_PATH", "/app/icd.json")

    db_pool_min_size: int = int(os.getenv("JANUS_DB_POOL_MIN_SIZE", "1"))
    db_pool_max_size: int = int(os.getenv("JANUS_DB_POOL_MAX_SIZE", "8"))

    log_level: str = os.getenv("JANUS_LOG_LEVEL", "INFO")

    @property
    def pg_conninfo(self) -> str:
        return (
            f"host={self.pg_host} "
            f"port={self.pg_port} "
            f"dbname={self.pg_database} "
            f"user={self.pg_user} "
            f"password={self.pg_password}"
        )


settings = Settings()
