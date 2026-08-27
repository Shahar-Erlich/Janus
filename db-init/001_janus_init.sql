CREATE SCHEMA IF NOT EXISTS janus;
SET search_path TO janus, public;


CREATE TABLE IF NOT EXISTS rule_catalog (
    rule_id        INTEGER PRIMARY KEY,
    rule_name      TEXT NOT NULL,
    rule_desc      TEXT,
    protocol       TEXT,
    action         TEXT,
    offset_mode    TEXT,
    offset_value   INTEGER,
    length_value   INTEGER,
    regex_pattern  TEXT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE TABLE IF NOT EXISTS packet_events (
    id                       BIGSERIAL PRIMARY KEY,
    ingested_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    queue_id                 INTEGER NOT NULL,
    packet_id                BIGINT NOT NULL,
    ts_unix_ms               BIGINT NOT NULL,

    payload_length           INTEGER,
    protocol                 TEXT NOT NULL,

    src_ip                   INET,
    src_port                 INTEGER,
    dst_ip                   INET,
    dst_port                 INTEGER,

    verdict                  TEXT NOT NULL,
    flagged                  BOOLEAN NOT NULL DEFAULT FALSE,
    inspected                BOOLEAN NOT NULL DEFAULT FALSE,
    match_info               TEXT,
    end_to_end_processing_us BIGINT,

    CONSTRAINT uq_packet_event UNIQUE (queue_id, packet_id, ts_unix_ms)
);

CREATE INDEX IF NOT EXISTS ix_packet_events_ts
    ON packet_events (ts_unix_ms DESC);

CREATE INDEX IF NOT EXISTS ix_packet_events_verdict_ts
    ON packet_events (verdict, ts_unix_ms DESC);

CREATE INDEX IF NOT EXISTS ix_packet_events_protocol_ts
    ON packet_events (protocol, ts_unix_ms DESC);

CREATE INDEX IF NOT EXISTS ix_packet_events_flagged_ts
    ON packet_events (flagged, ts_unix_ms DESC);

CREATE INDEX IF NOT EXISTS ix_packet_events_src_ip_ts
    ON packet_events (src_ip, ts_unix_ms DESC);

CREATE INDEX IF NOT EXISTS ix_packet_events_dst_ip_ts
    ON packet_events (dst_ip, ts_unix_ms DESC);


CREATE TABLE IF NOT EXISTS packet_processing_traces (
    id               BIGSERIAL PRIMARY KEY,
    event_id         BIGINT NOT NULL REFERENCES packet_events(id) ON DELETE CASCADE,
    trace_index      INTEGER NOT NULL,
    stage            TEXT NOT NULL,
    started_unix_ms  BIGINT,
    finished_unix_ms BIGINT,
    duration_us      BIGINT,
    status           TEXT,
    CONSTRAINT uq_packet_trace UNIQUE (event_id, trace_index)
);

CREATE INDEX IF NOT EXISTS ix_packet_processing_traces_event
    ON packet_processing_traces (event_id, trace_index);

CREATE INDEX IF NOT EXISTS ix_packet_processing_traces_stage_time
    ON packet_processing_traces (stage, started_unix_ms DESC);


CREATE TABLE IF NOT EXISTS packet_rule_hits (
    id        BIGSERIAL PRIMARY KEY,
    event_id  BIGINT NOT NULL REFERENCES packet_events(id) ON DELETE CASCADE,
    hit_index INTEGER NOT NULL,
    rule_id   INTEGER NOT NULL REFERENCES rule_catalog(rule_id),
    CONSTRAINT uq_packet_rule_hit UNIQUE (event_id, hit_index)
);

CREATE INDEX IF NOT EXISTS ix_packet_rule_hits_event
    ON packet_rule_hits (event_id, hit_index);

CREATE INDEX IF NOT EXISTS ix_packet_rule_hits_rule_id
    ON packet_rule_hits (rule_id);


CREATE OR REPLACE VIEW v_front_packets AS
SELECT
    e.id,
    to_timestamp(e.ts_unix_ms / 1000.0) AS event_time,
    e.ts_unix_ms,
    e.queue_id,
    e.packet_id,
    e.src_ip::TEXT AS source_ip,
    e.src_port AS source_port,
    e.dst_ip::TEXT AS destination_ip,
    e.dst_port AS destination_port,
    e.protocol,
    e.verdict,
    e.flagged,
    e.inspected,
    e.match_info AS action_reason,
    e.end_to_end_processing_us,
    e.payload_length,

    COALESCE(
    '["INGRESS","POLICY"]'::jsonb
    ||
    CASE
        WHEN e.inspected THEN '["SPI"]'::jsonb
        ELSE '[]'::jsonb
    END
    ||
    CASE
        WHEN EXISTS (
            SELECT 1
            FROM packet_processing_traces t
            WHERE t.event_id = e.id
              AND t.stage IN (
                  'ENGINE_STAGE_VECTOR_FILTER',
                  'ENGINE_STAGE_AHO',
                  'ENGINE_STAGE_REGEX'
              )
        )
        THEN '["DPI"]'::jsonb
        ELSE '[]'::jsonb
    END
    ||
    '["EGRESS"]'::jsonb
) AS engine_path,

    COALESCE(
        (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'trace_index', t.trace_index,
                    'stage', t.stage,
                    'started_unix_ms', t.started_unix_ms,
                    'finished_unix_ms', t.finished_unix_ms,
                    'duration_us', t.duration_us,
                    'status', t.status
                )
                ORDER BY t.trace_index
            )
            FROM packet_processing_traces t
            WHERE t.event_id = e.id
        ),
        '[]'::jsonb
    ) AS processing_trace,

    COALESCE(
        (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'rule_id', c.rule_id,
                    'rule_name', c.rule_name,
                    'rule_desc', c.rule_desc,
                    'protocol', c.protocol,
                    'action', c.action,
                    'offset_mode', c.offset_mode,
                    'offset', c.offset_value,
                    'length', c.length_value
                )
                ORDER BY h.hit_index
            )
            FROM packet_rule_hits h
            JOIN rule_catalog c ON c.rule_id = h.rule_id
            WHERE h.event_id = e.id
        ),
        '[]'::jsonb
    ) AS rule_hits

FROM packet_events e;

CREATE OR REPLACE VIEW v_front_recent_packets AS
SELECT *
FROM v_front_packets
ORDER BY event_time DESC, id DESC;



CREATE OR REPLACE VIEW v_dashboard_overview_last_hour AS
SELECT
    COUNT(*) AS total_packets,
    COUNT(*) FILTER (WHERE verdict = 'VERDICT_ALLOW') AS allowed_packets,
    COUNT(*) FILTER (WHERE verdict = 'VERDICT_DROP') AS dropped_packets,
    COUNT(*) FILTER (WHERE flagged) AS flagged_packets,
    COALESCE(ROUND(AVG(end_to_end_processing_us)::numeric, 2), 0) AS avg_processing_us
FROM packet_events
WHERE ts_unix_ms >= (EXTRACT(EPOCH FROM (now() - INTERVAL '1 hour')) * 1000)::bigint;

CREATE OR REPLACE VIEW v_dashboard_traffic_by_minute_last_24h AS
SELECT
    date_trunc('minute', to_timestamp(ts_unix_ms / 1000.0)) AS minute_bucket,
    COUNT(*) AS total_packets,
    COUNT(*) FILTER (WHERE verdict = 'VERDICT_ALLOW') AS allowed_packets,
    COUNT(*) FILTER (WHERE verdict = 'VERDICT_DROP') AS dropped_packets,
    COUNT(*) FILTER (WHERE flagged) AS flagged_packets
FROM packet_events
WHERE ts_unix_ms >= (EXTRACT(EPOCH FROM (now() - INTERVAL '24 hours')) * 1000)::bigint
GROUP BY 1
ORDER BY 1;

CREATE OR REPLACE VIEW v_dashboard_protocol_distribution_last_hour AS
SELECT
    protocol,
    COUNT(*) AS total_packets
FROM packet_events
WHERE ts_unix_ms >= (EXTRACT(EPOCH FROM (now() - INTERVAL '1 hour')) * 1000)::bigint
GROUP BY protocol
ORDER BY total_packets DESC, protocol;
CREATE OR REPLACE VIEW v_dashboard_stage_latency_last_hour AS
SELECT
    stage,
    samples,
    avg_duration_us,
    max_duration_us
FROM (
    WITH stage_counts AS (
        SELECT
            stage,
            COUNT(*) AS samples,
            COALESCE(ROUND(AVG(duration_us)::numeric, 2), 0) AS avg_duration_us,
            COALESCE(MAX(duration_us), 0) AS max_duration_us
        FROM packet_processing_traces
        WHERE started_unix_ms >= (EXTRACT(EPOCH FROM (now() - INTERVAL '1 hour')) * 1000)::bigint
          AND stage IN (
              'ENGINE_STAGE_POLICY',
              'ENGINE_STAGE_VECTOR_FILTER',
              'ENGINE_STAGE_AHO',
              'ENGINE_STAGE_REGEX'
          )
        GROUP BY stage
    )

    SELECT
        'ENGINE_STAGE_POLICY' AS stage,
        COALESCE((SELECT samples FROM stage_counts WHERE stage = 'ENGINE_STAGE_POLICY'), 0) AS samples,
        COALESCE((SELECT avg_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_POLICY'), 0) AS avg_duration_us,
        COALESCE((SELECT max_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_POLICY'), 0) AS max_duration_us,
        1 AS sort_order

    UNION ALL

    SELECT
        'ENGINE_STAGE_VECTOR_FILTER' AS stage,
        COALESCE((SELECT samples FROM stage_counts WHERE stage = 'ENGINE_STAGE_VECTOR_FILTER'), 0) AS samples,
        COALESCE((SELECT avg_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_VECTOR_FILTER'), 0) AS avg_duration_us,
        COALESCE((SELECT max_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_VECTOR_FILTER'), 0) AS max_duration_us,
        2 AS sort_order

    UNION ALL

    SELECT
        'ENGINE_STAGE_AHO' AS stage,
        COALESCE((SELECT samples FROM stage_counts WHERE stage = 'ENGINE_STAGE_AHO'), 0) AS samples,
        COALESCE((SELECT avg_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_AHO'), 0) AS avg_duration_us,
        COALESCE((SELECT max_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_AHO'), 0) AS max_duration_us,
        3 AS sort_order

    UNION ALL

    SELECT
        'ENGINE_STAGE_REGEX' AS stage,
        COALESCE((SELECT samples FROM stage_counts WHERE stage = 'ENGINE_STAGE_REGEX'), 0) AS samples,
        COALESCE((SELECT avg_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_REGEX'), 0) AS avg_duration_us,
        COALESCE((SELECT max_duration_us FROM stage_counts WHERE stage = 'ENGINE_STAGE_REGEX'), 0) AS max_duration_us,
        4 AS sort_order
) s
ORDER BY sort_order;
CREATE OR REPLACE VIEW v_dashboard_top_source_ips_last_hour AS
SELECT
    src_ip::TEXT AS source_ip,
    COUNT(*) AS total_packets,
    COUNT(*) FILTER (WHERE verdict = 'VERDICT_DROP') AS dropped_packets,
    COUNT(*) FILTER (WHERE flagged) AS flagged_packets
FROM packet_events
WHERE src_ip IS NOT NULL
  AND ts_unix_ms >= (EXTRACT(EPOCH FROM (now() - INTERVAL '1 hour')) * 1000)::bigint
GROUP BY src_ip
ORDER BY total_packets DESC, source_ip
LIMIT 20;

CREATE OR REPLACE VIEW v_dashboard_triggered_rules_last_hour AS
SELECT
    h.rule_id,
    c.rule_name,
    c.action,
    COUNT(*) AS hit_count
FROM packet_rule_hits h
JOIN packet_events e ON e.id = h.event_id
JOIN rule_catalog c ON c.rule_id = h.rule_id
WHERE e.ts_unix_ms >= (EXTRACT(EPOCH FROM (now() - INTERVAL '1 hour')) * 1000)::bigint
GROUP BY h.rule_id, c.rule_name, c.action
ORDER BY hit_count DESC, h.rule_id
LIMIT 20;