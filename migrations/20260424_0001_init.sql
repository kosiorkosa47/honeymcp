-- Initial Postgres schema for honeymcp.
--
-- Applied by: sqlx migrate run (once sqlx is wired in) OR psql -f <file>.
-- Mirrors the SQLite schema in src/logger/mod.rs with two differences:
--   1. BIGSERIAL / BIGINT id columns instead of rusqlite INTEGER PRIMARY KEY.
--   2. client_meta stored as JSONB so the dashboard can query ->>'mcp_protocol_version'
--      without a full-row deserialise.
-- pgvector extension and embedding columns land in a separate migration
-- (20260424_0002_pgvector.sql) so operators can stage rollout.

CREATE TABLE IF NOT EXISTS sessions (
    id             BIGSERIAL PRIMARY KEY,
    session_id     TEXT NOT NULL UNIQUE,
    transport      TEXT NOT NULL,              -- 'stdio' | 'http'
    persona        TEXT NOT NULL,              -- persona name active at session start
    remote_addr    TEXT,
    user_agent     TEXT,
    client_name    TEXT,
    client_version TEXT,
    started_ms     BIGINT NOT NULL,
    ended_ms       BIGINT,
    client_meta    JSONB
);

CREATE INDEX IF NOT EXISTS sessions_session_id_idx  ON sessions (session_id);
CREATE INDEX IF NOT EXISTS sessions_started_ms_idx  ON sessions (started_ms DESC);
CREATE INDEX IF NOT EXISTS sessions_remote_addr_idx ON sessions (remote_addr);

CREATE TABLE IF NOT EXISTS events (
    id               BIGSERIAL PRIMARY KEY,
    timestamp_ms     BIGINT NOT NULL,
    method           TEXT NOT NULL,
    params_hash      TEXT NOT NULL,            -- hex SHA-256 of canonical params
    params_raw       JSONB,                    -- raw params as received (redacted secrets)
    session_id       TEXT NOT NULL,
    transport        TEXT NOT NULL,
    remote_addr      TEXT,
    user_agent       TEXT,
    client_name      TEXT,
    client_version   TEXT,
    client_meta      JSONB,
    response_summary TEXT NOT NULL             -- 'ok' / 'error:<code>' / 'notification'
);

CREATE INDEX IF NOT EXISTS events_ts_idx             ON events (timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS events_method_idx         ON events (method);
CREATE INDEX IF NOT EXISTS events_session_ts_idx     ON events (session_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS events_remote_addr_idx    ON events (remote_addr);
CREATE INDEX IF NOT EXISTS events_params_hash_idx    ON events (params_hash);

-- Detector hits. One event can have many detections.
CREATE TABLE IF NOT EXISTS detections (
    id          BIGSERIAL PRIMARY KEY,
    event_id    BIGINT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    category    TEXT NOT NULL,                -- 'prompt_injection' | 'shell_injection' | ...
    severity    TEXT NOT NULL,                -- 'low' | 'medium' | 'high' | 'critical'
    confidence  REAL NOT NULL,                -- 0.0 .. 1.0
    matched     TEXT,                         -- the pattern / token that fired (redacted)
    details     JSONB
);

CREATE INDEX IF NOT EXISTS detections_event_id_idx ON detections (event_id);
CREATE INDEX IF NOT EXISTS detections_category_idx ON detections (category);

-- Snapshot of persona at the moment a session starts, so reports can be
-- regenerated even if the persona file on disk changes later.
CREATE TABLE IF NOT EXISTS personas_snapshot (
    id           BIGSERIAL PRIMARY KEY,
    session_id   TEXT NOT NULL UNIQUE REFERENCES sessions (session_id) ON DELETE CASCADE,
    persona_name TEXT NOT NULL,
    body         JSONB NOT NULL
);
