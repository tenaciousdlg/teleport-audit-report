-- Single denormalized events table. Teleport has 200+ audit event types;
-- per-type tables would be premature. Common fields are extracted as columns
-- for indexed filtering, the full payload is kept in `raw` for anything else.
CREATE TABLE IF NOT EXISTS events (
    uid          TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    event_code   TEXT,
    event_time   TIMESTAMPTZ NOT NULL,
    cluster_name TEXT,
    user_name    TEXT,
    session_id   TEXT,
    success      BOOLEAN,
    raw          JSONB NOT NULL,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS events_event_time_idx ON events (event_time);
CREATE INDEX IF NOT EXISTS events_event_type_idx ON events (event_type);
CREATE INDEX IF NOT EXISTS events_user_name_idx ON events (user_name);
CREATE INDEX IF NOT EXISTS events_raw_gin_idx ON events USING GIN (raw);
