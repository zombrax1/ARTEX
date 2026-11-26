-- Imported API definitions (OpenAPI 3, Swagger 2, Postman v2) per task, and the
-- operations they declare. An operation counts as tested when captured traffic
-- matches it or an agent/user marked it; skipped when marked with a reason.
-- Matching traffic is counted once and kept on the operation; scan_ts/scan_id
-- on the definition is the last capture already counted, so later passes only
-- read newer traffic and older coverage is never lost.
CREATE TABLE IF NOT EXISTS api_definitions (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    name        TEXT NOT NULL DEFAULT '',
    format      TEXT NOT NULL CHECK (format IN ('openapi','swagger','postman')),
    base_url    TEXT NOT NULL DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    scan_ts     BIGINT NOT NULL DEFAULT 0,
    scan_id     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_definitions_task ON api_definitions(task_id);

CREATE TABLE IF NOT EXISTS api_operations (
    id            BIGSERIAL PRIMARY KEY,
    definition_id BIGINT NOT NULL REFERENCES api_definitions(id) ON DELETE CASCADE,
    task_id       BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    method        TEXT NOT NULL,
    path          TEXT NOT NULL,
    base_url      TEXT NOT NULL DEFAULT '',
    operation_id  TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',
    params        JSONB NOT NULL DEFAULT '[]',
    auth          BOOLEAN NOT NULL DEFAULT false,
    mark          TEXT NOT NULL DEFAULT '' CHECK (mark IN ('','tested','skipped')),
    mark_note     TEXT NOT NULL DEFAULT '',
    mark_by       TEXT NOT NULL DEFAULT '',
    marked_at     TIMESTAMPTZ,
    seen_requests INTEGER NOT NULL DEFAULT 0,
    seen_last     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_operations_task ON api_operations(task_id);
CREATE INDEX IF NOT EXISTS idx_api_operations_def ON api_operations(definition_id);
