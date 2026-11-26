-- Multiple-account testing: test accounts carry a role and an organisation, and
-- optionally the session headers (Cookie, Authorization, ...) a logged-in
-- request needs. access_checks keeps each replay of one request as every
-- account, for comparing what each role and organisation can reach.
ALTER TABLE task_credentials ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT '';
ALTER TABLE task_credentials ADD COLUMN IF NOT EXISTS org TEXT NOT NULL DEFAULT '';
ALTER TABLE task_credentials ADD COLUMN IF NOT EXISTS auth_headers TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS access_checks (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    method      TEXT NOT NULL,
    url         TEXT NOT NULL,
    owner_id    BIGINT,
    results     JSONB NOT NULL DEFAULT '[]',
    flags       JSONB NOT NULL DEFAULT '[]',
    checked_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_access_checks_task ON access_checks(task_id, id DESC);
