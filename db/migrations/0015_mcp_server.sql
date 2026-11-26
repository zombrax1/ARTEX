-- ARTEX as an MCP server: access tokens for outside MCP clients and an audit
-- log of every tools/call they make. Only the SHA-256 of a token is stored.
CREATE TABLE IF NOT EXISTS api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    token_hint   TEXT NOT NULL DEFAULT '',
    scopes       TEXT NOT NULL DEFAULT '',  -- comma-separated: read, task:create, task:control
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mcp_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_id    BIGINT,
    token_name  TEXT NOT NULL DEFAULT '',
    tool        TEXT NOT NULL,
    args        TEXT NOT NULL DEFAULT '',
    ok          BOOLEAN NOT NULL,
    result      TEXT NOT NULL DEFAULT '',
    remote_addr TEXT NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0
);
