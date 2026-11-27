-- A new AI run kind, 'leftovers': a host's release-leftovers plan (host_id
-- set, like 'host'). The table is rebuilt exactly as in 0011, plus the
-- new kind.
CREATE TABLE ai_runs_new (
    id            INTEGER PRIMARY KEY,
    org_id        INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    host_id       INTEGER,
    kind          TEXT    NOT NULL CHECK (kind IN ('brief', 'host', 'leftovers')),
    status        TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'error')),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    finished_at   TEXT,
    requested_by  TEXT    NOT NULL DEFAULT '',
    deployment    TEXT    NOT NULL DEFAULT '',
    model         TEXT    NOT NULL DEFAULT '',
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    error         TEXT    NOT NULL DEFAULT '',
    result        TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(result)),
    FOREIGN KEY (host_id, org_id) REFERENCES hosts (id, org_id) ON DELETE CASCADE,
    CHECK ((kind = 'brief') = (host_id IS NULL))
) STRICT;

INSERT INTO ai_runs_new (id, org_id, host_id, kind, status, created_at, finished_at, requested_by, deployment,
                         model, input_tokens, output_tokens, error, result)
SELECT id, org_id, host_id, kind, status, created_at, finished_at, requested_by, deployment,
       model, input_tokens, output_tokens, error, result
FROM ai_runs;

DROP TABLE ai_runs;
ALTER TABLE ai_runs_new RENAME TO ai_runs;
CREATE INDEX ai_runs_latest ON ai_runs (org_id, kind, host_id, id);
