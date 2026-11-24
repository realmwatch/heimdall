-- feed_state's CHECK lists the feeds by name; SQLite can't alter a CHECK,
-- so rebuild it with 'php' (the PHP project's own advisories,
-- internal/feeds/php) added.
CREATE TABLE feed_state_new (
    feed            TEXT PRIMARY KEY CHECK (feed IN ('osv', 'kev', 'epss', 'endoflife', 'news', 'nginx', 'php')),
    last_attempt_at TEXT,
    last_success_at TEXT,
    etag            TEXT,
    last_modified   TEXT,
    last_error      TEXT
) STRICT;
INSERT INTO feed_state_new SELECT feed, last_attempt_at, last_success_at, etag, last_modified, last_error FROM feed_state;
DROP TABLE feed_state;
ALTER TABLE feed_state_new RENAME TO feed_state;
