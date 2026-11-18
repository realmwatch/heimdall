-- Where each host's third-party packages came from, from the collector's
-- X-Heimdall-Origins header (internal/ingest/origins.go): installed
-- packages whose version an apt source other than the distro's offers
-- (nginx.org, a PPA, a vendor repo). origins is a JSON object, package
-- name to the source's Origin ("nginx", "LP-PPA-ondrej-php"). Their
-- versions aren't the distro's, so distro advisories can't judge them.
-- No row means an older collector (or no apt): every package is then
-- taken for the distro's own.
CREATE TABLE host_origins (
    host_id INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    origins TEXT    NOT NULL CHECK (json_valid(origins)),
    seen_at TEXT    NOT NULL
) STRICT;

-- Whether a distro has published its own OSV record for an upstream
-- advisory's CVE (internal/findings/upstream.go). Until it has, the
-- upstream advisory (nginx.org's) stands in for it on the distro's builds.
--   distro: the OSV ID prefix ("UBUNTU", "DEBIAN", "ALPINE")
--   found:  1 once the record exists (never rechecked), 0 until then
CREATE TABLE distro_records (
    cve        TEXT    NOT NULL,
    distro     TEXT    NOT NULL,
    found      INTEGER NOT NULL CHECK (found IN (0, 1)),
    checked_at TEXT    NOT NULL,
    PRIMARY KEY (cve, distro)
) STRICT, WITHOUT ROWID;

-- feed_state's CHECK lists the feeds by name; SQLite can't alter a CHECK,
-- so rebuild it with 'nginx' (nginx.org's advisories) added.
CREATE TABLE feed_state_new (
    feed            TEXT PRIMARY KEY CHECK (feed IN ('osv', 'kev', 'epss', 'endoflife', 'news', 'nginx')),
    last_attempt_at TEXT,
    last_success_at TEXT,
    etag            TEXT,
    last_modified   TEXT,
    last_error      TEXT
) STRICT;
INSERT INTO feed_state_new SELECT feed, last_attempt_at, last_success_at, etag, last_modified, last_error FROM feed_state;
DROP TABLE feed_state;
ALTER TABLE feed_state_new RENAME TO feed_state;
