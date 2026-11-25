-- Each host's nginx sites as the collector's X-Heimdall-Sites header lists
-- them (internal/ingest/sites.go): the vhost file serving each enabled
-- site, and the sites whose vhost is there but not enabled. A disabled
-- site isn't in the snapshot, so this is the only record of it. vhost is
-- '' when the collector couldn't name the file; names is comma-separated.
-- Replaced on every report that carries the header.
CREATE TABLE host_site_vhosts (
    host_id INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    root    TEXT    NOT NULL,
    vhost   TEXT    NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    names   TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, root)
) STRICT;

-- Sites an operator has archived: retired, no longer meant to be served.
-- Only intent: Heimdall changes nothing on the host. An archived site
-- whose vhost is disabled is hidden by default.
CREATE TABLE site_archive (
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    root        TEXT    NOT NULL,
    archived_by TEXT    NOT NULL,
    archived_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (host_id, root)
) STRICT;
