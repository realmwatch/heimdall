-- Each host's nginx settings from the collector's X-Heimdall-Nginx header
-- (internal/ingest/nginx.go): how many server blocks speak HTTP/2 and
-- HTTP/3, whether the PROXY protocol, mail{}, a resolver and mp4 are in
-- use (what some nginx advisories depend on), each site root's HTTP/2, and
-- whether the running nginx predates its binary (needs a restart). state
-- is store.NginxState as JSON. No row: an older collector, or no nginx.
CREATE TABLE host_nginx (
    host_id INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    state   TEXT    NOT NULL CHECK (json_valid(state)),
    seen_at TEXT    NOT NULL
) STRICT;
