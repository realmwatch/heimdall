-- Which Node.js binaries a host has, which run, and each site's Node, from
-- the collector's X-Heimdall-Node header (collector 0.5.51 on): state is
-- a JSON object, {"bins": [{"path", "version", "running"}], "sites":
-- {"<root>": {"bin", "requirement"}}}. dpkg sees only the apt nodejs; a
-- host can keep other majors under /opt/node, one per site. No row means
-- an older collector: only the apt package is known.
CREATE TABLE host_node (
    host_id INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    state   TEXT    NOT NULL CHECK (json_valid(state)),
    seen_at TEXT    NOT NULL
) STRICT;
