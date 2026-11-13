-- Each host's apt state from the collector's X-Heimdall-Release header
-- (internal/leftovers): its codename, enabled apt sources, packages no
-- configured source has, packages only an older release's suites offer,
-- files the release upgrader left, and processes mapping those packages'
-- libraries. state is leftovers.State as JSON. No row means an older
-- collector (or no apt): leftovers are then told from versions alone.
CREATE TABLE host_release (
    host_id INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    state   TEXT    NOT NULL CHECK (json_valid(state)),
    seen_at TEXT    NOT NULL
) STRICT;
