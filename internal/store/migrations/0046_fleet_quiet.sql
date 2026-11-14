-- An org whose fleet went quiet at once (internal/anomaly/fleet.go): most
-- of its regularly reporting hosts stopped within the same window, or every
-- host reporting from outside did while the hub's own collector (or tailnet
-- hosts) still reported. That's what a down public ingest looks like. One
-- row per open episode; it's deleted once a "back" notice went out (or the
-- condition cleared before it was confirmed).
--   held_since:   the condition was first seen
--   quiet_since:  when the quiet hosts stopped reporting (their median last report)
--   hosts:        the quiet hosts' names, as a JSON array (capped)
--   still:        what still reports: hub, tailnet, local or '' (unknown)
--   outside:      1 when every host reporting from outside went quiet
--   confirmed_at: the condition held long enough: banner shown, notice due
--   notified:     the "down" notice went out (or there was nowhere to send it)
--   clear_since:  the condition stopped holding; "back" once it stays clear
CREATE TABLE fleet_quiet (
    org_id       INTEGER PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    held_since   TEXT    NOT NULL,
    quiet_since  TEXT    NOT NULL,
    quiet        INTEGER NOT NULL,
    total        INTEGER NOT NULL,
    hosts        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(hosts)),
    still        TEXT    NOT NULL DEFAULT '',
    outside      INTEGER NOT NULL DEFAULT 0,
    confirmed_at TEXT,
    notified     INTEGER NOT NULL DEFAULT 0,
    clear_since  TEXT
) STRICT;
