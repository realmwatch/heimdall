-- Tripwire reports (docs/tripwires.md): an app's own decoys and honey
-- credentials (a Laravel package writes them to a spool directory), shipped
-- by the collector. One row per trip, deduped on the app's trip ID; kept
-- TripRetention (pruned on each report).
--   occurred_at: when the app saw it (the app's clock, checked for skew)
--   site, root:  the app's name for itself and its base path: claims by the
--                authenticated host, not proof
--   detail:      query_keys, headers, context and package_version, as sent
CREATE TABLE trips (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    trip_id     TEXT    NOT NULL,
    occurred_at TEXT    NOT NULL,
    received_at TEXT    NOT NULL,
    site        TEXT    NOT NULL DEFAULT '',
    root        TEXT    NOT NULL DEFAULT '',
    tripwire    TEXT    NOT NULL,
    token       TEXT    NOT NULL DEFAULT '',
    severity    TEXT    NOT NULL CHECK (severity IN ('noise', 'low', 'high', 'critical')),
    ip          TEXT    NOT NULL DEFAULT '',
    method      TEXT    NOT NULL DEFAULT '',
    path        TEXT    NOT NULL DEFAULT '',
    user_id     TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    UNIQUE (host_id, trip_id)
) STRICT;
CREATE INDEX trips_host ON trips (host_id, occurred_at);
CREATE INDEX trips_ip ON trips (ip) WHERE ip <> '';

-- New anomaly rule: tripwire. SQLite can't change a CHECK in place, so the
-- table is rebuilt, exactly as in 0026 plus the new rule name.
CREATE TABLE anomalies_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier',
                        'trigger_disabled', 'privileged_access', 'privilege_watch_disabled',
                        'uptime_inconsistent', 'inventory_reverted', 'package_drop', 'collector_downgrade',
                        'os_changed', 'privilege_unknown_source', 'privilege_off_tailnet',
                        'silent_online', 'login_then_succeeded', 'dns_unproxied', 'cname_takeover',
                        'tripwire')),
    severity        TEXT    NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    summary         TEXT    NOT NULL,
    detail          TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    detected_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    acknowledged_at TEXT,
    acknowledged_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    ack_note        TEXT,
    CHECK ((acknowledged_at IS NULL) = (ack_note IS NULL))
) STRICT;

INSERT INTO anomalies_new (id, host_id, snapshot_id, rule, severity, summary, detail, detected_at,
                           acknowledged_at, acknowledged_by, ack_note)
SELECT id, host_id, snapshot_id, rule, severity, summary, detail, detected_at,
       acknowledged_at, acknowledged_by, ack_note
FROM anomalies;

DROP TABLE anomalies;
ALTER TABLE anomalies_new RENAME TO anomalies;
CREATE INDEX anomalies_open ON anomalies (host_id, detected_at) WHERE acknowledged_at IS NULL;
