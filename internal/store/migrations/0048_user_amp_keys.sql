-- A user's own Amp API key (Settings → Amp key): Amp hand-offs they start
-- can run as them instead of the agent's service account. sealed is the
-- key encrypted with the hub's secrets key (internal/secret: AES-256-GCM,
-- bound to the user's ID), never the key itself; hint is its last four
-- characters, for the settings page. It goes with the user.
CREATE TABLE user_amp_keys (
    user_id    INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    sealed     BLOB    NOT NULL CHECK (length(sealed) BETWEEN 29 AND 2048),
    hint       TEXT    NOT NULL CHECK (length(hint) <= 8),
    created_at TEXT    NOT NULL,
    tested_at  TEXT
) STRICT;
