-- fpm_known: the collector's X-Heimdall-PHP fpm list is complete (header
-- v2: running master processes and pool sockets, not only pid files), so
-- a version nothing runs may be called unused. 0 for older collectors,
-- whose list missed every host that writes no pid file.
ALTER TABLE host_php ADD COLUMN fpm_known INTEGER NOT NULL DEFAULT 0 CHECK (fpm_known IN (0, 1));

-- When each host's apt package lists were last refreshed successfully,
-- from the collector's X-Heimdall-Apt header: pending updates come from
-- those lists, so old ones hide new updates. refreshed_at is NULL when the
-- host has no refresh stamp. No row: an older collector, or no apt.
CREATE TABLE host_apt (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    refreshed_at TEXT,
    seen_at      TEXT    NOT NULL
) STRICT;
