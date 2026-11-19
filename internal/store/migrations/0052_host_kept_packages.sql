-- Packages an operator marked as installed on purpose on a host
-- (internal/leftovers): a .deb no apt source has that isn't a release
-- leftover, though its version doesn't show it. The release cleanup leaves
-- them alone.
CREATE TABLE host_kept_packages (
    host_id INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    name    TEXT    NOT NULL,
    kept_by TEXT    NOT NULL,
    kept_at TEXT    NOT NULL,
    PRIMARY KEY (host_id, name)
) STRICT;
