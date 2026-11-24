-- Each host's live patch state from the collector's X-Heimdall-Livepatch
-- header (internal/ingest/livepatch.go): whether a patch is applied, and
-- what Canonical's client says it fixes. state is store.HostLivepatch as
-- JSON. No row: an older collector, or a kernel that can't take live
-- patches.
CREATE TABLE host_livepatch (
    host_id INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    state   TEXT    NOT NULL CHECK (json_valid(state)),
    seen_at TEXT    NOT NULL
) STRICT;

-- Kernel findings the applied live patch fixes: in total, and no other count.
ALTER TABLE finding_counts ADD COLUMN livepatched INTEGER NOT NULL DEFAULT 0;
