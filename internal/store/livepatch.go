// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"
)

// HostLivepatch is a host's live patch state, from its collector.
type HostLivepatch struct {
	// Applied: a patch is loaded, enabled and not mid-transition (the
	// kernel's own word, /sys/kernel/livepatch).
	Applied bool `json:"applied"`
	// State, Version and Support are Canonical's client's ("applied",
	// "108.1", "supported"), "" when unknown; Fixes the CVEs it says the
	// applied patch fixes, upper case; Checked when it said so.
	State   string    `json:"state,omitempty"`
	Version string    `json:"version,omitempty"`
	Support string    `json:"support,omitempty"`
	Checked time.Time `json:"checked,omitzero"`
	Fixes   []string  `json:"fixes,omitempty"`
	// Reboot is what a pending reboot is for (/run/reboot-required.pkgs):
	// "kernel" (only kernel packages), "other", or "" (none).
	Reboot string    `json:"reboot,omitempty"`
	SeenAt time.Time `json:"-"`
}

// LivepatchFresh is how old the client's status may be, against the
// report that carried it, for its fixes to count: its timer saves it
// hourly.
const LivepatchFresh = 26 * time.Hour

// Mitigates are the CVEs the applied patch fixes, or nil when no patch is
// applied or the client's status is missing or stale.
func (l HostLivepatch) Mitigates() []string {
	if !l.Applied || l.State != "applied" || l.Checked.IsZero() || l.SeenAt.Sub(l.Checked) > LivepatchFresh {
		return nil
	}
	return l.Fixes
}

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)

// SetHostLivepatch records a host's live patch state; fixes that aren't
// CVE ids are dropped.
func (s *Store) SetHostLivepatch(ctx context.Context, hostID int64, l HostLivepatch, at time.Time) error {
	clean := []string{}
	for _, f := range l.Fixes {
		f = strings.ToUpper(f)
		if cveID.MatchString(f) && !slices.Contains(clean, f) && len(clean) < 500 {
			clean = append(clean, f)
		}
	}
	slices.Sort(clean)
	l.Fixes = clean
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old string
	_ = tx.QueryRowContext(ctx, `SELECT state FROM host_livepatch WHERE host_id = ?`, hostID).Scan(&old)
	if _, err := tx.ExecContext(ctx, `INSERT INTO host_livepatch (host_id, state, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET state = excluded.state, seen_at = excluded.seen_at`,
		hostID, string(b), at.UTC().Format(timeLayout)); err != nil {
		return err
	}
	// What the patch mitigates changes the host's tallies.
	if old != string(b) {
		if err := refreshFindingCounts(ctx, tx, hostID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// HostLivepatches is every host's live patch state, by host ID.
func (s *Store) HostLivepatches(ctx context.Context) (map[int64]HostLivepatch, error) {
	return hostLivepatches(ctx, s.rd, 0)
}

// HostLivepatchOf is one host's live patch state; ok is false without one.
func (s *Store) HostLivepatchOf(ctx context.Context, hostID int64) (HostLivepatch, bool, error) {
	m, err := hostLivepatches(ctx, s.rd, hostID)
	l, ok := m[hostID]
	return l, ok, err
}

type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func hostLivepatches(ctx context.Context, q rowsQuerier, hostID int64) (map[int64]HostLivepatch, error) {
	rows, err := q.QueryContext(ctx, `SELECT host_id, state, seen_at FROM host_livepatch WHERE ?1 = 0 OR host_id = ?1`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostLivepatch{}
	for rows.Next() {
		var id int64
		var state, at string
		if err := rows.Scan(&id, &state, &at); err != nil {
			return nil, err
		}
		var l HostLivepatch
		if json.Unmarshal([]byte(state), &l) != nil {
			continue
		}
		l.SeenAt = parseTime(at)
		out[id] = l
	}
	return out, rows.Err()
}

// KernelSource reports whether an OS package source is a kernel's (linux
// and its flavours), as countsSQL's livepatch rule tells it.
func KernelSource(pkg string) bool {
	return (pkg == "linux" || strings.HasPrefix(pkg, "linux-")) && !slices.Contains(notKernelSources, pkg)
}

var notKernelSources = []string{"linux-firmware", "linux-base", "linux-atm", "linux-ftpd"}
