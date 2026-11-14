// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// FleetQuiet is one org's open "fleet went quiet" episode (migration 0046,
// internal/anomaly/fleet.go).
type FleetQuiet struct {
	OrgID      int64
	OrgSlug    string
	HeldSince  time.Time // the condition was first seen
	QuietSince time.Time // when the quiet hosts stopped reporting
	Quiet      int       // hosts quiet
	Total      int       // regularly reporting hosts that count
	Hosts      []string  // the quiet hosts' names (capped)
	Still      string    // what still reports: "hub", "tailnet", "local" or ""
	Outside    bool      // every host reporting from outside went quiet
	// ConfirmedAt: the condition held long enough to show and send (zero
	// until then). Notified: the "down" notice went out.
	ConfirmedAt time.Time
	Notified    bool
	ClearSince  time.Time // the condition stopped holding (zero while it holds)
}

// Down reports whether the episode is confirmed and still holds: what the
// banner shows.
func (q FleetQuiet) Down() bool { return !q.ConfirmedAt.IsZero() && q.ClearSince.IsZero() }

// Headline is the episode in one sentence, for the banner, the alert and
// MCP, e.g. "Public ingest looks down: 9 of 11 hosts in acme stopped
// reporting since 22:15 UTC; the hub's own collector still reports."
func (q FleetQuiet) Headline(now time.Time) string {
	since := q.QuietSince.UTC()
	at := since.Format("15:04 UTC")
	if now.Sub(since) >= 20*time.Hour {
		at = since.Format("Jan 2 15:04 UTC")
	}
	s := fmt.Sprintf("Public ingest looks down: %d of %d hosts in %s stopped reporting since %s", q.Quiet, q.Total, q.OrgSlug, at)
	if q.Outside && 2*q.Quiet <= q.Total {
		s += ", every one that reports from outside"
	}
	switch q.Still {
	case "hub":
		return s + "; the hub's own collector still reports."
	case "tailnet":
		return s + "; hosts on the tailnet still report."
	case "local":
		return s + "; hosts on the local network still report."
	}
	if n := q.Total - q.Quiet; n == 1 {
		return s + "; the other one still reports."
	} else if n > 1 {
		return s + fmt.Sprintf("; the other %d still report.", n)
	}
	return s + "."
}

// FleetQuietStates lists the open episodes, by org slug.
func (s *Store) FleetQuietStates(ctx context.Context) ([]FleetQuiet, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT f.org_id, o.slug, f.held_since, f.quiet_since, f.quiet, f.total, f.hosts, f.still, f.outside,
		       f.confirmed_at, f.notified, f.clear_since
		FROM fleet_quiet f JOIN organizations o ON o.id = f.org_id ORDER BY o.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FleetQuiet
	for rows.Next() {
		var q FleetQuiet
		var held, since, hosts string
		var confirmed, clear sql.NullString
		if err := rows.Scan(&q.OrgID, &q.OrgSlug, &held, &since, &q.Quiet, &q.Total, &hosts, &q.Still, &q.Outside,
			&confirmed, &q.Notified, &clear); err != nil {
			return nil, err
		}
		q.HeldSince, q.QuietSince = parseTime(held), parseTime(since)
		q.ConfirmedAt, q.ClearSince = parseNullTime(confirmed), parseNullTime(clear)
		if err := json.Unmarshal([]byte(hosts), &q.Hosts); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// PutFleetQuiet stores an org's episode, replacing what was there.
func (s *Store) PutFleetQuiet(ctx context.Context, q FleetQuiet) error {
	hosts, err := json.Marshal(append([]string{}, q.Hosts...))
	if err != nil {
		return err
	}
	opt := func(t time.Time) sql.NullString {
		if t.IsZero() {
			return sql.NullString{}
		}
		return sql.NullString{String: t.UTC().Format(timeLayout), Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO fleet_quiet (org_id, held_since, quiet_since, quiet, total, hosts, still, outside, confirmed_at, notified, clear_since)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (org_id) DO UPDATE SET held_since = excluded.held_since, quiet_since = excluded.quiet_since,
		  quiet = excluded.quiet, total = excluded.total, hosts = excluded.hosts, still = excluded.still,
		  outside = excluded.outside, confirmed_at = excluded.confirmed_at, notified = excluded.notified,
		  clear_since = excluded.clear_since`,
		q.OrgID, q.HeldSince.UTC().Format(timeLayout), q.QuietSince.UTC().Format(timeLayout), q.Quiet, q.Total,
		string(hosts), q.Still, q.Outside, opt(q.ConfirmedAt), q.Notified, opt(q.ClearSince))
	return err
}

// DeleteFleetQuiet ends an org's episode.
func (s *Store) DeleteFleetQuiet(ctx context.Context, orgID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fleet_quiet WHERE org_id = ?`, orgID)
	return err
}

// FleetHost is a host the fleet-quiet check weighs: when it last reported,
// and from where.
type FleetHost struct {
	IngestHost
	LastSeenAt time.Time
	ReportIP   string // "" if unknown
}

// FleetHosts lists hosts that last reported at or after since.
func (s *Store) FleetHosts(ctx context.Context, since time.Time) ([]FleetHost, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, h.last_seen_at, h.report_ip
		FROM hosts h JOIN organizations o ON o.id = h.org_id
		WHERE h.last_seen_at IS NOT NULL AND h.last_seen_at >= ? ORDER BY o.slug, h.name`,
		since.UTC().Format(timeLayout))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FleetHost
	for rows.Next() {
		var h FleetHost
		var seen string
		if err := rows.Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &seen, &h.ReportIP); err != nil {
			return nil, err
		}
		h.LastSeenAt = parseTime(seen)
		out = append(out, h)
	}
	return out, rows.Err()
}
