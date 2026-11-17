// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"time"
)

// TripRetention is how long trips are kept.
const TripRetention = 90 * 24 * time.Hour

// Trip is one tripwire report from an app on a host (docs/tripwires.md),
// already validated by ingest.
type Trip struct {
	ID         string // the app's ULID; unique per host
	OccurredAt time.Time
	Site, Root string
	Tripwire   string
	Token      string
	Severity   string // noise, low, high or critical
	IP         string // "" when the trip had no request
	Method     string
	Path       string
	UserID     string // "" when no one was signed in
	Detail     string // JSON object
}

// RecordTrips stores a host's trips, skipping ones it already has, and
// prunes the host's trips older than TripRetention. fresh are the ones
// stored now.
func (s *Store) RecordTrips(ctx context.Context, hostID int64, trips []Trip, now time.Time) (fresh []Trip, err error) {
	ts := now.UTC().Format(timeLayout)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		for _, t := range trips {
			res, err := tx.ExecContext(ctx, `
				INSERT INTO trips (host_id, trip_id, occurred_at, received_at, site, root, tripwire, token,
				                   severity, ip, method, path, user_id, detail)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT DO NOTHING`,
				hostID, t.ID, t.OccurredAt.UTC().Format(timeLayout), ts, t.Site, t.Root, t.Tripwire, t.Token,
				t.Severity, t.IP, t.Method, t.Path, t.UserID, t.Detail)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				fresh = append(fresh, t)
			}
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM trips WHERE host_id = ? AND occurred_at < ?`,
			hostID, now.Add(-TripRetention).UTC().Format(timeLayout))
		return err
	})
	return fresh, err
}

// RecentTrips are a host's latest trips, newest first.
func (s *Store) RecentTrips(ctx context.Context, hostID int64, limit int) ([]Trip, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT trip_id, occurred_at, site, root, tripwire, token, severity, ip, method, path, user_id, detail
		FROM trips WHERE host_id = ? ORDER BY occurred_at DESC, id DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Trip
	for rows.Next() {
		var t Trip
		var at string
		if err := rows.Scan(&t.ID, &at, &t.Site, &t.Root, &t.Tripwire, &t.Token, &t.Severity, &t.IP,
			&t.Method, &t.Path, &t.UserID, &t.Detail); err != nil {
			return nil, err
		}
		t.OccurredAt = parseTime(at)
		out = append(out, t)
	}
	return out, rows.Err()
}
