// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SetHostRelease records a host's apt state (leftovers.State as JSON,
// migration 0045).
func (s *Store) SetHostRelease(ctx context.Context, hostID int64, state []byte, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO host_release (host_id, state, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET state = excluded.state, seen_at = excluded.seen_at`,
		hostID, string(state), at.UTC().Format(timeLayout))
	return err
}

// HostRelease is a host's apt state as JSON; ok is false when its
// collector never reported it.
func (s *Store) HostRelease(ctx context.Context, hostID int64) (state []byte, ok bool, err error) {
	var v string
	err = s.rd.QueryRowContext(ctx, `SELECT state FROM host_release WHERE host_id = ?`, hostID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return []byte(v), true, nil
}

// HostReleases is every host's apt state as JSON, by host ID.
func (s *Store) HostReleases(ctx context.Context) (map[int64][]byte, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, state FROM host_release`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]byte{}
	for rows.Next() {
		var id int64
		var v string
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = []byte(v)
	}
	return out, rows.Err()
}
