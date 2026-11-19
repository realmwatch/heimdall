// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// maxKept caps the packages kept on one host.
const maxKept = 300

var keptNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,199}$`)

// KeptPackages are the packages marked as installed on purpose on a host
// (migration 0052), sorted.
func (s *Store) KeptPackages(ctx context.Context, hostID int64) ([]string, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT name FROM host_kept_packages WHERE host_id = ? ORDER BY name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// KeptPackagesAll is every host's kept packages, by host ID.
func (s *Store) KeptPackagesAll(ctx context.Context) (map[int64][]string, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, name FROM host_kept_packages ORDER BY host_id, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = append(out[id], n)
	}
	return out, rows.Err()
}

// SetPackageKept marks a host's package as installed on purpose, or
// unmarks it, and audits it.
func (s *Store) SetPackageKept(ctx context.Context, actor string, hostID int64, name string, keep bool, at time.Time) error {
	if !keptNameRe.MatchString(name) {
		return &ValidationError{Field: "package", Msg: "not a package name"}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var host string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, hostID).Scan(&orgID, &host); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %d: %w", hostID, ErrNotFound)
		} else if err != nil {
			return err
		}
		action := "host.package_keep"
		if keep {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM host_kept_packages WHERE host_id = ?`, hostID).Scan(&n); err != nil {
				return err
			}
			if n >= maxKept {
				return &ValidationError{Field: "package", Msg: "too many kept packages"}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO host_kept_packages (host_id, name, kept_by, kept_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (host_id, name) DO NOTHING`, hostID, name, actor, at.UTC().Format(timeLayout)); err != nil {
				return err
			}
		} else {
			action = "host.package_unkeep"
			if _, err := tx.ExecContext(ctx, `DELETE FROM host_kept_packages WHERE host_id = ? AND name = ?`, hostID, name); err != nil {
				return err
			}
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, OrgID: orgID, Target: host, Detail: map[string]any{"package": name}})
	})
}
