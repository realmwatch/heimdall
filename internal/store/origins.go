// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// SetHostOrigins records which of a host's packages came from a source
// other than the distro's: package name to the source's Origin (migration
// 0050).
func (s *Store) SetHostOrigins(ctx context.Context, hostID int64, origins map[string]string, at time.Time) error {
	if origins == nil {
		origins = map[string]string{}
	}
	b, err := json.Marshal(origins)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO host_origins (host_id, origins, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET origins = excluded.origins, seen_at = excluded.seen_at`,
		hostID, string(b), at.UTC().Format(timeLayout))
	return err
}

// HostOrigins is a host's third-party packages and their sources; ok is
// false when its collector never reported them.
func (s *Store) HostOrigins(ctx context.Context, hostID int64) (origins map[string]string, ok bool, err error) {
	var v string
	err = s.rd.QueryRowContext(ctx, `SELECT origins FROM host_origins WHERE host_id = ?`, hostID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal([]byte(v), &origins); err != nil {
		return nil, false, err
	}
	return origins, true, nil
}

// DistroRecord is what's known of a distro's own record for a CVE.
type DistroRecord struct {
	Found   bool
	Checked time.Time
}

// DistroRecords returns what was last found for each CVE and distro (OSV
// ID prefix), keyed [cve, distro]. Pairs never checked are absent.
func (s *Store) DistroRecords(ctx context.Context) (map[[2]string]DistroRecord, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT cve, distro, found, checked_at FROM distro_records`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[[2]string]DistroRecord{}
	for rows.Next() {
		var cve, distro, at string
		var found int
		if err := rows.Scan(&cve, &distro, &found, &at); err != nil {
			return nil, err
		}
		t, _ := time.Parse(timeLayout, at)
		out[[2]string{cve, distro}] = DistroRecord{Found: found == 1, Checked: t}
	}
	return out, rows.Err()
}

// SetDistroRecord records whether a distro's record for cve exists. Once
// found, it stays found.
func (s *Store) SetDistroRecord(ctx context.Context, cve, distro string, found bool, at time.Time) error {
	f := 0
	if found {
		f = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO distro_records (cve, distro, found, checked_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (cve, distro) DO UPDATE SET found = max(found, excluded.found), checked_at = excluded.checked_at`,
		cve, distro, f, at.UTC().Format(timeLayout))
	return err
}

// UpstreamAdvisory is a stored advisory from an upstream project's own
// list (its ID starts with prefix), with the record it was stored with.
type UpstreamAdvisory struct {
	ID  string
	Raw []byte
}

// UpstreamAdvisories lists the stored advisories whose ID starts with
// prefix ("NGINX-"), with their records.
func (s *Store) UpstreamAdvisories(ctx context.Context, prefix string) ([]UpstreamAdvisory, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT id, raw, record FROM advisories WHERE substr(id, 1, length(?)) = ? AND withdrawn IS NULL ORDER BY id`, prefix, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UpstreamAdvisory
	for rows.Next() {
		var a UpstreamAdvisory
		var raw string
		var z []byte
		if err := rows.Scan(&a.ID, &raw, &z); err != nil {
			return nil, err
		}
		if raw != "" {
			a.Raw = []byte(raw)
		} else if a.Raw, err = decompressRecord(z); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// WithdrawUpstream marks stored advisories with prefix that aren't in keep
// as withdrawn: the upstream list dropped them.
func (s *Store) WithdrawUpstream(ctx context.Context, prefix string, keep []string, at time.Time) (int, error) {
	b, err := json.Marshal(keep)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE advisories SET withdrawn = ?
		WHERE substr(id, 1, length(?)) = ? AND withdrawn IS NULL AND id NOT IN (SELECT value FROM json_each(?))`,
		at.UTC().Format(time.RFC3339Nano), prefix, prefix, string(b))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DistroAdvisoryFor reports whether a stored advisory from another source
// than prefix (a distro's) names cve and has a range for package pkg in
// an ecosystem starting with eco ("Ubuntu"): the distro has judged its own
// builds, so the upstream advisory no longer stands in for it.
func (s *Store) DistroAdvisoryFor(ctx context.Context, prefix, cve, eco, pkg string) (bool, error) {
	var n int
	err := s.rd.QueryRowContext(ctx, `
		SELECT count(*) FROM advisory_aliases al
		JOIN affected_ranges r ON r.advisory_id = al.advisory_id
		WHERE al.alias = ? AND substr(al.advisory_id, 1, length(?)) <> ?
		  AND r.package = ? AND (r.ecosystem = ? OR substr(r.ecosystem, 1, length(?) + 1) = ? || ':')`,
		cve, prefix, prefix, pkg, eco, eco, eco).Scan(&n)
	return n > 0, err
}
