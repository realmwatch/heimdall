// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxFindingIDs caps one FindingsByID lookup (and the MCP finding tool).
const MaxFindingIDs = 200

// FindingStatus is one finding by id, open or resolved, with its host. A
// change-management tool keeps the id and asks again later whether the
// finding is gone.
type FindingStatus struct {
	ID         int64
	OrgID      int64
	Org, Host  string
	Advisory   string
	CVEs       []string
	Severity   string
	KEV        bool
	Package    string
	Version    string // installed when last seen
	Fixed      string // "" if no fix published
	SiteRoot   string // "" for OS packages
	Ecosystem  string
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt time.Time // zero while open
}

// FindingsByID returns the findings with these ids, in id order. Ids that
// don't exist are left out; callers check each finding's OrgID against
// what the caller may see.
func (s *Store) FindingsByID(ctx context.Context, ids []int64) ([]FindingStatus, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > MaxFindingIDs {
		return nil, fmt.Errorf("at most %d finding ids at once", MaxFindingIDs)
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.rd.QueryContext(ctx, `
		SELECT f.id, h.org_id, o.slug, h.name, f.advisory_id, coalesce(a.severity, ''),
		       f.package_name, f.package_version, coalesce(f.fixed_version, ''), f.site_root, f.ecosystem,
		       f.first_seen_at, f.last_seen_at, coalesce(f.resolved_at, ''),
		       coalesce((SELECT group_concat(alias, ' ') FROM advisory_aliases WHERE advisory_id = f.advisory_id AND alias LIKE 'CVE-%'), ''),
		       EXISTS (SELECT 1 FROM kev_entries k
		               WHERE k.cve_id = f.advisory_id OR k.cve_id IN (SELECT alias FROM advisory_aliases WHERE advisory_id = f.advisory_id))
		FROM findings f
		JOIN hosts h ON h.id = f.host_id
		JOIN organizations o ON o.id = h.org_id
		LEFT JOIN advisories a ON a.id = f.advisory_id
		WHERE f.id IN (?`+strings.Repeat(", ?", len(ids)-1)+`)
		ORDER BY f.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingStatus
	for rows.Next() {
		var f FindingStatus
		var first, last, resolved, cves string
		if err := rows.Scan(&f.ID, &f.OrgID, &f.Org, &f.Host, &f.Advisory, &f.Severity, &f.Package, &f.Version,
			&f.Fixed, &f.SiteRoot, &f.Ecosystem, &first, &last, &resolved, &cves, &f.KEV); err != nil {
			return nil, err
		}
		f.FirstSeen, f.LastSeen = parseTime(first), parseTime(last)
		if resolved != "" {
			f.ResolvedAt = parseTime(resolved)
		}
		if cves != "" {
			f.CVEs = strings.Fields(cves)
		} else if strings.HasPrefix(f.Advisory, "CVE-") {
			f.CVEs = []string{f.Advisory}
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// HostByMachine finds the host in an org whose collector reports this
// machine ID hash (the oldest, if a rebuilt server left two).
func (s *Store) HostByMachine(ctx context.Context, orgSlug, machine string) (IngestHost, error) {
	m := NormalizeMachine(machine)
	if m == "" {
		return IngestHost{}, errors.New("machine must be a hex SHA-256 machine ID hash")
	}
	var h IngestHost
	err := s.rd.QueryRowContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, h.auto_name, e.slug
		FROM hosts h JOIN organizations o ON o.id = h.org_id JOIN environments e ON e.id = h.env_id
		WHERE o.slug = ? AND h.machine = ?
		ORDER BY h.id LIMIT 1`, orgSlug, m).
		Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &h.AutoName, &h.EnvSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return IngestHost{}, fmt.Errorf("no host with that machine in org %q: %w", orgSlug, ErrNotFound)
	}
	return h, err
}

// HostMachine is the machine ID hash a host's collector last reported, or "".
func (s *Store) HostMachine(ctx context.Context, hostID int64) (string, error) {
	var m string
	err := s.rd.QueryRowContext(ctx, `SELECT machine FROM hosts WHERE id = ?`, hostID).Scan(&m)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return m, err
}
