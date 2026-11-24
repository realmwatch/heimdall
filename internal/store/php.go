// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"time"
)

// HostPHP is what a host's collector said about its PHP versions: the
// command line's (CLI, "" for none) and those whose PHP-FPM is running.
type HostPHP struct {
	CLI string
	FPM []string
	// FPMKnown: FPM is complete (collector 0.5.45 on), so a version
	// nothing runs may be called unused.
	FPMKnown bool
	SeenAt   time.Time
}

// phpMinor is a PHP version as the collector reports it, e.g. "8.4".
var phpMinor = regexp.MustCompile(`^[5-9]\.[0-9]{1,2}$`)

// ValidPHPVersion reports whether v looks like "8.4".
func ValidPHPVersion(v string) bool { return phpMinor.MatchString(v) }

// SetHostPHP records a host's PHP state. Versions that don't look like
// one are dropped.
func (s *Store) SetHostPHP(ctx context.Context, hostID int64, cli string, fpm []string, fpmKnown bool, at time.Time) error {
	if !ValidPHPVersion(cli) {
		cli = ""
	}
	clean := []string{}
	for _, v := range fpm {
		if ValidPHPVersion(v) && !slices.Contains(clean, v) && len(clean) < 20 {
			clean = append(clean, v)
		}
	}
	slices.Sort(clean)
	b, _ := json.Marshal(clean)
	_, err := s.db.ExecContext(ctx, `INSERT INTO host_php (host_id, cli, fpm, fpm_known, seen_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET cli = excluded.cli, fpm = excluded.fpm, fpm_known = excluded.fpm_known, seen_at = excluded.seen_at`,
		hostID, cli, string(b), fpmKnown, at.UTC().Format(timeLayout))
	return err
}

// HostPHPs is every host's PHP state, by host ID; hosts whose collector
// never reported it are absent.
func (s *Store) HostPHPs(ctx context.Context) (map[int64]HostPHP, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, cli, fpm, fpm_known, seen_at FROM host_php`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostPHP{}
	for rows.Next() {
		var id int64
		var p HostPHP
		var fpm, at string
		if err := rows.Scan(&id, &p.CLI, &fpm, &p.FPMKnown, &at); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(fpm), &p.FPM)
		p.SeenAt = parseTime(at)
		out[id] = p
	}
	return out, rows.Err()
}

// SetHostApt records when a host's apt package lists were last refreshed
// successfully; zero refreshed is unknown (no stamp on the host).
func (s *Store) SetHostApt(ctx context.Context, hostID int64, refreshed, at time.Time) error {
	var r any
	if !refreshed.IsZero() {
		r = refreshed.UTC().Format(timeLayout)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO host_apt (host_id, refreshed_at, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET refreshed_at = excluded.refreshed_at, seen_at = excluded.seen_at`,
		hostID, r, at.UTC().Format(timeLayout))
	return err
}

// HostApts is when each host's apt lists were last refreshed, by host ID
// (zero: no stamp); hosts whose collector never said are absent.
func (s *Store) HostApts(ctx context.Context) (map[int64]time.Time, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, coalesce(refreshed_at, '') FROM host_apt`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]time.Time{}
	for rows.Next() {
		var id int64
		var at string
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		var t time.Time
		if at != "" {
			t = parseTime(at)
		}
		out[id] = t
	}
	return out, rows.Err()
}
