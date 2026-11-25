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

// SiteVhost is one of a host's nginx sites as the collector reported it:
// the vhost file that serves it, or, when Enabled is false, the file that
// would (in sites-available, or set aside by the change-management tool).
type SiteVhost struct {
	Root    string
	Vhost   string // "" when the collector couldn't name it
	Enabled bool
	Names   []string // server names; only for disabled sites
}

// MaxSiteVhosts caps a host's stored sites.
const MaxSiteVhosts = 300

// SetHostSiteVhosts replaces a host's reported nginx sites.
func (s *Store) SetHostSiteVhosts(ctx context.Context, hostID int64, sites []SiteVhost) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_site_vhosts WHERE host_id = ?`, hostID); err != nil {
			return err
		}
		for i, v := range sites {
			if i == MaxSiteVhosts {
				break
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO host_site_vhosts (host_id, root, vhost, enabled, names)
				VALUES (?, ?, ?, ?, ?) ON CONFLICT (host_id, root) DO NOTHING`,
				hostID, v.Root, v.Vhost, v.Enabled, strings.Join(v.Names, ",")); err != nil {
				return err
			}
		}
		return nil
	})
}

// HostSiteVhosts is a host's reported nginx sites by root.
func (s *Store) HostSiteVhosts(ctx context.Context, hostID int64) (map[string]SiteVhost, error) {
	all, err := s.siteVhosts(ctx, `WHERE v.host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	out := map[string]SiteVhost{}
	for _, d := range all {
		out[d.Root] = d.SiteVhost
	}
	return out, nil
}

// HostedSiteVhost is a SiteVhost with its host.
type HostedSiteVhost struct {
	SiteVhost
	HostID, OrgID int64
	Org, Host     string
}

// AllSiteVhosts are every host's reported nginx sites, keyed by
// SiteLabelKey.
func (s *Store) AllSiteVhosts(ctx context.Context) (map[string]HostedSiteVhost, error) {
	all, err := s.siteVhosts(ctx, ``)
	if err != nil {
		return nil, err
	}
	out := make(map[string]HostedSiteVhost, len(all))
	for _, d := range all {
		out[SiteLabelKey(d.Org, d.Host, d.Root)] = d
	}
	return out, nil
}

// DisabledSites are the sites, across every host, whose vhost the
// collector reports as not enabled.
func (s *Store) DisabledSites(ctx context.Context) ([]HostedSiteVhost, error) {
	return s.siteVhosts(ctx, `WHERE v.enabled = 0`)
}

func (s *Store) siteVhosts(ctx context.Context, where string, args ...any) ([]HostedSiteVhost, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT v.host_id, h.org_id, o.slug, h.name, v.root, v.vhost, v.enabled, v.names
		FROM host_site_vhosts v
		JOIN hosts h ON h.id = v.host_id
		JOIN organizations o ON o.id = h.org_id `+where+`
		ORDER BY o.slug, h.name, v.root`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostedSiteVhost
	for rows.Next() {
		var d HostedSiteVhost
		var names string
		if err := rows.Scan(&d.HostID, &d.OrgID, &d.Org, &d.Host, &d.Root, &d.Vhost, &d.Enabled, &names); err != nil {
			return nil, err
		}
		if names != "" {
			d.Names = strings.Split(names, ",")
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SiteArchive is who archived a site, and when.
type SiteArchive struct {
	By string
	At time.Time
}

// ArchivedSites are the archived sites, keyed by SiteLabelKey.
func (s *Store) ArchivedSites(ctx context.Context) (map[string]SiteArchive, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT o.slug, h.name, a.root, a.archived_by, a.archived_at
		FROM site_archive a
		JOIN hosts h ON h.id = a.host_id
		JOIN organizations o ON o.id = h.org_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SiteArchive{}
	for rows.Next() {
		var org, host, root, by, at string
		if err := rows.Scan(&org, &host, &root, &by, &at); err != nil {
			return nil, err
		}
		out[SiteLabelKey(org, host, root)] = SiteArchive{By: by, At: parseTime(at)}
	}
	return out, rows.Err()
}

// SetSiteArchived archives a site on a host, or brings it back. It only
// records the intent: disabling the site is the change-management tool's
// job.
func (s *Store) SetSiteArchived(ctx context.Context, actor string, hostID int64, root string, archived bool) error {
	if root == "" || len(root) > 4096 {
		return &ValidationError{"site", "a site root is required"}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, hostID).Scan(&orgID, &name); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %d: %w", hostID, ErrNotFound)
		} else if err != nil {
			return err
		}
		var err error
		action := "site.archive"
		if archived {
			_, err = tx.ExecContext(ctx, `INSERT INTO site_archive (host_id, root, archived_by) VALUES (?, ?, ?)
				ON CONFLICT (host_id, root) DO NOTHING`, hostID, root, actor)
		} else {
			action = "site.unarchive"
			_, err = tx.ExecContext(ctx, `DELETE FROM site_archive WHERE host_id = ? AND root = ?`, hostID, root)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, OrgID: orgID, Target: name,
			Detail: map[string]any{"root": root}})
	})
}
