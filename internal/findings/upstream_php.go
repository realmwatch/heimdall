// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/realmwatch/heimdall/internal/ecosystem"
	"github.com/realmwatch/heimdall/internal/feeds/osv"
	"github.com/realmwatch/heimdall/internal/feeds/php"
	"github.com/realmwatch/heimdall/internal/store"
)

// PHP's own advisories (internal/feeds/php), stored as OSV records under
// IDs starting php.IDPrefix, judge third-party PHP builds: Ondřej Surý's
// packages carry upstream versions ("8.4.27-1+ubuntu24.04.1+deb.sury.org+1")
// that no distro advisory can judge, so without these nothing checks PHP
// itself on hosts that run them. The distro's own PHP builds are left to
// the distro's advisories: they backport fixes, so their upstream version
// says little.

// phpPackage is one third-party PHP branch installed on a host: the binary
// packages built from one source ("php8.4") at one version.
type phpPackage struct {
	source   string // "php8.4"
	version  string // the package's ("8.4.27-1+ubuntu24.04.1+deb.sury.org+1")
	upstream string // PHP's ("8.4.27")
	binaries []string
	pending  []string
}

// isPHP reports whether a package is built from one of PHP's per-branch
// source packages.
func isPHP(p store.InventoryPackage) bool { return php.IsSource(p.SourceName) }

// phpPackages groups the host's third-party PHP packages by source and
// version.
func phpPackages(pkgs []store.InventoryPackage, third map[string]bool) []phpPackage {
	type key struct{ source, version string }
	by := map[key]*phpPackage{}
	var order []key
	for _, p := range pkgs {
		if !isPHP(p) || !third[p.Name] {
			continue
		}
		v := p.SourceVersion
		if v == "" {
			v = p.Version
		}
		up, ok := php.UpstreamVersion(v)
		if !ok {
			continue
		}
		k := key{p.SourceName, v}
		u := by[k]
		if u == nil {
			u = &phpPackage{source: p.SourceName, version: v, upstream: up}
			by[k] = u
			order = append(order, k)
		}
		if !slices.Contains(u.binaries, p.Name) {
			u.binaries = append(u.binaries, p.Name)
		}
		if p.PendingVersion != "" {
			u.pending = append(u.pending, p.PendingVersion)
		}
	}
	out := make([]phpPackage, 0, len(order))
	for _, k := range order {
		u := by[k]
		slices.Sort(u.binaries)
		out = append(out, *u)
	}
	return out
}

// phpAdvisory is a stored PHP advisory, read back from its record.
type phpAdvisory struct {
	id         string
	ranges     []php.Range
	good       []string
	components []string
}

func parsePHPAdvisory(rec store.UpstreamAdvisory) (phpAdvisory, bool) {
	v, err := osv.Parse(rec.Raw)
	if err != nil || v.ID != rec.ID {
		return phpAdvisory{}, false
	}
	a := phpAdvisory{id: v.ID}
	for _, aff := range v.Affected {
		if aff.Package.Ecosystem != php.Ecosystem || aff.Package.Name != php.Package {
			continue
		}
		for _, r := range aff.Ranges {
			var cur php.Range
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					cur = php.Range{Lo: e.Introduced}
					if cur.Lo == "0" {
						cur.Lo = ""
					}
				case e.Fixed != "":
					cur.Hi = e.Fixed
				case e.LastAffected != "":
					cur.Hi, cur.HiIncl = e.LastAffected, true
				}
			}
			a.ranges = append(a.ranges, cur)
		}
	}
	var ds struct {
		Good       []string `json:"good"`
		Components []string `json:"components"`
	}
	if len(v.DatabaseSpecific) > 0 && json.Unmarshal(v.DatabaseSpecific, &ds) == nil {
		a.good, a.components = ds.Good, ds.Components
	}
	return a, len(a.ranges) > 0
}

// phpFindings matches the host's third-party PHP against the stored PHP
// advisories, where the part of PHP each is about is installed.
func (e *Engine) phpFindings(ctx context.Context, info ecosystem.Info, pkgs []phpPackage) ([]store.Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	recs, err := e.Store.UpstreamAdvisories(ctx, php.IDPrefix)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	var fs []store.Finding
	for _, rec := range recs {
		a, ok := parsePHPAdvisory(rec)
		if !ok {
			continue
		}
		for _, p := range pkgs {
			if !php.Affects(a.ranges, a.good, p.upstream) || !php.Installed(a.components, p.source, p.binaries) {
				continue
			}
			fixed := php.FixFor(a.good, p.upstream)
			pending := false
			if fixed != "" {
				for _, pv := range p.pending {
					if up, ok := php.UpstreamVersion(pv); ok && compare(info.Scheme, up, fixed) >= 0 {
						pending = true
					}
				}
			}
			fs = append(fs, store.Finding{
				AdvisoryID: a.id, Ecosystem: php.Ecosystem, Package: p.source, Version: p.version,
				Binaries: p.binaries, FixedVersion: fixed, FixPending: pending,
			})
		}
	}
	return fs, nil
}

// syncPHP fetches PHP's advisories, stores them and withdraws those the
// list no longer has.
func (s *Syncer) syncPHP(ctx context.Context) error {
	list, err := php.Fetch(ctx, s.HTTP, s.PHPURL, s.GitHubToken)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(list))
	for _, a := range list {
		raw := a.OSV()
		v, err := osv.Parse(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", a.ID, err)
		}
		adv := toAdvisory(v, raw)
		adv.Modified = s.Now()
		if err := s.Store.PutAdvisory(ctx, adv); err != nil {
			return err
		}
		ids = append(ids, a.ID)
	}
	if n, err := s.Store.WithdrawUpstream(ctx, php.IDPrefix, ids, s.Now()); err != nil {
		return err
	} else if n > 0 {
		s.Log.Info("upstream advisories withdrawn", "source", "php-src", "count", n)
	}
	return nil
}
