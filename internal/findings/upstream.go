// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/realmwatch/heimdall/internal/ecosystem"
	"github.com/realmwatch/heimdall/internal/feeds/nginx"
	"github.com/realmwatch/heimdall/internal/feeds/osv"
	"github.com/realmwatch/heimdall/internal/feeds/php"
	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/store"
)

// Upstream advisories: nginx.org's own list (internal/feeds/nginx), stored
// as OSV records under IDs starting nginx.IDPrefix, with ranges in plain
// upstream versions.
//
// They're matched against two kinds of nginx package:
//
//   - nginx.org's builds (and any other non-distro build): their versions
//     aren't the distro's, so a distro advisory can't judge them ("1.30.6"
//     looks newer than Ubuntu's fixed "1.18.0-6ubuntu14.5"). They're left
//     out of distro matching and judged by nginx.org's advisories alone,
//     with nginx.org's fix.
//   - the distro's own builds, for an advisory the distro hasn't published
//     a record of yet: the days between nginx.org's fix and the distro's,
//     when distro matching shows nothing. No fix is offered (the distro has
//     none yet); the distro's record takes over once it exists.

// UpstreamChecked reports whether an upstream project's own advisories
// cover a package (nginx.org's cover nginx, PHP's own cover PHP), so a third-party build
// of it is still checked.
func UpstreamChecked(p store.InventoryPackage) bool { return isNginx(p) || isPHP(p) }

// upstreamPackage is one nginx package version installed on a host.
type upstreamPackage struct {
	version    string // the package's ("1.30.6-1~jammy")
	upstream   string // nginx's ("1.30.6")
	binaries   []string
	pending    []string
	thirdParty bool
}

// isNginx reports whether a package is a build of nginx itself (by its
// source package, or its own name when it has none).
func isNginx(p store.InventoryPackage) bool {
	src := p.SourceName
	if src == "" {
		src = p.Name
	}
	return src == "nginx"
}

// thirdPartyPackages are the host's packages that came from a source other
// than the distro's, by name: those the collector says came from another
// apt source, and nginx.org's and Ondřej Surý's nginx and PHP builds by
// their version (for collectors that don't say, and for a source whose
// lists are gone, like the removed ondrej/nginx PPA).
func thirdPartyPackages(pkgs []store.InventoryPackage, origins map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, p := range pkgs {
		if origins[p.Name] != "" || (isNginx(p) && nginx.IsThirdPartyBuild(p.Version)) || (isPHP(p) && php.IsSuryBuild(p.Version)) {
			out[p.Name] = true
		}
	}
	return out
}

// nginxPackages groups the host's nginx packages by version.
func nginxPackages(pkgs []store.InventoryPackage, third map[string]bool) []upstreamPackage {
	byVer := map[string]*upstreamPackage{}
	var order []string
	for _, p := range pkgs {
		if !isNginx(p) {
			continue
		}
		v := p.Version
		if p.SourceVersion != "" {
			v = p.SourceVersion
		}
		up, ok := nginx.UpstreamVersion(v)
		if !ok {
			continue
		}
		u := byVer[v]
		if u == nil {
			u = &upstreamPackage{version: v, upstream: up}
			byVer[v] = u
			order = append(order, v)
		}
		u.binaries = append(u.binaries, p.Name)
		if p.PendingVersion != "" {
			u.pending = append(u.pending, p.PendingVersion)
		}
		u.thirdParty = u.thirdParty || third[p.Name]
	}
	out := make([]upstreamPackage, 0, len(order))
	for _, v := range order {
		u := byVer[v]
		slices.Sort(u.binaries)
		out = append(out, *u)
	}
	return out
}

// upstreamAdvisory is a stored nginx.org advisory, read back from its
// record.
type upstreamAdvisory struct {
	id, cve string
	ranges  [][3]string // introduced, fixed, last_affected
	good    []string
}

func (a upstreamAdvisory) affects(v string) bool {
	for _, r := range a.ranges {
		if nginx.Compare(v, r[0]) < 0 {
			continue
		}
		switch {
		case r[1] != "" && nginx.Compare(v, r[1]) < 0,
			r[2] != "" && nginx.Compare(v, r[2]) <= 0,
			r[1] == "" && r[2] == "":
			return true
		}
	}
	return false
}

// fixFor mirrors nginx.Advisory.FixFor.
func (a upstreamAdvisory) fixFor(v string) string {
	return nginx.Advisory{Good: a.good}.FixFor(v)
}

func parseUpstream(rec store.UpstreamAdvisory) (upstreamAdvisory, bool) {
	v, err := osv.Parse(rec.Raw)
	if err != nil || v.ID != rec.ID {
		return upstreamAdvisory{}, false
	}
	a := upstreamAdvisory{id: v.ID}
	if cves := v.CVEs(); len(cves) > 0 {
		a.cve = cves[0]
	}
	for _, aff := range v.Affected {
		if aff.Package.Ecosystem != nginx.Ecosystem || aff.Package.Name != nginx.Package {
			continue
		}
		for _, r := range aff.Ranges {
			var cur [3]string
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					cur = [3]string{e.Introduced, "", ""}
				case e.Fixed != "":
					cur[1] = e.Fixed
				case e.LastAffected != "":
					cur[2] = e.LastAffected
				}
			}
			if cur[0] != "" {
				a.ranges = append(a.ranges, cur)
			}
		}
	}
	var ds struct {
		Good []string `json:"good"`
	}
	if len(v.DatabaseSpecific) > 0 && json.Unmarshal(v.DatabaseSpecific, &ds) == nil {
		a.good = ds.Good
	}
	return a, a.cve != "" && len(a.ranges) > 0
}

// distroPrefix is the OSV ID prefix of the distro's own per-CVE records
// for a host's ecosystem ("Ubuntu:22.04" → "UBUNTU"), or "" when the
// distro has none to look for (rpm distros publish per-update records, so
// whether one covers a CVE can't be looked up by the CVE).
func distroPrefix(osvEcosystem string) string {
	switch {
	case strings.HasPrefix(osvEcosystem, "Ubuntu"):
		return "UBUNTU"
	case strings.HasPrefix(osvEcosystem, "Debian"):
		return "DEBIAN"
	case strings.HasPrefix(osvEcosystem, "Alpine"):
		return "ALPINE"
	}
	return ""
}

// upstreamFindings matches the host's nginx packages against the stored
// nginx.org advisories.
func (e *Engine) upstreamFindings(ctx context.Context, info ecosystem.Info, pkgs []upstreamPackage) ([]store.Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	recs, err := e.Store.UpstreamAdvisories(ctx, nginx.IDPrefix)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	distro := distroPrefix(info.OSV)
	var checked map[[2]string]store.DistroRecord
	var fs []store.Finding
	for _, rec := range recs {
		a, ok := parseUpstream(rec)
		if !ok {
			continue
		}
		for _, p := range pkgs {
			if !a.affects(p.upstream) {
				continue
			}
			fixed := ""
			if p.thirdParty {
				fixed = a.fixFor(p.upstream)
			} else {
				// The distro's own build: only while the distro hasn't
				// published its record of this CVE (checked by sync; a
				// pair never checked counts as published, so a failed
				// check can't flag every old CVE).
				if distro == "" {
					continue
				}
				if checked == nil {
					if checked, err = e.Store.DistroRecords(ctx); err != nil {
						return nil, err
					}
				}
				if r, ok := checked[[2]string{a.cve, distro}]; !ok || r.Found {
					continue
				}
				// A record stored since (a host matched it) settles it too.
				has, err := e.Store.DistroAdvisoryFor(ctx, nginx.IDPrefix, a.cve, ecosystemFamily(info.OSV), "nginx")
				if err != nil {
					return nil, err
				}
				if has {
					continue
				}
			}
			pending := false
			if fixed != "" {
				for _, pv := range p.pending {
					if compare(info.Scheme, pv, fixed) >= 0 {
						pending = true
					}
				}
			}
			fs = append(fs, store.Finding{
				AdvisoryID: a.id, Ecosystem: nginx.Ecosystem, Package: "nginx", Version: p.version,
				Binaries: p.binaries, FixedVersion: fixed, FixPending: pending,
			})
		}
	}
	return fs, nil
}

// ecosystemFamily is an OSV ecosystem's distro name ("Ubuntu:22.04:LTS" →
// "Ubuntu").
func ecosystemFamily(eco string) string {
	name, _, _ := strings.Cut(eco, ":")
	return name
}

// syncUpstream fetches nginx.org's advisories, stores them, withdraws those
// it dropped, and checks which distros have published their own record of
// each CVE (for the distros the fleet runs).
func (s *Syncer) syncUpstream(ctx context.Context) error {
	list, err := nginx.Fetch(ctx, s.HTTP, s.NginxURL)
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
	if n, err := s.Store.WithdrawUpstream(ctx, nginx.IDPrefix, ids, s.Now()); err != nil {
		return err
	} else if n > 0 {
		s.Log.Info("upstream advisories withdrawn", "source", "nginx.org", "count", n)
	}
	return s.checkDistroRecords(ctx, list)
}

// checkDistroRecords looks up, for each advisory and each distro the fleet
// runs, whether the distro's own record exists yet. Found records aren't
// looked up again.
func (s *Syncer) checkDistroRecords(ctx context.Context, list []nginx.Advisory) error {
	distros, err := s.fleetDistros(ctx)
	if err != nil || len(distros) == 0 {
		return err
	}
	known, err := s.Store.DistroRecords(ctx)
	if err != nil {
		return err
	}
	var failed int
	for _, a := range list {
		for _, d := range distros {
			if known[[2]string{a.CVE, d}].Found {
				continue
			}
			found, err := s.Engine.distroRecordExists(ctx, d+"-"+a.CVE)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				failed++
				continue
			}
			if err := s.Store.SetDistroRecord(ctx, a.CVE, d, found, s.Now()); err != nil {
				return err
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("checking distro records: %d lookups failed", failed)
	}
	return nil
}

// fleetDistros are the distro record prefixes of every host's OS.
func (s *Syncer) fleetDistros(ctx context.Context) ([]string, error) {
	hosts, err := s.Store.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		inv, err := s.Store.Inventory(ctx, h)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info, ok := HostEcosystem(inv); ok {
			if d := distroPrefix(info.OSV); d != "" {
				seen[d] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	slices.Sort(out)
	return out, nil
}

// distroRecordExists asks OSV whether a record exists: true on 200, false
// on 404, an error otherwise.
func (e *Engine) distroRecordExists(ctx context.Context, id string) (bool, error) {
	_, _, err := e.OSV.Vuln(ctx, id)
	if err == nil {
		return true, nil
	}
	var se *netx.StatusError
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		return false, nil
	}
	return false, err
}
