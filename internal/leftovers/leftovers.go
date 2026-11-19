// SPDX-License-Identifier: AGPL-3.0-or-later

package leftovers

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/version"
)

// Kind is the finding's kind, as the MCP host data names it.
const Kind = "release_leftovers"

// Package is an installed dpkg package, as the snapshot reports it.
type Package struct {
	Name, Version, SourceName, SourceVersion string
}

// Finding is one host's release leftovers: what's left from an older
// release, and what still loads it.
type Finding struct {
	Kind     string `json:"kind"`     // Kind
	Severity string `json:"severity"` // medium when a running process loads a leftover library, else low
	Release  string `json:"release"`  // the host's release, "Ubuntu 22.04 (jammy)"
	Codename string `json:"codename"`
	// Previous is the older release the leftovers are from, when known.
	Previous  string        `json:"previous_release,omitempty"`
	Sources   []StaleSource `json:"sources"`
	Obsolete  []Leftover    `json:"obsolete"`   // no configured source has them
	OldBuilds []Leftover    `json:"old_builds"` // still built for an older release
	// Vendor are packages no apt source has that look installed on purpose
	// from a vendor's .deb (OnPurpose): not leftovers, so the cleanup
	// leaves them alone.
	Vendor []Leftover `json:"vendor_debs,omitempty"`
	UsedBy []Use      `json:"used_by"`
	// UsageScan is how much of the host the collector could look at for
	// UsedBy: "full", "partial" (it isn't root, so it can't read every
	// process), "none" or "not_reported" (an older collector).
	UsageScan    string   `json:"usage_scan"`
	UpgradeFiles []string `json:"upgrade_files,omitempty"`
	Remediation  []string `json:"remediation"`
}

// StaleSource is an apt source naming an older release.
type StaleSource struct {
	File       string `json:"file"`
	URI        string `json:"uri"`
	Suite      string `json:"suite"`
	Release    string `json:"release"`       // the release Suite names
	Current    string `json:"current_suite"` // the suite naming the host's release instead
	Components string `json:"components,omitempty"`
}

// Leftover is a package left from an older release.
type Leftover struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	BuiltFor string `json:"built_for,omitempty"` // "" when it can't be told
	// Offered are the (old-release) suites that still offer it.
	Offered []string `json:"offered_by,omitempty"`
	// For an obsolete package: what to do with it (Plan*), why, and the
	// installed packages that need it (when the collector said).
	Plan     string   `json:"plan,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	NeededBy []string `json:"needed_by,omitempty"`
}

// What to do with an obsolete package.
const (
	PlanReplace = "replace" // the host's sources have a build of its name: install it in its place
	PlanRemove  = "remove"  // nothing installed needs it and nothing running loads it
	PlanReview  = "review"  // something needs or loads it, or the collector didn't say
)

// Analysis is what Analyze found.
type Analysis struct {
	Current Release
	// BuiltFor maps each binary package built for an older release to
	// it: its advisories come from that release, and no fix applies.
	BuiltFor map[string]Release
	// Obsolete are the binary packages no configured source has: nothing
	// can upgrade them.
	Obsolete map[string]bool
	Finding  *Finding // nil when nothing is left over
}

// Leftover reports whether a binary package is left from an older
// release or can't be upgraded at all.
func (a Analysis) Leftover(name string) bool {
	_, old := a.BuiltFor[name]
	return old || a.Obsolete[name]
}

// kernelSource: kernels have their own removal (internal/kernel).
func kernelSource(p Package) bool {
	src := p.SourceName
	if src == "" {
		src = p.Name
	}
	return strings.HasPrefix(src, "linux")
}

// Analyze looks at a dpkg host's packages and what its collector said
// (st is nil for a collector too old to send the Header). current is the
// host's release.
//
// A package's release is, in order: the old release a configured suite
// offering its version names (from st). Else, when no configured source
// offers it at all (or st is nil), the release its version names; without
// st, only a third-party builder's marker counts on its own (see
// versionPattern). Else, for a package built from the same source as a
// newer installed package with another upstream version (libssl1.1 beside
// libssl3), the release its version names, or the one the host was
// upgraded from. A version naming current always means current. Only
// releases older than current count.
func Analyze(current Release, pkgs []Package, st *State) Analysis {
	a := Analysis{Current: current, BuiltFor: map[string]Release{}, Obsolete: map[string]bool{}}
	if current.IsZero() {
		return a
	}
	origins := map[string]Origin{}
	if st != nil {
		for _, o := range st.Origins {
			origins[o.Name] = o
		}
		for _, o := range st.Obsolete {
			if vendorDeb(o) {
				continue // not a leftover: apt was never meant to upgrade it
			}
			a.Obsolete[o.Name] = true
		}
	}
	var stale []StaleSource
	newest := Release{} // the newest older release seen: the one upgraded from
	seen := func(r Release) {
		if r.Before(current) && (newest.IsZero() || newest.Before(r)) {
			newest = r
		}
	}
	if st != nil {
		for _, s := range st.Sources {
			if r, ok := FromSuite(s.Suite, current); ok && r.Before(current) {
				stale = append(stale, StaleSource{File: s.File, URI: s.URI, Suite: s.Suite, Release: r.String(),
					Current: suiteFor(s.Suite, r, current), Components: s.Components})
				seen(r)
			}
		}
	}

	var live []Package
	for _, p := range pkgs {
		if !kernelSource(p) {
			live = append(live, p)
		}
	}
	weak := map[string]Release{} // an Ubuntu-archive marker only: needs a twin to count
	candidates := map[string]bool{}
	for _, p := range live {
		if o, ok := origins[p.Name]; ok && o.Version == p.Version {
			if r, ok := oldestOffer(o.Suites, current); ok {
				a.BuiltFor[p.Name] = r
				seen(r)
			}
			continue
		}
		if st != nil && !a.Obsolete[p.Name] {
			continue // a configured source for this release offers it
		}
		r, strong, ok := versionRelease(current.Distro, p)
		switch {
		case ok && !r.Before(current):
			// built for this release (or a newer one)
		case ok && (strong || st != nil):
			a.BuiltFor[p.Name] = r
			seen(r)
		case ok:
			weak[p.Name] = r
			candidates[p.Name] = true
		default:
			candidates[p.Name] = true
		}
	}
	twins(a, live, candidates, weak, seen, func() Release { return newest })

	if st == nil && len(a.BuiltFor) == 0 {
		return a
	}
	f := &Finding{Kind: Kind, Release: current.String(), Codename: current.Codename, Previous: newest.String(),
		Sources: nonNil(stale), Obsolete: []Leftover{}, OldBuilds: []Leftover{}, UsedBy: []Use{}, UsageScan: "not_reported"}
	left := map[string]bool{}
	byName := map[string]Package{}
	for _, p := range live {
		byName[p.Name] = p
	}
	if st != nil {
		f.UpgradeFiles = st.UpgradeFiles
		for _, o := range st.Obsolete {
			p, ok := byName[o.Name]
			if !ok {
				continue // a kernel, or not in the snapshot
			}
			l := Leftover{Name: o.Name, Version: o.Version}
			if vendorDeb(o) {
				f.Vendor = append(f.Vendor, l)
				continue
			}
			if r, ok := a.BuiltFor[o.Name]; ok {
				l.BuiltFor = r.String()
			} else if r, _, ok := versionRelease(current.Distro, p); ok && r.Before(current) {
				l.BuiltFor = r.String()
			}
			f.Obsolete = append(f.Obsolete, l)
			left[o.Name] = true
		}
		switch {
		case st.MapsTotal == 0:
			f.UsageScan = "none"
		case st.MapsRead == st.MapsTotal:
			f.UsageScan = "full"
		default:
			f.UsageScan = "partial"
		}
	}
	for _, p := range live {
		r, ok := a.BuiltFor[p.Name]
		if !ok || a.Obsolete[p.Name] {
			continue
		}
		l := Leftover{Name: p.Name, Version: p.Version, BuiltFor: r.String()}
		if o, ok := origins[p.Name]; ok {
			l.Offered = o.Suites
		}
		f.OldBuilds = append(f.OldBuilds, l)
		left[p.Name] = true
	}
	// Obsolete packages alone may be .debs installed by hand: they count
	// only with signs of a release upgrade.
	evidence := len(stale) > 0 || len(f.OldBuilds) > 0 || len(f.UpgradeFiles) > 0 || !newest.IsZero() ||
		slices.ContainsFunc(f.Obsolete, func(l Leftover) bool { return l.BuiltFor != "" })
	if !evidence || (len(stale) == 0 && len(f.Obsolete) == 0 && len(f.OldBuilds) == 0) {
		return a
	}
	if st != nil {
		for _, u := range st.Uses {
			if left[u.Package] {
				f.UsedBy = append(f.UsedBy, u)
			}
		}
	}
	if st != nil {
		planObsolete(f, st)
	}
	f.Severity = "low"
	if len(f.UsedBy) > 0 {
		f.Severity = "medium"
	}
	f.Remediation = remediation(f)
	a.Finding = f
	return a
}

// oldestOffer is the release the suites offering a package name, when
// it's older than current (the oldest, if several do).
func oldestOffer(suites []string, current Release) (Release, bool) {
	var best Release
	for _, s := range suites {
		if r, ok := FromSuite(s, current); ok && r.Before(current) && (best.IsZero() || r.Before(best)) {
			best = r
		}
	}
	return best, !best.IsZero()
}

// versionRelease is the release a package's version (or its source
// version) names, and whether a strong pattern named it.
func versionRelease(distro string, p Package) (Release, bool, bool) {
	if r, strong, ok := fromVersion(distro, p.Version); ok {
		return r, strong, true
	}
	if p.SourceVersion != "" && p.SourceVersion != p.Version {
		return fromVersion(distro, p.SourceVersion)
	}
	return Release{}, false, false
}

// twins marks candidates (packages no configured source offers, or every
// package without collector state, whose version doesn't name the
// current release) built from the same source as a newer installed
// package with another upstream version, such as libssl1.1 (openssl
// 1.1.1f) beside libssl3 (3.0.2). The newer one mustn't itself be built
// for an older release: jammy's postgresql-client 14+238 beside a stale
// source's postgresql-common 278.pgdg20.04+1 is current. A twin is built
// for the release its version names (weak), else for the one the host
// was upgraded from (prev, once the others are counted). A held-back
// package has the same upstream version, so it isn't one.
func twins(a Analysis, pkgs []Package, candidates map[string]bool, weak map[string]Release, seen func(Release), prev func() Release) {
	top := map[string]string{}
	src := func(p Package) (string, string) {
		name, ver := p.SourceName, p.SourceVersion
		if name == "" {
			name = p.Name
		}
		if ver == "" {
			ver = p.Version
		}
		return name, ver
	}
	for _, p := range pkgs {
		if _, old := a.BuiltFor[p.Name]; old {
			continue // a newer leftover (a stale source's build) isn't the current one
		}
		n, v := src(p)
		if t, ok := top[n]; !ok || version.CompareDpkg(v, t) > 0 {
			top[n] = v
		}
	}
	var unnamed []string
	for _, p := range pkgs {
		if !candidates[p.Name] {
			continue
		}
		n, v := src(p)
		if t, ok := top[n]; !ok || version.CompareDpkg(v, t) >= 0 || upstream(v) == upstream(t) {
			continue
		}
		if r, ok := weak[p.Name]; ok {
			a.BuiltFor[p.Name] = r
			seen(r)
		} else {
			unnamed = append(unnamed, p.Name)
		}
	}
	if r := prev(); !r.IsZero() {
		for _, name := range unnamed {
			a.BuiltFor[name] = r
		}
	}
}

// remediation is what to do, in order.
func remediation(f *Finding) []string {
	var out []string
	if len(f.Sources) > 0 {
		out = append(out, "Retarget or disable each apt source that names an older release: point it at the suite for "+
			f.Codename+" when the repository publishes one, otherwise disable it; then run apt update.")
	}
	if len(f.OldBuilds) > 0 {
		out = append(out, "Reinstall the packages still built for an older release from "+f.Codename+
			"'s sources (apt install --reinstall, or the matching "+f.Codename+" package), so they get "+f.Codename+"'s security fixes.")
	}
	if len(f.UsedBy) > 0 || f.UsageScan != "full" {
		out = append(out, "Restart the services that load a leftover library, so they map the current release's copy.")
	}
	byPlan := map[string][]string{}
	for _, l := range f.Obsolete {
		byPlan[l.Plan] = append(byPlan[l.Plan], l.Name)
	}
	if names := byPlan[PlanReplace]; len(names) > 0 {
		out = append(out, "Install "+f.Codename+"'s build of "+strings.Join(names, ", ")+" in place of the old one "+
			"(apt install --allow-downgrades <package>=<the version apt-cache policy offers>): what needs them keeps working.")
	}
	if names := byPlan[PlanRemove]; len(names) > 0 {
		out = append(out, "Remove "+strings.Join(names, ", ")+": nothing installed needs them (apt purge; check that apt removes nothing else).")
	}
	if names := byPlan[PlanReview]; len(names) > 0 {
		out = append(out, "Leave "+strings.Join(names, ", ")+" until what needs or loads them is replaced or removed, then remove them.")
	}
	if names := byPlan[""]; len(names) > 0 {
		out = append(out, "Remove the obsolete packages once nothing loads or depends on them (apt purge; check apt's list "+
			"first, and keep anything installed on purpose from a .deb).")
	}
	return out
}

// planObsolete decides what to do with each obsolete package, from what
// the collector said (Pkg.Deps): replace one the
// host's sources have a build of, remove one nothing needs, and leave
// for review one something else needs or loads (a vendor's .deb among
// them). A package needed only by others being removed goes with them.
func planObsolete(f *Finding, st *State) {
	info := map[string]Pkg{}
	for _, p := range st.Obsolete {
		info[p.Name] = p
	}
	loaded := map[string]string{}
	for _, u := range f.UsedBy {
		if _, ok := loaded[u.Package]; !ok {
			loaded[u.Package] = cmp.Or(u.Unit, u.Command)
		}
	}
	removable := map[string]bool{}
	for i := range f.Obsolete {
		l := &f.Obsolete[i]
		p := info[l.Name]
		l.NeededBy = p.NeededBy
		switch {
		case !p.Deps:
			l.Plan, l.Reason = "", "" // an older collector: what needs it isn't known
		case p.Offered:
			l.Plan, l.Reason = PlanReplace, f.Codename+"'s sources have a build of it: install that in its place"
		case loaded[l.Name] != "":
			l.Plan, l.Reason = PlanReview, "loaded by "+loaded[l.Name]
		default:
			removable[l.Name] = true
		}
	}
	// Removable once everything needing it is removed too.
	for changed := true; changed; {
		changed = false
		for name := range removable {
			p := info[name]
			if p.More > 0 || slices.ContainsFunc(p.NeededBy, func(n string) bool { return !removable[n] }) {
				delete(removable, name)
				changed = true
			}
		}
	}
	for i := range f.Obsolete {
		l := &f.Obsolete[i]
		p := info[l.Name]
		if l.Plan != "" || !p.Deps || p.Offered || loaded[l.Name] != "" {
			continue
		}
		if removable[l.Name] {
			l.Plan, l.Reason = PlanRemove, "nothing installed needs it"
			if len(p.NeededBy) > 0 {
				l.Reason = "needed only by " + strings.Join(p.NeededBy, ", ") + ", removed too"
			}
			continue
		}
		names := p.NeededBy
		if p.More > 0 {
			names = append(slices.Clone(names), strconv.Itoa(p.More)+" more")
		}
		l.Plan, l.Reason = PlanReview, "needed by "+strings.Join(names, ", ")
	}
}

// vendorDeb reports whether an obsolete package is a vendor's own .deb.
func vendorDeb(o Pkg) bool { return !o.Offered && OnPurpose(o.Version) }

// OnPurpose reports whether a version looks like a vendor's own .deb
// (acme-edr 7.2.0.1234, acme-scanner 4.1.0) rather than a distro's or a
// packager's build: no Debian revision and no distro or builder marker.
// A .deb nothing offers with such a version wasn't left by an upgrade.
func OnPurpose(v string) bool {
	if _, after, ok := strings.Cut(v, ":"); ok {
		v = after // an epoch
	}
	if v == "" || strings.Contains(v, "-") {
		return false
	}
	lv := strings.ToLower(v)
	for _, m := range []string{"ubuntu", "deb", "dfsg", "esm", "pgdg", "sury", "build", "focal", "jammy", "noble", "bionic", "xenial", "bookworm", "bullseye", "buster", "trixie"} {
		if strings.Contains(lv, m) {
			return false
		}
	}
	return lv[0] >= '0' && lv[0] <= '9'
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
