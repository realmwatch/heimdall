// SPDX-License-Identifier: AGPL-3.0-or-later

package leftovers

import (
	"slices"
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
	UsedBy    []Use         `json:"used_by"`
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
}

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
// offering its version names (from st); else, when no configured source
// offers it at all (or st is nil), the release its version names; else,
// for a package built from the same source as a newer installed package
// with a different upstream version (libssl1.1 beside libssl3), the
// release the host was upgraded from. Only releases older than current
// count.
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
		if r, ok := versionRelease(current.Distro, p); ok && r.Before(current) {
			a.BuiltFor[p.Name] = r
			seen(r)
		}
	}
	twins(a, live, st, newest)

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
			if r, ok := a.BuiltFor[o.Name]; ok {
				l.BuiltFor = r.String()
			} else if r, ok := versionRelease(current.Distro, p); ok && r.Before(current) {
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
// version) names.
func versionRelease(distro string, p Package) (Release, bool) {
	if r, ok := FromVersion(distro, p.Version); ok {
		return r, true
	}
	if p.SourceVersion != "" && p.SourceVersion != p.Version {
		return FromVersion(distro, p.SourceVersion)
	}
	return Release{}, false
}

// twins marks packages built from the same source as a newer installed
// package with another upstream version (libssl1.1 from openssl 1.1.1f
// beside libssl3 from openssl 3.0.2) as built for prev, the release the
// host was upgraded from. Packages a configured source offers don't
// count: a held-back package isn't a leftover.
func twins(a Analysis, pkgs []Package, st *State, prev Release) {
	if prev.IsZero() {
		return
	}
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
		n, v := src(p)
		if t, ok := top[n]; !ok || version.CompareDpkg(v, t) > 0 {
			top[n] = v
		}
	}
	for _, p := range pkgs {
		if _, done := a.BuiltFor[p.Name]; done || (st != nil && !a.Obsolete[p.Name]) {
			continue
		}
		n, v := src(p)
		if t := top[n]; version.CompareDpkg(v, t) < 0 && upstream(v) != upstream(t) {
			a.BuiltFor[p.Name] = prev
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
	if len(f.Obsolete) > 0 {
		out = append(out, "Remove the obsolete packages once nothing loads or depends on them (apt purge; check apt's list "+
			"first, and keep anything installed on purpose from a .deb).")
	}
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
