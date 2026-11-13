// SPDX-License-Identifier: AGPL-3.0-or-later

// Package leftovers finds what an in-place release upgrade (Ubuntu's
// do-release-upgrade, Debian's dist-upgrade to a new codename) left
// behind: apt sources still naming the old release, packages no
// configured source has any more, and packages still built for the old
// release. It also tells the findings engine which release each installed
// package was built for, so a leftover is judged against that release's
// advisories and never offered another package's fixed version.
package leftovers

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Release is an Ubuntu or Debian release.
type Release struct {
	Distro   string // "ubuntu" or "debian"
	Version  string // "20.04", "11"
	Codename string // "focal", "bullseye"
}

// releases are the ones Heimdall knows, oldest first within each distro.
var releases = []Release{
	{"debian", "8", "jessie"}, {"debian", "9", "stretch"}, {"debian", "10", "buster"},
	{"debian", "11", "bullseye"}, {"debian", "12", "bookworm"}, {"debian", "13", "trixie"},
	{"debian", "14", "forky"}, {"debian", "15", "duke"},
	{"ubuntu", "14.04", "trusty"}, {"ubuntu", "14.10", "utopic"}, {"ubuntu", "15.04", "vivid"},
	{"ubuntu", "15.10", "wily"}, {"ubuntu", "16.04", "xenial"}, {"ubuntu", "16.10", "yakkety"},
	{"ubuntu", "17.04", "zesty"}, {"ubuntu", "17.10", "artful"}, {"ubuntu", "18.04", "bionic"},
	{"ubuntu", "18.10", "cosmic"}, {"ubuntu", "19.04", "disco"}, {"ubuntu", "19.10", "eoan"},
	{"ubuntu", "20.04", "focal"}, {"ubuntu", "20.10", "groovy"}, {"ubuntu", "21.04", "hirsute"},
	{"ubuntu", "21.10", "impish"}, {"ubuntu", "22.04", "jammy"}, {"ubuntu", "22.10", "kinetic"},
	{"ubuntu", "23.04", "lunar"}, {"ubuntu", "23.10", "mantic"}, {"ubuntu", "24.04", "noble"},
	{"ubuntu", "24.10", "oracular"}, {"ubuntu", "25.04", "plucky"}, {"ubuntu", "25.10", "questing"},
	{"ubuntu", "26.04", "resolute"}, {"ubuntu", "26.10", "stonking"},
}

// IsZero reports whether r is no release.
func (r Release) IsZero() bool { return r.Distro == "" }

// String names r for people: "Ubuntu 20.04 (focal)".
func (r Release) String() string {
	if r.IsZero() {
		return ""
	}
	name := "Ubuntu"
	if r.Distro == "debian" {
		name = "Debian"
	}
	return name + " " + r.Version + " (" + r.Codename + ")"
}

// OSV is r's OSV ecosystem, as the findings engine queries it.
func (r Release) OSV() string {
	switch r.Distro {
	case "ubuntu":
		return "Ubuntu:" + r.Version
	case "debian":
		return "Debian:" + r.Version
	}
	return ""
}

// Before reports whether r is an older release of the same distro as o.
func (r Release) Before(o Release) bool {
	return r.Distro == o.Distro && !r.IsZero() && rank(r) < rank(o)
}

func rank(r Release) int {
	return slices.IndexFunc(releases, func(x Release) bool { return x == r })
}

// ByCodename finds a release by codename.
func ByCodename(codename string) (Release, bool) {
	i := slices.IndexFunc(releases, func(x Release) bool { return x.Codename == codename })
	if i < 0 {
		return Release{}, false
	}
	return releases[i], true
}

func byVersion(distro, v string) (Release, bool) {
	i := slices.IndexFunc(releases, func(x Release) bool { return x.Distro == distro && x.Version == v })
	if i < 0 {
		return Release{}, false
	}
	return releases[i], true
}

// FromOSV is the release an OSV ecosystem names ("Ubuntu:22.04",
// "Debian:12"), if Heimdall knows it.
func FromOSV(eco string) (Release, bool) {
	name, v, ok := strings.Cut(eco, ":")
	if !ok {
		return Release{}, false
	}
	return byVersion(strings.ToLower(name), v)
}

// previous is the release before r, if Heimdall knows it.
func previous(r Release) (Release, bool) {
	i := rank(r)
	if i <= 0 || releases[i-1].Distro != r.Distro {
		return Release{}, false
	}
	return releases[i-1], true
}

var (
	// Ubuntu: an SRU (1ubuntu0.20.04.3), a no-change rebuild
	// (build0.22.04.1), a backport (~20.04.1), and third-party builds
	// (+ubuntu20.04.1+deb.sury.org, ~ubuntu.22.04~jammy, pgdg20.04+1).
	ubuntuVersionRes = []*regexp.Regexp{
		regexp.MustCompile(`ubuntu0\.([0-9]{2}\.[0-9]{2})`),
		regexp.MustCompile(`build0\.([0-9]{2}\.[0-9]{2})`),
		regexp.MustCompile(`[~+]ubuntu\.?([0-9]{2}\.[0-9]{2})`),
		regexp.MustCompile(`~([0-9]{2}\.[0-9]{2})(?:\.[0-9]+)*(?:[^0-9.]|$)`),
		regexp.MustCompile(`pgdg([0-9]{2}\.[0-9]{2})`),
	}
	// Debian: a stable update (+deb11u3), a backport (~bpo11+1) and
	// third-party builds (pgdg110+1, +debian11).
	debianVersionRes = []*regexp.Regexp{
		regexp.MustCompile(`[+~]deb([0-9]{1,2})u[0-9]`),
		regexp.MustCompile(`~bpo([0-9]{1,2})\+`),
		regexp.MustCompile(`pgdg([0-9]{1,2})0(?:\+|$)`),
		regexp.MustCompile(`\+debian([0-9]{1,2})(?:[^0-9]|$)`),
	}
	codenameRe = regexp.MustCompile(`[a-z]+`)
)

// FromVersion is the release of distro a package version names, if any:
// the one named last (the outermost change) when it names several. A
// version that names a codename (~focal1) counts too.
func FromVersion(distro, v string) (Release, bool) {
	res := ubuntuVersionRes
	if distro == "debian" {
		res = debianVersionRes
	}
	best, at := Release{}, -1
	for _, re := range res {
		for _, m := range re.FindAllStringSubmatchIndex(v, -1) {
			if r, ok := byVersion(distro, v[m[2]:m[3]]); ok && m[2] > at {
				best, at = r, m[2]
			}
		}
	}
	for _, m := range codenameRe.FindAllStringIndex(v, -1) {
		if r, ok := ByCodename(v[m[0]:m[1]]); ok && r.Distro == distro && m[0] > at {
			best, at = r, m[0]
		}
	}
	return best, at >= 0
}

// FromSuite is the release of current's distro an apt suite names
// ("focal-pgdg", "focal-infra-security", "bullseye-backports"), or for
// Debian's "oldstable", the one before current.
func FromSuite(suite string, current Release) (Release, bool) {
	for _, tok := range strings.FieldsFunc(suite, func(r rune) bool { return r == '-' || r == '_' || r == '/' }) {
		if r, ok := ByCodename(tok); ok && r.Distro == current.Distro {
			return r, true
		}
		if tok == "oldstable" && current.Distro == "debian" {
			return previous(current)
		}
	}
	return Release{}, false
}

// suiteFor rewrites a suite naming old to name current instead
// ("focal-pgdg" for jammy is "jammy-pgdg"; "oldstable" is "stable").
func suiteFor(suite string, old, current Release) string {
	parts := strings.FieldsFunc(suite, func(r rune) bool { return r == '-' || r == '_' || r == '/' })
	for _, p := range parts {
		if p == old.Codename {
			return replaceToken(suite, old.Codename, current.Codename)
		}
	}
	if strings.Contains(suite, "oldstable") {
		return strings.Replace(suite, "oldstable", "stable", 1)
	}
	return suite
}

// replaceToken replaces whole tokens (between - _ / or the ends) only.
func replaceToken(s, old, repl string) string {
	var b strings.Builder
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '-' || s[i] == '_' || s[i] == '/' {
			if s[start:i] == old {
				b.WriteString(repl)
			} else {
				b.WriteString(s[start:i])
			}
			if i < len(s) {
				b.WriteByte(s[i])
			}
			start = i + 1
		}
	}
	return b.String()
}

// upstream is a Debian version's upstream part: no epoch, no revision.
func upstream(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if _, err := strconv.Atoi(v[:i]); err == nil {
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return v
}
