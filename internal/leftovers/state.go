// SPDX-License-Identifier: AGPL-3.0-or-later

package leftovers

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Header carries a host's apt state, from collectors 0.5.26 on:
//
//	X-Heimdall-Release: v1 cn=jammy maps=40/120;u=sources.list.distUpgrade;
//	  s=sources.list.d/pgdg.list|http://apt.postgresql.org/pub/repos/apt|focal-pgdg|main;
//	  o=libssl1.1|1.1.1f-1ubuntu2.24+esm6;b=libpq5|17.5-1.pgdg20.04+1|focal-pgdg;
//	  p=812|php8.3-fpm.service|php-fpm8.3|libssl.so.1.1|libssl1.1
//
// u is a file the release upgrader left, s an enabled apt source (one per
// suite), o an installed package no configured source has, b one only
// suites naming another release offer, and p a process mapping a library
// an o or b package ships. maps is how many processes the collector could
// read of those running: it isn't root, so usually not all. A header, not
// a snapshot field, for the same reason as the others: hubs and collectors
// of different versions still accept each other.
const Header = "X-Heimdall-Release"

// MaxHeader caps the header's length; the collector sends at most 8000.
const MaxHeader = 9000

// State is what a host's collector reported (stored as JSON).
type State struct {
	Codename     string   `json:"codename"`
	MapsRead     int      `json:"maps_read"`
	MapsTotal    int      `json:"maps_total"`
	UpgradeFiles []string `json:"upgrade_files"`
	Sources      []Source `json:"sources"`
	Obsolete     []Pkg    `json:"obsolete"`
	Origins      []Origin `json:"origins"`
	Uses         []Use    `json:"uses"`
}

// Source is an enabled apt source entry for one suite.
type Source struct {
	File       string `json:"file"` // relative to /etc/apt
	URI        string `json:"uri"`
	Suite      string `json:"suite"`
	Components string `json:"components"`
}

// Pkg is an installed package.
type Pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Origin is an installed package and the suites that offer its version.
type Origin struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Suites  []string `json:"suites"`
}

// Use is a running process that maps a leftover package's library.
type Use struct {
	PID     int    `json:"pid"`
	Unit    string `json:"unit,omitempty"` // its systemd unit, when it has one
	Command string `json:"command,omitempty"`
	Library string `json:"library"`
	Package string `json:"package"`
}

var (
	codenameTokRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)
	fileRe        = regexp.MustCompile(`^[A-Za-z0-9._+@-][A-Za-z0-9._+@/-]{0,199}$`)
	uriRe         = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/+@=,%-]{1,300}$`)
	suiteRe       = regexp.MustCompile(`^[A-Za-z0-9._~/+-]{1,64}$`)
	compsRe       = regexp.MustCompile(`^[A-Za-z0-9._,/+-]{0,200}$`)
	pkgRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,199}$`)
	verRe         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:-]{0,127}$`)
	unitRe        = regexp.MustCompile(`^[A-Za-z0-9:._@+-]{1,200}$`)
	commRe        = regexp.MustCompile(`^[A-Za-z0-9 ._:@/+-]{1,64}$`)
	libRe         = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,200}$`)
	mapsRe        = regexp.MustCompile(`^maps=([0-9]{1,7})/([0-9]{1,7})$`)
)

// Bounds on what one header may carry.
const (
	maxFiles   = 10
	maxSources = 60
	maxPkgs    = 300
	maxUses    = 40
)

// Parse reads a Header value. The header is untrusted input from the host,
// and the collector cuts it at 8000 characters, so a record that's
// malformed (or cut short) is skipped; only a bad first record fails.
func Parse(v string) (State, error) {
	var st State
	if len(v) > MaxHeader {
		return st, fmt.Errorf("%s is too long", Header)
	}
	recs := strings.Split(v, ";")
	head := strings.Fields(recs[0])
	if len(head) != 3 || head[0] != "v1" {
		return st, errors.New("not a v1 " + Header + " value")
	}
	cn, ok := strings.CutPrefix(head[1], "cn=")
	m := mapsRe.FindStringSubmatch(head[2])
	if !ok || !codenameTokRe.MatchString(cn) || m == nil {
		return st, errors.New("malformed " + Header + " value")
	}
	st.Codename = cn
	st.MapsRead, _ = strconv.Atoi(m[1])
	st.MapsTotal, _ = strconv.Atoi(m[2])
	if st.MapsRead > st.MapsTotal {
		return st, errors.New("malformed " + Header + " value")
	}
	st.UpgradeFiles, st.Sources, st.Obsolete, st.Origins, st.Uses = []string{}, []Source{}, []Pkg{}, []Origin{}, []Use{}
	for _, rec := range recs[1:] {
		kind, body, ok := strings.Cut(strings.TrimSpace(rec), "=")
		if !ok {
			continue
		}
		f := strings.Split(body, "|")
		switch {
		case kind == "u" && len(f) == 1 && fileRe.MatchString(f[0]) && len(st.UpgradeFiles) < maxFiles:
			st.UpgradeFiles = append(st.UpgradeFiles, f[0])
		case kind == "s" && len(f) == 4 && len(st.Sources) < maxSources && fileRe.MatchString(f[0]) &&
			uriRe.MatchString(f[1]) && suiteRe.MatchString(f[2]) && compsRe.MatchString(f[3]):
			st.Sources = append(st.Sources, Source{File: f[0], URI: f[1], Suite: f[2], Components: f[3]})
		case kind == "o" && len(f) == 2 && len(st.Obsolete) < maxPkgs && pkgRe.MatchString(f[0]) && verRe.MatchString(f[1]):
			st.Obsolete = append(st.Obsolete, Pkg{Name: f[0], Version: f[1]})
		case kind == "b" && len(f) == 3 && len(st.Origins) < maxPkgs && pkgRe.MatchString(f[0]) && verRe.MatchString(f[1]):
			o := Origin{Name: f[0], Version: f[1], Suites: []string{}}
			for s := range strings.SplitSeq(f[2], ",") {
				if suiteRe.MatchString(s) && len(o.Suites) < 16 {
					o.Suites = append(o.Suites, s)
				}
			}
			if len(o.Suites) > 0 {
				st.Origins = append(st.Origins, o)
			}
		case kind == "p" && len(f) == 5 && len(st.Uses) < maxUses:
			pid, err := strconv.Atoi(f[0])
			if err != nil || pid <= 0 || pid > 1<<22 || (f[1] != "" && !unitRe.MatchString(f[1])) ||
				(f[2] != "" && !commRe.MatchString(f[2])) || !libRe.MatchString(f[3]) || !pkgRe.MatchString(f[4]) {
				continue
			}
			st.Uses = append(st.Uses, Use{PID: pid, Unit: f[1], Command: strings.TrimSpace(f[2]), Library: f[3], Package: f[4]})
		}
	}
	return st, nil
}
