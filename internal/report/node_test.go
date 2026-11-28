// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/feeds/eol"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseNodeRange(t *testing.T) {
	cases := []struct {
		in    string
		allow []int
		deny  []int
		major int
	}{
		{"22", []int{22}, []int{20, 24}, 22},
		{"v22.11.0", []int{22}, []int{20}, 22},
		{"22.x", []int{22}, []int{23}, 22},
		{"^20.11", []int{20}, []int{22}, 20},
		{"~18", []int{18}, []int{20}, 18},
		{">=18", []int{18, 24}, []int{16}, 0},
		{">=18 <21", []int{18, 20}, []int{22}, 0},
		{">=18 <21 || ^22", []int{20, 22}, []int{24}, 0},
		{"<20.5.0", []int{18, 20}, []int{22}, 0},
		{"<20", []int{18}, []int{20}, 0},
		{">20", []int{22}, []int{20}, 0},
		{">20.1", []int{20, 22}, []int{18}, 0},
		{"18 - 20", []int{18, 20}, []int{22}, 0},
		{"*", []int{18, 24}, nil, 0},
	}
	for _, c := range cases {
		r, ok := ParseNodeRange(c.in)
		if !ok {
			t.Errorf("%q: not parsed", c.in)
			continue
		}
		for _, m := range c.allow {
			if !r.Allows(m) {
				t.Errorf("%q should allow %d", c.in, m)
			}
		}
		for _, m := range c.deny {
			if r.Allows(m) {
				t.Errorf("%q shouldn't allow %d", c.in, m)
			}
		}
		if r.Major() != c.major {
			t.Errorf("%q: major %d, want %d", c.in, r.Major(), c.major)
		}
	}
	for _, bad := range []string{"", "lts/*", "lts/iron", "node", "iron", "^abc", "0", ">=x"} {
		if _, ok := ParseNodeRange(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestNodeRuntimes(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	eol22, eol20 := now.AddDate(1, 5, 0), now.AddDate(0, -7, 0)
	cs := []eol.Cycle{
		{Product: "nodejs", Cycle: "22", EOL: &eol22, Latest: "22.12.0"},
		{Product: "nodejs", Cycle: "20", EOL: &eol20, Latest: "20.19.6"},
	}
	cycles := func(string) ([]eol.Cycle, error) { return cs, nil }
	lifecycle := func(product, cycle string) (*Lifecycle, error) {
		s := eol.Evaluate(cs, cycle, now)
		return &Lifecycle{Product: product, Cycle: cycle, Known: s.Known, EOL: s.EOL, EOLDate: s.EOLDate}, nil
	}
	nvm := "/home/acme/.nvm/versions/node/v20.11.0/bin/node"
	host := Host{
		Runtimes: []Runtime{{Name: "nodejs", Version: "20.19.6", Package: "nodejs"}},
		Sites:    []Site{{Root: "/srv/app"}, {Root: "/srv/legacy"}, {Root: "/srv/build"}, {Root: "/srv/old"}, {Root: "/srv/other"}},
	}
	n := store.HostNode{
		Bins: []store.NodeBin{
			{Path: "/usr/bin/node", Running: false},
			{Path: "/opt/node/22/bin/node", Version: "22.11.0", Running: true},
			{Path: nvm, Version: "20.11.0", Running: true},
			{Path: "/usr/local/bin/node"},
		},
		Sites: map[string]store.NodeSite{
			"/srv/app":    {Bin: "/opt/node/22/bin/node", Requirement: "22"},
			"/srv/legacy": {Bin: nvm},
			"/srv/build":  {Requirement: ">=18 <21"},
			"/srv/old":    {Requirement: "16"},
			"/srv/other":  {Requirement: "lts/*"},
		},
	}
	if err := nodeRuntimes(&host, n, lifecycle, cycles); err != nil {
		t.Fatal(err)
	}
	if len(host.Runtimes) != 4 {
		t.Fatalf("runtimes: %+v", host.Runtimes)
	}
	apt, opt, nv, other := host.Runtimes[0], host.Runtimes[1], host.Runtimes[2], host.Runtimes[3]
	if apt.Kind != "apt" || apt.Path != "/usr/bin/node" || apt.Running || len(apt.Sites) != 0 || apt.Latest != "" {
		t.Errorf("apt: %+v", apt)
	}
	if opt.Kind != "opt" || !opt.Running || len(opt.Sites) != 1 || opt.Sites[0] != "/srv/app" ||
		opt.Status != "outdated" || opt.Latest != "22.12.0" || opt.Life == nil || opt.Life.EOL {
		t.Errorf("opt: %+v", opt)
	}
	if nv.Kind != "nvm" || nv.Life == nil || !nv.Life.EOL || nv.Sites[0] != "/srv/legacy" {
		t.Errorf("nvm: %+v", nv)
	}
	if other.Kind != "other" || other.Version != "unknown" || other.Life != nil {
		t.Errorf("other: %+v", other)
	}
	met := func(i int) string {
		s := host.Sites[i]
		if s.NodeSatisfied == nil {
			return "?"
		}
		if *s.NodeSatisfied {
			return "yes"
		}
		return "no"
	}
	if s := host.Sites[0]; s.NodeVersion != "22.11.0" || met(0) != "yes" || s.NodeWant != "22" {
		t.Errorf("app: %+v", s)
	}
	if s := host.Sites[1]; s.NodeVersion != "20.11.0" || met(1) != "?" {
		t.Errorf("legacy: %+v", s)
	}
	if s := host.Sites[2]; s.NodeBin != "" || met(2) != "yes" || s.NodeWant != "" {
		t.Errorf("build: %+v", s)
	}
	if s := host.Sites[3]; met(3) != "no" || s.NodeWant != "16" {
		t.Errorf("old: %+v", s)
	}
	if met(4) != "?" {
		t.Errorf("lts/*: %+v", host.Sites[4])
	}
}
