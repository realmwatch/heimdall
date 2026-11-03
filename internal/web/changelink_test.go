// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strconv"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestChangeLink(t *testing.T) {
	c := ChangeLink{URL: "https://changes.example.com/new?org={org}&host={host}&pkg={package}&finding={finding}", Label: "Fix"}
	if got := c.link("acme", "web 01&x", "lib/ssl", []int64{12, 7}); got !=
		"https://changes.example.com/new?org=acme&host=web+01%26x&pkg=lib%2Fssl&finding=12,7" {
		t.Errorf("link %s", got)
	}
	if c.link("acme", "web-01", "", nil) != "" || (ChangeLink{}).link("acme", "web-01", "", []int64{1}) != "" {
		t.Error("a link with nothing to fix, or with the link off")
	}
	many := make([]int64, store.MaxFindingIDs+50)
	for i := range many {
		many[i] = int64(i + 1)
	}
	if n := strings.Count(c.link("acme", "web-01", "", many), ",") + 1; n != store.MaxFindingIDs {
		t.Errorf("%d ids in the link", n)
	}

	list := []report.Finding{
		{ID: 1, Package: "openssl", Version: "1", Fixed: "2", Severity: "high"},
		{ID: 2, Package: "openssl", Version: "1", Severity: "high"}, // no fix yet
		{ID: 3, Package: "bash", Version: "5", Fixed: "5.1", Severity: "low"},
	}
	fv := buildFindingsView("/hosts/acme/web-01", "dpkg", nil, list, nil, kernelInfo{})
	c.addChangeLinks(&fv, "acme", "web-01")
	if fv.ChangeCount != 2 || !strings.HasSuffix(fv.ChangeURL, "finding=1,3") {
		t.Errorf("view link %q (%d)", fv.ChangeURL, fv.ChangeCount)
	}
	for _, g := range fv.Groups {
		want := map[string]string{"openssl": "pkg=openssl&finding=1", "bash": "pkg=bash&finding=3"}[g.Package]
		if !strings.HasSuffix(g.ChangeURL, want) || g.ChangeLabel != "Fix" {
			t.Errorf("%s: %q", g.Package, g.ChangeURL)
		}
	}
	off := buildFindingsView("/hosts/acme/web-01", "dpkg", nil, list, nil, kernelInfo{})
	(ChangeLink{}).addChangeLinks(&off, "acme", "web-01")
	if off.ChangeURL != "" || off.Groups[0].ChangeURL != "" {
		t.Error("links with [change_link] off")
	}
}

// The host page links each package and the fixable findings shown to the
// change-management tool, in a new tab with no referrer.
func TestHostPageChangeLinks(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink = ChangeLink{URL: "https://changes.example.com/new?org={org}&host={host}&pkg={package}&finding={finding}", Label: "Fix"}
	})
	host := e.seed()
	fs, _ := e.st.OpenFindings(t.Context(), host.ID)
	id := strconv.FormatInt(fs[0].ID, 10)
	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{
		`href="https://changes.example.com/new?org=acme&amp;host=web-01&amp;pkg=&amp;finding=` + id + `" target="_blank" rel="noopener noreferrer">Fix 1 finding</a>`,
		`href="https://changes.example.com/new?org=acme&amp;host=web-01&amp;pkg=openssl&amp;finding=` + id + `" target="_blank" rel="noopener noreferrer">Fix openssl</a>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host page missing %s", want)
		}
	}
	plain := newEnv(t, "http://127.0.0.1:8080", nil)
	plain.seed()
	if strings.Contains(plain.get("/hosts/acme/web-01", signedIn(plain)).Body.String(), "change-btn") {
		t.Error("Fix links with [change_link] off")
	}
}
