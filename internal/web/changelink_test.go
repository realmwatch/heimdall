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
	c.addChangeLinks(&fv, "acme", "web-01", 0)
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
	(ChangeLink{}).addChangeLinks(&off, "acme", "web-01", 3)
	if off.ChangeURL != "" || off.Groups[0].ChangeURL != "" {
		t.Error("links with [change_link] off")
	}
}

// The host page links each package and the fixable findings shown to the
// change-management tool, in a new tab with no referrer.
func TestUpdatesLink(t *testing.T) {
	c := ChangeLink{UpdatesURL: "https://changes.example.com/updates?org={org}&host={host}"}
	if got, want := c.updatesLink("a&b", "web 01", 3), "https://changes.example.com/updates?org=a%26b&host=web+01"; got != want {
		t.Errorf("link %q, want %q", got, want)
	}
	if c.updatesLink("acme", "web-01", 0) != "" {
		t.Error("link with nothing pending")
	}
	if (ChangeLink{}).updatesLink("acme", "web-01", 3) != "" {
		t.Error("link with updates_url off")
	}
	// All updates doesn't depend on findings, or on the findings link being on.
	var fv findingsView
	c.addChangeLinks(&fv, "acme", "web-01", 3)
	if fv.UpdatesCount != 3 || fv.UpdatesURL == "" || fv.ChangeURL != "" {
		t.Errorf("view %q %d %q", fv.UpdatesURL, fv.UpdatesCount, fv.ChangeURL)
	}
}

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
		`href="https://changes.example.com/new?org=acme&amp;host=web-01&amp;pkg=&amp;finding=` + id + `" target="_blank" rel="noopener noreferrer">Install security updates · 1 finding</a>`,
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
