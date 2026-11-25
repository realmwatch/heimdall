// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestSiteArchive(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
	host := e.seedSites()
	ctx := t.Context()
	const old = "/home/forge/old.example.com"
	if err := e.st.SetHostSiteVhosts(ctx, host.ID, []store.SiteVhost{
		{Root: siteRoot, Vhost: "/etc/nginx/sites-enabled/example.com", Enabled: true},
		{Root: old, Vhost: "/etc/nginx/sites-available/old", Names: []string{"old.example.com"}},
	}); err != nil {
		t.Fatal(err)
	}
	// As rendered: html/template escapes every & in the href.
	enable := "action=site.enable&amp;org=acme&amp;host=app-01&amp;root=" + url.QueryEscape(old) + "&amp;vhost=" + url.QueryEscape("/etc/nginx/sites-available/old")
	disable := "action=site.disable&amp;org=acme&amp;host=app-01&amp;root=" + url.QueryEscape(siteRoot) + "&amp;vhost=" + url.QueryEscape("/etc/nginx/sites-enabled/example.com")
	has := func(path string, want ...string) string {
		t.Helper()
		w := e.get(path, signedIn(e))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		b := w.Body.String()
		for _, s := range want {
			if !strings.Contains(b, s) {
				t.Errorf("%s missing %q", path, s)
			}
		}
		return b
	}
	// A disabled site, not archived: listed with an enable link, on both
	// pages; nothing is archived yet, so no disable link.
	b := has("/sites", "old.example.com", ">disabled<", "Not served, so not checked", "Propose enable", ">Archive<")
	if strings.Contains(b, "action=site.disable") {
		t.Error("disable link before archiving")
	}
	has("/hosts/acme/app-01", "Disabled sites", "old.example.com", "Propose enable")

	csrf := auth.CSRFToken(goodToken)
	archive := func(root, on, back string) *http.Response {
		t.Helper()
		f := url.Values{"csrf": {csrf}, "org": {"acme"}, "host": {"app-01"}, "root": {root}, "archive": {on}, "back": {back}}
		return e.post("/sites/archive", f, signedIn(e), origin(e.baseURL)).Result()
	}
	// Archiving a served site: still listed, flagged, with a disable link.
	if res := archive(siteRoot, "1", "/hosts/acme/app-01#site-0"); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/hosts/acme/app-01?site_archive=archived#site-0" {
		t.Fatalf("archive: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	has("/hosts/acme/app-01?site_archive=archived", "Site archived.", "archived, still served", "Propose disable", ">Unarchive<", disable)
	has("/sites", "archived, still served", "action=site.disable")
	has("/hosts/acme/app-01/site?root="+url.QueryEscape(siteRoot), "archived, still served", "action=site.disable", ">Unarchive<")

	// Archiving a disabled site hides it, behind a toggle.
	if res := archive(old, "1", "/sites"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("archive disabled: %d", res.StatusCode)
	}
	b = has("/sites", "Show archived (1)")
	if strings.Contains(b, "old.example.com") {
		t.Error("archived, disabled site listed by default")
	}
	has("/sites?archived=1", "old.example.com", ">archived<", "Hide archived", enable)
	b = has("/hosts/acme/app-01", "Show archived (1)")
	if strings.Contains(b, "old.example.com") {
		t.Error("host page lists the archived, disabled site by default")
	}
	has("/hosts/acme/app-01?archived=1", "old.example.com", enable)

	// Bringing it back.
	if res := archive(old, "0", "/sites?archived=1"); res.Header.Get("Location") != "/sites?archived=1&site_archive=unarchived" {
		t.Fatalf("unarchive: %s", res.Header.Get("Location"))
	}
	if a, _ := e.st.ArchivedSites(ctx); len(a) != 1 {
		t.Errorf("archived = %v", a)
	}

	// Viewers can't archive, and see no archive button.
	orgs, _ := e.st.ListOrgs(ctx)
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleViewer}}}
	if res := archive(old, "1", "/sites"); res.StatusCode != http.StatusNotFound {
		t.Errorf("viewer archiving: %d", res.StatusCode)
	}
	if b := has("/sites"); strings.Contains(b, "/sites/archive") {
		t.Error("viewer sees the archive form")
	}
}
