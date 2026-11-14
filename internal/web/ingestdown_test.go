// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// A confirmed fleet-quiet episode shows on every page, to those who can
// see the org; a pending or clearing one doesn't.
func TestIngestDownBanner(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	ctx := t.Context()
	orgID := func(slug string) int64 {
		orgs, err := e.st.ListOrgs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range orgs {
			if o.Slug == slug {
				return o.ID
			}
		}
		t.Fatalf("no org %s", slug)
		return 0
	}
	since := testNow.Add(-3 * time.Hour)
	q := store.FleetQuiet{OrgID: orgID("acme"), HeldSince: testNow.Add(-time.Hour), QuietSince: since, Quiet: 9, Total: 11,
		Hosts: []string{"web-01"}, Still: "hub"}
	if err := e.st.PutFleetQuiet(ctx, q); err != nil {
		t.Fatal(err)
	}
	const banner = "Public ingest looks down: 9 of 11 hosts in acme stopped reporting since "
	if body := e.get("/", signedIn(e)).Body.String(); strings.Contains(body, banner) {
		t.Error("banner shown before the episode was confirmed")
	}
	q.ConfirmedAt = testNow.Add(-50 * time.Minute)
	if err := e.st.PutFleetQuiet(ctx, q); err != nil {
		t.Fatal(err)
	}
	want := banner + since.UTC().Format("15:04") + " UTC; the hub&#39;s own collector still reports."
	for _, path := range []string{"/", "/hosts", "/anomalies"} {
		if body := e.get(path, signedIn(e)).Body.String(); !strings.Contains(body, want) || !strings.Contains(body, `class="notice notice-down" role="alert"`) {
			t.Errorf("%s: no ingest banner", path)
		}
	}
	e.st.CreateOrg(ctx, "test", "globex", "Globex")
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgID("globex"): store.RoleViewer}}}
	if body := e.get("/", signedIn(e)).Body.String(); strings.Contains(body, "Public ingest looks down") {
		t.Error("banner shown to someone who can't see the org")
	}
	e.auth.viewer = nil
	q.ClearSince = testNow
	if err := e.st.PutFleetQuiet(ctx, q); err != nil {
		t.Fatal(err)
	}
	if body := e.get("/", signedIn(e)).Body.String(); strings.Contains(body, "Public ingest looks down") {
		t.Error("banner shown once reports resumed")
	}
}
