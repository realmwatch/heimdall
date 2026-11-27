// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/updates"
)

func TestUpdatesPage(t *testing.T) {
	t.Parallel()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/realmwatch/heimdall/releases/tag/v9.9.9","published_at":"` +
			time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`))
	}))
	defer gh.Close()
	d := t.TempDir()
	status := filepath.Join(d, "status")
	os.Mkdir(status, 0o750)
	inst := &updates.Installer{Current: "v0.5.0", Auto: true, Soak: 2 * time.Hour, Request: filepath.Join(d, "request"), Dir: status}
	chk := &updates.Checker{HTTP: netx.NewForTest(gh.Client()), URL: gh.URL, Current: "v0.5.0"}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Version = "v0.5.0"
		c.Upgrades = &Upgrades{Checker: chk, Installer: inst}
		c.Updates = chk.Available
	})
	e.seed()
	csrf := auth.CSRFToken(goodToken)
	body := func(path string) string {
		t.Helper()
		w := e.get(path, signedIn(e))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	if b := body("/admin/updates"); !strings.Contains(b, "not checked yet") || !strings.Contains(b, "Check now") {
		t.Error("before a check")
	}
	if b := body("/hosts"); !strings.Contains(b, `<a class="side-version" href="/admin/updates" title="Heimdall v0.5.0">v0.5.0</a>`) {
		t.Error("the sidebar doesn't show the running version")
	}
	if w := e.post("/admin/updates/check", url.Values{"csrf": {csrf}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("check: %d", w.Code)
	}
	b := body("/admin/updates?ok=checked")
	for _, want := range []string{"v9.9.9 is available", "Install v9.9.9 now", "waiting until it has been out for 2h0m0s"} {
		if !strings.Contains(b, want) {
			t.Errorf("updates page missing %q", want)
		}
	}
	if !strings.Contains(body("/hosts"), `title="Heimdall v0.5.0: v9.9.9 is available">v0.5.0<span class="side-text"> · update available</span></a>`) {
		t.Error("the sidebar version doesn't mention the update")
	}
	if !strings.Contains(body("/hosts"), `<a href="/admin/updates">Install it</a>`) {
		t.Error("banner doesn't link to the updates page")
	}
	// Only the release the check found.
	if w := e.post("/admin/updates/install", url.Values{"csrf": {csrf}, "version": {"v9.9.8"}}, signedIn(e), origin(e.baseURL)); w.Header().Get("Location") != "/admin/updates?error=install" {
		t.Errorf("other version: %s", w.Header().Get("Location"))
	}
	if w := e.post("/admin/updates/install", url.Values{"csrf": {csrf}, "version": {"v9.9.9"}}, signedIn(e), origin(e.baseURL)); w.Header().Get("Location") != "/admin/updates?ok=requested" {
		t.Fatalf("install: %s", w.Header().Get("Location"))
	}
	if inst.Requested() != "v9.9.9" {
		t.Errorf("requested %q", inst.Requested())
	}
	if !strings.Contains(body("/admin/updates"), "Installing v9.9.9") {
		t.Error("pending upgrade not shown")
	}
	updates.WriteStatus(status, updates.Status{Version: "v9.9.9", From: "v0.5.0", Result: updates.ResultFailed, Message: "the new hub didn't start", Started: time.Now(), Finished: time.Now()})
	if b := body("/admin/updates"); !strings.Contains(b, "the new hub didn&#39;t start") || !strings.Contains(b, "won't try this release again") {
		t.Error("failed upgrade not shown")
	}
	// Non-admins: no page.
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken}
	if w := e.get("/admin/updates", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("non-admin: %d", w.Code)
	}
	if w := e.post("/admin/updates/install", url.Values{"csrf": {csrf}, "version": {"v9.9.9"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("non-admin install: %d", w.Code)
	}
}
