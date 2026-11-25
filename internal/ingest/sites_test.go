// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseSites(t *testing.T) {
	got, ok := parseSites("v1 on /home/acme/example.com /etc/nginx/sites-enabled/example.com;on /var/www/b -;" +
		"off /home/acme/old.example.com /etc/nginx/sites-available/old old.example.com,www.old.example.com,BAD_NAME;" +
		"off /home/acme/example.com /x dup;off relative /x;bogus /a /b;off /home/acme/gone /etc/nginx/heimdall-disabled/gone")
	want := []store.SiteVhost{
		{Root: "/home/acme/example.com", Vhost: "/etc/nginx/sites-enabled/example.com", Enabled: true},
		{Root: "/var/www/b", Enabled: true},
		{Root: "/home/acme/old.example.com", Vhost: "/etc/nginx/sites-available/old", Names: []string{"old.example.com", "www.old.example.com"}},
		{Root: "/home/acme/gone", Vhost: "/etc/nginx/heimdall-disabled/gone"},
	}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSites = %+v, %v", got, ok)
	}
	if got, ok := parseSites("v1"); !ok || len(got) != 0 {
		t.Errorf("v1 alone = %v, %v", got, ok)
	}
	for _, bad := range []string{"", "v2 on /a /b", "v1x", "v1 " + strings.Repeat("a", maxSitesHeader)} {
		if _, ok := parseSites(bad); ok {
			t.Errorf("parseSites(%q) accepted", bad)
		}
	}
}

func (e *env) pushSites(header string, set bool) {
	e.t.Helper()
	hr := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(e.body))
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/json")
	if set {
		hr.Header.Set(SitesHeader, header)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	if w.Code >= 300 {
		e.t.Fatalf("push status %d: %s", w.Code, w.Body.String())
	}
}

func TestSitesHeader(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	e.pushSites("v1 on /var/www/a /etc/nginx/sites-enabled/a;off /var/www/old /etc/nginx/sites-available/old old.example.com", true)
	got, err := e.st.HostSiteVhosts(ctx, e.host.ID)
	if err != nil || len(got) != 2 || !got["/var/www/a"].Enabled || got["/var/www/old"].Enabled {
		t.Fatalf("vhosts = %+v, %v", got, err)
	}
	dis, err := e.st.DisabledSites(ctx)
	if err != nil || len(dis) != 1 || dis[0].Root != "/var/www/old" || dis[0].Host != e.host.Name || len(dis[0].Names) != 1 {
		t.Fatalf("disabled = %+v, %v", dis, err)
	}
	// An older collector and a malformed header change nothing.
	e.pushSites("", false)
	e.pushSites("garbage", true)
	if got, _ := e.st.HostSiteVhosts(ctx, e.host.ID); len(got) != 2 {
		t.Fatalf("vhosts changed: %+v", got)
	}
	// The next header replaces the list.
	e.pushSites("v1 on /var/www/old /etc/nginx/sites-enabled/old", true)
	if got, _ := e.st.HostSiteVhosts(ctx, e.host.ID); len(got) != 1 || !got["/var/www/old"].Enabled {
		t.Fatalf("vhosts = %+v", got)
	}
}
