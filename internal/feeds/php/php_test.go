// SPDX-License-Identifier: AGPL-3.0-or-later

package php

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/netx"
)

func testList(t *testing.T) []Advisory {
	t.Helper()
	raw, err := os.ReadFile("testdata/advisories.json")
	if err != nil {
		t.Fatal(err)
	}
	list, skipped, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 3 { // withdrawn, a bad ID, an unreadable range
		t.Errorf("skipped = %d, want 3", skipped)
	}
	return list
}

func byGHSA(list []Advisory, id string) Advisory {
	for _, a := range list {
		if a.GHSA == id {
			return a
		}
	}
	return Advisory{}
}

func TestParse(t *testing.T) {
	list := testList(t)
	if len(list) != 4 {
		t.Fatalf("parsed %d, want 4", len(list))
	}
	fpm := byGHSA(list, "GHSA-2222-3333-4444")
	if fpm.ID != "PHP-GHSA-2222-3333-4444" || fpm.CVE != "CVE-2026-990001" || fpm.Severity != "critical" ||
		fpm.Summary != "FPM request smuggling via an unread body" || !strings.HasPrefix(fpm.CVSSv4, "CVSS:4.0/") ||
		fpm.URL != PageURL+"/GHSA-2222-3333-4444" || fpm.Published != "2026-11-19T14:05:55Z" {
		t.Errorf("fpm = %+v", fpm)
	}
	if !slices.Equal(fpm.Components, []string{"sapi-fpm"}) || !slices.Equal(fpm.Good, []string{"8.3.37", "8.4.28"}) {
		t.Errorf("fpm components %v good %v", fpm.Components, fpm.Good)
	}
	old := byGHSA(list, "GHSA-p8p8-q9q9-r2r2")
	if old.CVE != "" || old.Components != nil { // an entry without a component: the core
		t.Errorf("old = %+v", old)
	}
	if !slices.Equal(old.Good, []string{"8.0.30", "8.1.29", "8.2.20", "8.3.8"}) {
		t.Errorf("old good = %v", old.Good)
	}
}

func TestAffectsAndFix(t *testing.T) {
	list := testList(t)
	fpm := byGHSA(list, "GHSA-2222-3333-4444")
	date := byGHSA(list, "GHSA-c2c2-f3f3-g4g4")
	old := byGHSA(list, "GHSA-p8p8-q9q9-r2r2")
	for _, c := range []struct {
		a    Advisory
		v    string
		want bool
		fix  string
	}{
		{fpm, "8.4.27", true, "8.4.28"},
		{fpm, "8.4.28", false, ""},
		{fpm, "8.3.36", true, "8.3.37"},
		{fpm, "8.1.34", true, ""}, // affected, and no fix on 8.1
		{fpm, "8.1.19", false, ""},
		{fpm, "8.2.30", false, ""}, // not listed: 8.2 isn't affected
		{date, "8.2.30", true, ""}, // "< 8.3.37" reaches back, with no 8.2 fix
		{date, "8.3.37", false, ""},
		{old, "8.2.19", true, "8.2.20"},
		{old, "8.2.20", false, ""},
		{old, "8.0.0", false, ""}, // "> 8.0.0"
		{old, "8.0.1", true, "8.0.30"},
		{old, "8.4.1", false, ""},
	} {
		if got := c.a.Affects(c.v); got != c.want {
			t.Errorf("%s affects %s = %v, want %v", c.a.GHSA, c.v, got, c.want)
		}
		if c.want {
			if got := FixFor(c.a.Good, c.v); got != c.fix {
				t.Errorf("%s fix for %s = %q, want %q", c.a.GHSA, c.v, got, c.fix)
			}
		}
	}
}

func TestOSVRecord(t *testing.T) {
	fpm := byGHSA(testList(t), "GHSA-2222-3333-4444")
	var rec struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Severity []struct{ Type, Score string }
		Affected []struct {
			Package struct{ Ecosystem, Name string }
			Ranges  []struct {
				Events []map[string]string
			}
		}
		DatabaseSpecific struct {
			Severity   string   `json:"severity"`
			Good       []string `json:"good"`
			Components []string `json:"components"`
		} `json:"database_specific"`
	}
	if err := json.Unmarshal(fpm.OSV(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID != fpm.ID || !slices.Equal(rec.Aliases, []string{"CVE-2026-990001", "GHSA-2222-3333-4444"}) ||
		len(rec.Severity) != 1 || rec.Severity[0].Type != "CVSS_V4" {
		t.Errorf("record = %+v", rec)
	}
	if len(rec.Affected) != 1 || rec.Affected[0].Package.Ecosystem != Ecosystem || len(rec.Affected[0].Ranges) != 3 {
		t.Fatalf("affected = %+v", rec.Affected)
	}
	if ev := rec.Affected[0].Ranges[0].Events; ev[0]["introduced"] != "8.1.20" || ev[1]["last_affected"] != "8.1.34" {
		t.Errorf("8.1 range = %v", ev)
	}
	if ev := rec.Affected[0].Ranges[2].Events; ev[0]["introduced"] != "8.4.0" || ev[1]["fixed"] != "8.4.28" {
		t.Errorf("8.4 range = %v", ev)
	}
	if rec.DatabaseSpecific.Severity != "critical" || !slices.Equal(rec.DatabaseSpecific.Components, []string{"sapi-fpm"}) {
		t.Errorf("database_specific = %+v", rec.DatabaseSpecific)
	}
}

func TestComponentsInstalled(t *testing.T) {
	bins := []string{"php8.4-cli", "php8.4-common", "php8.4-fpm", "php8.4-mysql", "php8.4-xml"}
	for _, c := range []struct {
		comps []string
		want  bool
	}{
		{nil, true},                     // the core
		{[]string{"sapi-fpm"}, true},    // php8.4-fpm
		{[]string{"sapi-cgi"}, false},   // no php8.4-cgi
		{[]string{"ext-soap"}, false},   // no php8.4-soap
		{[]string{"ext-dom"}, true},     // in php8.4-xml
		{[]string{"ext-mysqlnd"}, true}, // in php8.4-mysql
		{[]string{"ext-session"}, true}, // built in
		{[]string{"sapi-apache2handler"}, false},
		{[]string{"ext-soap", "sapi-fpm"}, true},
	} {
		if got := Installed(c.comps, "php8.4", bins); got != c.want {
			t.Errorf("Installed(%v) = %v, want %v", c.comps, got, c.want)
		}
	}
	if Component("PHP-FPM") != "sapi-fpm" || Component("") != "" || Component("php-src") != "" || Component("ext-soap") != "ext-soap" {
		t.Error("Component")
	}
}

func TestUpstreamVersion(t *testing.T) {
	for in, want := range map[string]string{
		"8.4.27-1+ubuntu24.04.1+deb.sury.org+1": "8.4.27",
		"8.5.12-3+0~deb.sury.org.1+ubuntu26.04": "8.5.12",
		"1:8.3.6-0ubuntu0.24.04.5":              "8.3.6",
	} {
		if got, ok := UpstreamVersion(in); !ok || got != want {
			t.Errorf("UpstreamVersion(%q) = %q, %v", in, got, ok)
		}
	}
	if !IsSuryBuild("8.4.27-1+ubuntu24.04.1+deb.sury.org+1") || !IsSuryBuild("8.2.12-1+0~20231026.31+debian12~1.gbp3fb5e2") ||
		IsSuryBuild("8.3.6-0ubuntu0.24.04.5") || IsSuryBuild("8.2.29-1~deb12u1") {
		t.Error("IsSuryBuild")
	}
	if !IsSource("php8.4") || IsSource("php-defaults") || IsSource("php8.4-fpm") {
		t.Error("IsSource")
	}
}

// Fetch follows GitHub's Link header page by page, only on the same
// endpoint, and sends the token only when one is set.
func TestFetchPages(t *testing.T) {
	raw, err := os.ReadFile("testdata/advisories.json")
	if err != nil {
		t.Fatal(err)
	}
	var items []json.RawMessage
	json.Unmarshal(raw, &items)
	var auth []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Query().Get("page") == "2" {
			w.Header().Set("Link", `<https://elsewhere.example.com/x?page=3>; rel="next"`)
			b, _ := json.Marshal(items[2:])
			w.Write(b)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?per_page=2&page=2>; rel="next", <%s/advisories?page=2>; rel="last"`, srv.URL, srv.URL))
		b, _ := json.Marshal(items[:2])
		w.Write(b)
	}))
	defer srv.Close()
	c := netx.NewForTest(srv.Client())
	list, err := Fetch(t.Context(), c, srv.URL+"/advisories?per_page=2", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 || len(auth) != 2 || auth[0] != "" {
		t.Errorf("got %d advisories over %d requests (auth %q)", len(list), len(auth), auth)
	}
	auth = nil
	if _, err := Fetch(t.Context(), c, srv.URL+"/advisories?per_page=2", "tok"); err != nil || auth[0] != "Bearer tok" {
		t.Errorf("with a token: %v %q", err, auth)
	}
}
