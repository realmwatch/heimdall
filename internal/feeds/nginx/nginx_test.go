// SPDX-License-Identifier: AGPL-3.0-or-later

package nginx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"github.com/realmwatch/heimdall/internal/feeds/osv"
	"github.com/realmwatch/heimdall/internal/netx"
)

func load(t *testing.T) map[string]Advisory {
	t.Helper()
	raw, err := os.ReadFile("testdata/advisories.xml")
	if err != nil {
		t.Fatal(err)
	}
	list, skipped, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	// "none" severity, two Windows-only entries, a too-short CVE and an
	// unreadable range.
	if skipped != 5 {
		t.Errorf("skipped %d, want 5", skipped)
	}
	out := map[string]Advisory{}
	for _, a := range list {
		out[a.CVE] = a
	}
	if len(out) != 7 {
		t.Errorf("parsed %d advisories, want 7: %v", len(out), slices.Collect(func(yield func(string) bool) {
			for k := range out {
				if !yield(k) {
					return
				}
			}
		}))
	}
	return out
}

func TestParse(t *testing.T) {
	m := load(t)
	a := m["CVE-2026-123007"]
	if a.ID != "NGINX-CVE-2026-123007" || a.Severity != "high" || a.Feature != "http2" ||
		a.URL != "https://example.com/advisory/1" || a.Name != "Memory corruption in HTTP/2 flow control" {
		t.Errorf("123007 = %+v", a)
	}
	if !slices.Equal(a.Good, []string{"1.30.7", "1.31.9"}) || len(a.Vulnerable) != 1 || a.Vulnerable[0] != [2]string{"1.9.5", "1.31.8"} {
		t.Errorf("123007 bounds = %v %v", a.Vulnerable, a.Good)
	}
	if b := m["CVE-2026-121810"]; b.ID != "NGINX-CVE-2026-121810" || b.Feature != "http3" || b.Severity != "medium" {
		t.Errorf("CVE- prefixed entry = %+v", b)
	}
	if c := m["CVE-2026-120993"]; c.URL != "" || c.Feature != "proxy_protocol" || c.Severity != "low" {
		t.Errorf("a non-https advisory link must be dropped: %+v", c)
	}
	if d := m["CVE-2026-113425"]; d.Feature != "mail" {
		t.Errorf("mail = %+v", d)
	}
	if e := m["CVE-2026-55555"]; len(e.Good) != 0 {
		t.Errorf(`good="none" = %v`, e.Good)
	}
}

func TestParseRejects(t *testing.T) {
	for _, raw := range []string{"", "<html><body>not it</body></html>", "<security><item"} {
		if _, _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("Parse(%q) accepted", raw)
		}
	}
}

func TestAffectsAndFix(t *testing.T) {
	m := load(t)
	cases := []struct {
		cve, v   string
		affected bool
		fix      string
	}{
		{"CVE-2026-123007", "1.9.4", false, ""},
		{"CVE-2026-123007", "1.9.5", true, "1.30.7"},
		{"CVE-2026-123007", "1.18.0", true, "1.30.7"},
		{"CVE-2026-123007", "1.24.0", true, "1.30.7"},
		{"CVE-2026-123007", "1.30.6", true, "1.30.7"},
		{"CVE-2026-123007", "1.30.7", false, ""},
		{"CVE-2026-123007", "1.30.12", false, ""},
		{"CVE-2026-123007", "1.31.0", true, "1.31.9"},
		{"CVE-2026-123007", "1.31.8", true, "1.31.9"},
		{"CVE-2026-123007", "1.31.9", false, ""},
		{"CVE-2026-123007", "1.32.0", false, ""},
		// Two vulnerable ranges; the 1.26 branch fixed in 1.26.1.
		{"CVE-2024-32760", "1.24.0", false, ""},
		{"CVE-2024-32760", "1.25.3", true, "1.26.1"},
		{"CVE-2024-32760", "1.26.0", true, "1.26.1"},
		{"CVE-2024-32760", "1.26.1", false, ""},
		{"CVE-2024-32760", "1.27.0", false, ""},
		// Old branches, each with its own fix.
		{"CVE-2009-2629", "0.6.38", true, "0.6.39"},
		{"CVE-2009-2629", "0.6.39", false, ""},
		{"CVE-2009-2629", "0.8.14", true, "0.8.15"},
		{"CVE-2009-2629", "1.0.0", false, ""},
		// Nothing fixes it.
		{"CVE-2026-55555", "1.30.6", true, ""},
		{"CVE-2026-55555", "1.31.9", false, ""},
		{"CVE-2026-123007", "garbage", false, ""},
	}
	for _, c := range cases {
		a := m[c.cve]
		if got := a.Affects(c.v); got != c.affected {
			t.Errorf("%s Affects(%s) = %v", c.cve, c.v, got)
		}
		if c.affected {
			if got := a.FixFor(c.v); got != c.fix {
				t.Errorf("%s FixFor(%s) = %q, want %q", c.cve, c.v, got, c.fix)
			}
		}
	}
}

// TestOSVRecord: the stored record parses as OSV, and its ranges say the
// same as Affects for every version around each bound.
func TestOSVRecord(t *testing.T) {
	m := load(t)
	for _, a := range m {
		v, err := osv.Parse(a.OSV())
		if err != nil {
			t.Fatalf("%s: %v", a.ID, err)
		}
		if v.ID != a.ID || !slices.Contains(v.CVEs(), a.CVE) || v.DistroRating() != a.Severity || v.Summary != a.Name {
			t.Errorf("%s: OSV record = %+v (CVEs %v, rating %q)", a.ID, v, v.CVEs(), v.DistroRating())
		}
		if len(v.Affected) != 1 || v.Affected[0].Package.Ecosystem != Ecosystem || v.Affected[0].Package.Name != Package {
			t.Fatalf("%s: affected = %+v", a.ID, v.Affected)
		}
		inRanges := func(ver string) bool {
			for _, r := range v.Affected[0].Ranges {
				lo, fixed, last := "", "", ""
				for _, e := range r.Events {
					switch {
					case e.Introduced != "":
						lo = e.Introduced
					case e.Fixed != "":
						fixed = e.Fixed
					case e.LastAffected != "":
						last = e.LastAffected
					}
				}
				if Compare(ver, lo) < 0 {
					continue
				}
				if (fixed != "" && Compare(ver, fixed) < 0) || (last != "" && Compare(ver, last) <= 0) || (fixed == "" && last == "") {
					return true
				}
			}
			return false
		}
		for _, ver := range []string{"0.1.0", "0.5.37", "0.5.38", "0.6.39", "0.8.14", "0.8.15", "1.0.0", "1.9.4", "1.9.5",
			"1.18.0", "1.20.0", "1.24.0", "1.25.0", "1.25.5", "1.25.6", "1.26.0", "1.26.1", "1.27.0", "1.30.6", "1.30.7",
			"1.31.0", "1.31.3", "1.31.4", "1.31.8", "1.31.9", "1.32.0"} {
			if got, want := inRanges(ver), a.Affects(ver); got != want {
				t.Errorf("%s: %s in OSV ranges = %v, Affects = %v (ranges %+v)", a.ID, ver, got, want, v.Affected[0].Ranges)
			}
		}
		var ds struct {
			Good    []string `json:"good"`
			Feature string   `json:"feature"`
		}
		if err := json.Unmarshal(v.DatabaseSpecific, &ds); err != nil || !slices.Equal(ds.Good, a.Good) || ds.Feature != a.Feature {
			t.Errorf("%s: database_specific = %s", a.ID, v.DatabaseSpecific)
		}
	}
}

func TestUpstreamVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.30.6-1~jammy":                        "1.30.6",
		"1.18.0-6ubuntu14.4":                    "1.18.0",
		"1:1.24.0-2":                            "1.24.0",
		"1.20.1-14.el9_2.1":                     "1.20.1",
		"1.30.7-r0":                             "1.30.7",
		"1.22.1-9+deb12u2":                      "1.22.1",
		"1.26.3":                                "1.26.3",
		"1.31.8-1~resolute":                     "1.31.8",
		"1.30.6-1.el9.ngx":                      "1.30.6",
		"1.24.0+dfsg-1ubuntu1":                  "1.24.0",
		"1.26.3-1+ubuntu22.04.1+deb.sury.org+1": "1.26.3",
	} {
		if got, ok := UpstreamVersion(in); !ok || got != want {
			t.Errorf("UpstreamVersion(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "abc", "1-2", "1.x.0-1"} {
		if _, ok := UpstreamVersion(bad); ok {
			t.Errorf("UpstreamVersion(%q) accepted", bad)
		}
	}
}

func TestIsNginxOrgBuild(t *testing.T) {
	for v, want := range map[string]bool{
		"1.30.6-1~jammy":     true,
		"1.31.8-1~noble":     true,
		"1.30.6-1.el9.ngx":   true,
		"1.18.0-6ubuntu14.4": false,
		"1.22.1-9+deb12u2":   false,
		"1.26.3-3":           false,
		"1.30.6-1.fc43":      false,
		"1.30.7-r0":          false,
		"1.20.1-14.el9_2.1":  false,
	} {
		if got := IsNginxOrgBuild(v); got != want {
			t.Errorf("IsNginxOrgBuild(%q) = %v", v, got)
		}
	}
}

func TestIsSuryBuild(t *testing.T) {
	if !IsSuryBuild("1.26.3-1+ubuntu22.04.1+deb.sury.org+1") || !IsThirdPartyBuild("1.26.3-1+ubuntu22.04.1+deb.sury.org+1") {
		t.Error("Surý's build not recognized")
	}
	if IsSuryBuild("1.30.6-1~jammy") || !IsThirdPartyBuild("1.30.6-1~jammy") || IsThirdPartyBuild("1.18.0-6ubuntu14.4") {
		t.Error("misjudged")
	}
}

func TestFetch(t *testing.T) {
	raw, _ := os.ReadFile("testdata/advisories.xml")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
	defer srv.Close()
	c := netx.NewForTest(srv.Client())
	list, err := Fetch(context.Background(), c, srv.URL+"/x.xml")
	if err != nil || len(list) != 7 {
		t.Fatalf("Fetch = %d, %v", len(list), err)
	}
}
