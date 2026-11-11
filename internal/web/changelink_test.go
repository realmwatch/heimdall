// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/updates"
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
		`href="https://changes.example.com/new?org=acme&amp;host=web-01&amp;pkg=&amp;finding=` + id + `" target="_blank" rel="noopener noreferrer">Install security updates · fixes 1 finding</a>`,
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

func TestCollectorLink(t *testing.T) {
	t.Parallel()
	c := ChangeLink{CollectorURL: "https://changes.example.com/collector?org={org}&host={host}"}
	if got, want := c.collectorLink("a&b", "web 01", true), "https://changes.example.com/collector?org=a%26b&host=web+01"; got != want {
		t.Errorf("link = %q, want %q", got, want)
	}
	if got := c.collectorLink("acme", "web-01", false); got != "" {
		t.Errorf("current collector got a link: %q", got)
	}
	if got := (ChangeLink{}).collectorLink("acme", "web-01", true); got != "" {
		t.Errorf("no template got a link: %q", got)
	}
}

func TestCollectorLinkOnPages(t *testing.T) {
	t.Parallel()
	const tooltip = `title="On the server: sudo heimdall-collect upgrade">behind</span>`
	const href = `href="https://changes.example.com/collector?org=acme&amp;host=web-01"`

	off := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.Version = "v9.0.0" })
	off.seed() // collector 0.1.0: behind
	if body := off.get("/hosts", signedIn(off)).Body.String(); !strings.Contains(body, tooltip) || strings.Contains(body, "/collector?") {
		t.Error("without collector_url the host list should keep the plain pill")
	}
	if body := off.get("/hosts/acme/web-01", signedIn(off)).Body.String(); strings.Contains(body, "Update collector") {
		t.Error("update collector link shown without collector_url")
	}

	on := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Version = "v9.0.0"
		c.ChangeLink.CollectorURL = "https://changes.example.com/collector?org={org}&host={host}"
	})
	host := on.seed()
	if body := on.get("/hosts", signedIn(on)).Body.String(); !strings.Contains(body, href) || strings.Contains(body, tooltip) {
		t.Error("a behind collector's pill should link to collector_url")
	}
	if body := on.get("/hosts/acme/web-01", signedIn(on)).Body.String(); !strings.Contains(body, href) || !strings.Contains(body, "Update collector") {
		t.Error("host page missing the update collector link")
	}

	raw, _ := os.ReadFile("../snapshot/testdata/debian12.json")
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Add(time.Minute).Format(time.RFC3339)
	snap["collector"].(map[string]any)["version"] = strings.TrimPrefix(updates.CollectorChanged, "v")
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: on.st, Now: func() time.Time { return testNow.Add(time.Minute) }}
	if res, err := acc.Accept(t.Context(), host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("snapshot: %+v %v", res, err)
	}
	for _, path := range []string{"/hosts", "/hosts/acme/web-01"} {
		if body := on.get(path, signedIn(on)).Body.String(); strings.Contains(body, "/collector?") || strings.Contains(body, "Update collector") {
			t.Errorf("%s: a current collector got the link", path)
		}
	}
}

func TestPHPRemoveLinks(t *testing.T) {
	t.Parallel()
	runtimes := []report.Runtime{
		{Name: "php", Use: &report.PHPUse{Minor: "8.2", Unused: true}},
		{Name: "php", Use: &report.PHPUse{Minor: "8.1", Unused: true, CLI: true, CLITo: "8.4"}},
		{Name: "php", Use: &report.PHPUse{Minor: "8.4"}},
		{Name: "node"},
	}
	c := ChangeLink{ActionURL: "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"}
	got := c.phpRemoveLinks("a&b", "web 01", runtimes)
	want := "https://changes.example.com/propose?action=php.remove&org=a%26b&host=web+01&php=8.2"
	if len(got) != 1 || got["8.2"] != want {
		t.Errorf("links = %v, want only 8.2 at %q", got, want)
	}
	if got := (ChangeLink{}).phpRemoveLinks("acme", "web-01", runtimes); got != nil {
		t.Errorf("no template got links: %v", got)
	}
}

func TestAgeAt(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{{time.Hour, "today"}, {12 * 24 * time.Hour, "12d ago"}, {59 * 24 * time.Hour, "59d ago"},
		{60 * 24 * time.Hour, "1mo ago"}, {240 * 24 * time.Hour, "7mo ago"}, {800 * 24 * time.Hour, "2y ago"}} {
		if got := ageAt(now.Add(-tc.d), now); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.d, got, tc.want)
		}
	}
}

// A finding shows how long it's been public, known-exploited and in the
// news, each with its date on hover, and nothing for what isn't known.
func TestFindAgesTemplate(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(funcs).ParseFiles("templates/partials.html"))
	now := time.Now()
	render := func(f report.Finding) string {
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, "findages", f); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	if got := render(report.Finding{}); got != "" {
		t.Errorf("no dates: %q", got)
	}
	got := render(report.Finding{Published: now.Add(-400 * 24 * time.Hour), KEVAdded: now.Add(-12 * 24 * time.Hour), NewsSince: now.Add(-2 * 24 * time.Hour)})
	for _, want := range []string{">public 13mo ago</span> · <span", ">KEV 12d ago</span> · <span", ">in the news 2d ago</span>", `title="Added to CISA's Known Exploited Vulnerabilities `} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if got := render(report.Finding{KEVAdded: now.Add(-12 * 24 * time.Hour)}); strings.Contains(got, "·") || !strings.Contains(got, "KEV 12d ago") {
		t.Errorf("KEV only: %q", got)
	}
}

// Both buttons lead with packages, what changes on the host; the
// security one says how many findings that fixes.
func TestInstallButtonsCount(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(funcs).ParseFiles("templates/partials.html"))
	render := func(fv findingsView) string {
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, "installbtns", fv); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	got := render(findingsView{ChangeURL: "https://changes.example.com/a", ChangeCount: 3104, FixPkgs: 7,
		UpdatesURL: "https://changes.example.com/b", UpdatesCount: 16})
	for _, want := range []string{">Install security updates · 7 packages · fixes 3,104 findings</a>", ">Install all updates · 16 packages</a>"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if got := render(findingsView{ChangeURL: "https://changes.example.com/a", ChangeCount: 1, FixPkgs: 1}); !strings.Contains(got, ">Install security updates · 1 package · fixes 1 finding</a>") {
		t.Errorf("one: %q", got)
	}
}
