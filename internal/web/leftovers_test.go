// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/ai"
	"github.com/realmwatch/heimdall/internal/leftovers"
	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// A noble host upgraded from jammy: its release leftovers card lists the
// stale source, the old build, the obsolete package and the service that
// loads it, each obsolete package's plan, a vendor's .deb apart (not
// obsolete), offers the
// cleanup action with that plan as its params, and its leftover's finding
// says no update fixes it.
func TestHostPageReleaseLeftovers(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
	h := seedLeftoverHost(t, e)
	ctx := t.Context()

	page := e.get("/hosts/acme/web-01?show=all", signedIn(e)).Body.String()
	for _, want := range []string{
		`id="release-leftovers"`, `<span class="sev sev-medium">medium</span>`,
		"This server runs Ubuntu 24.04 (noble) but still has parts of Ubuntu 22.04 (jammy)",
		"<code>/etc/apt/sources.list.d/pgdg.list</code>", "<td>noble-pgdg</td>",
		"<code>php8.3-fpm.service</code>", "maps <code>libpq.so.5</code> from libpq5",
		"<td>libtinfo5</td>", "<td>libpq5</td>", "only some processes",
		`href="https://changes.example.com/propose?action=release.cleanup&amp;org=acme&amp;host=web-01&amp;keep=acme-agent&amp;remove=libtinfo5"`,
		"<h3>Installed on purpose</h3>", `<code>acme-agent</code> <span class="muted">3.0.0.1000 · a vendor's .deb</span>`,
		`<input type="hidden" name="package" value="libtinfo5"><button type="submit" class="link"`,
		`<span class="badge warn">remove</span> <span class="muted">nothing installed needs it</span>`,

		"built for Ubuntu 22.04 (jammy)", "no update: a leftover",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks %q", want)
		}
	}

	// Keeping libtinfo5: it moves to the kept list with an Undo, is no
	// longer a leftover, and the cleanup link keeps it too. Undo puts it
	// back.
	if w := e.formPost("/hosts/acme/web-01/keep", url.Values{"package": {"libtinfo5"}}); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/hosts/acme/web-01?renamed=kept#release-leftovers" {
		t.Fatalf("keep: %d %s", w.Code, w.Header().Get("Location"))
	}
	page = e.get("/hosts/acme/web-01?show=all&renamed=kept", signedIn(e)).Body.String()
	for _, want := range []string{
		`<code>libtinfo5</code> <span class="muted">6.3-2 · marked to keep</span>`, `<input type="hidden" name="keep" value="0"><button type="submit" class="link">Undo</button>`,
		`&amp;keep=libtinfo5%2Cacme-agent"`, "Marked as installed on purpose",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("after keep, host page lacks %q", want)
		}
	}
	const keepBtn = `value="libtinfo5"><button type="submit" class="link" title="It was installed on purpose`
	if strings.Contains(page, keepBtn) {
		t.Error("a kept package is still listed as obsolete")
	}
	if w := e.formPost("/hosts/acme/web-01/keep", url.Values{"package": {"libtinfo5"}, "keep": {"0"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("undo: %d", w.Code)
	}
	if page := e.get("/hosts/acme/web-01?show=all", signedIn(e)).Body.String(); !strings.Contains(page, keepBtn) {
		t.Error("undo didn't put it back")
	}
	if w := e.formPost("/hosts/acme/web-01/keep", url.Values{"package": {"Bad Name"}}); w.Code != http.StatusSeeOther {
		t.Errorf("a bad name: %d", w.Code)
	}
	if kept, _ := e.st.KeptPackages(ctx, h.ID); len(kept) != 0 {
		t.Errorf("kept %v", kept)
	}

	// No leftovers, no card and no button.
	plain := kernelCaseEnv(t)
	if page := plain.get("/hosts/acme/"+storetest.OldKernelHost, signedIn(plain)).Body.String(); strings.Contains(page, "release-leftovers") ||
		strings.Contains(page, "release.cleanup") {
		t.Error("a host without leftovers shows the card")
	}
}

// seedLeftoverHost makes acme/web-01: noble, upgraded from jammy, with a
// stale pgdg source, an old build of libpq5 that php8.3-fpm loads, an
// obsolete libtinfo5 and a vendor's acme-agent.
func seedLeftoverHost(t *testing.T, e *env) store.IngestHost {
	t.Helper()
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	e.st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	h, err := e.st.HostByName(ctx, "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(storetest.KernelCaseSnapshot(t, storetest.OldKernelHost, testNow), &snap)
	snap["packages"] = append(snap["packages"].([]any),
		map[string]any{"name": "libtinfo5", "version": "6.3-2", "arch": "amd64", "source_name": "ncurses", "source_version": "6.3-2"},
		map[string]any{"name": "acme-agent", "version": "3.0.0.1000", "arch": "amd64"},
		map[string]any{"name": "libpq5", "version": "16.4-1.pgdg22.04+1", "arch": "amd64", "source_name": "postgresql-16", "source_version": "16.4-1.pgdg22.04+1"})
	raw, _ := json.Marshal(snap)
	s, err := snapshot.DecodeBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SaveReport(ctx, store.NewSnapshot{Host: h, Source: "push", ReceivedAt: testNow, PayloadSHA256: sha256.Sum256(raw), Snapshot: s}, nil); err != nil {
		t.Fatal(err)
	}
	st, err := leftovers.Parse("v1 cn=noble maps=10/90;u=sources.list.d/pgdg.list.distUpgrade;" +
		"p=812|php8.3-fpm.service|php-fpm8.3|libpq.so.5|libpq5;" +
		"s=sources.list.d/pgdg.list|http://apt.postgresql.org/pub/repos/apt|jammy-pgdg|main;" +
		"o=libtinfo5|6.3-2|0|;o=acme-agent|3.0.0.1000|0|;b=libpq5|16.4-1.pgdg22.04+1|jammy-pgdg")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(st)
	if err := e.st.SetHostRelease(ctx, h.ID, b, testNow); err != nil {
		t.Fatal(err)
	}
	e.st.PutAdvisory(ctx, store.Advisory{ID: "UBUNTU-CVE-2026-40001", Modified: testNow, Severity: "high", Raw: []byte(`{}`)})
	if _, _, err := e.st.SetFindings(ctx, h.ID, []store.Finding{{AdvisoryID: "UBUNTU-CVE-2026-40001", Ecosystem: "Ubuntu:22.04",
		Package: "postgresql-16", Version: "16.4-1.pgdg22.04+1", Binaries: []string{"libpq5"}}}, testNow); err != nil {
		t.Fatal(err)
	}

	return h
}

// The leftovers card leads with the steps, in order, and with AI on
// offers a plan: the button starts one, and a stored plan shows its
// steps and per-package advice.
func TestLeftoversStepsAndAIPlan(t *testing.T) {
	t.Parallel()
	fa := &fakeAI{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.AI = fa })
	h := seedLeftoverHost(t, e)
	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{
		"<h3>What to do, in order</h3>", "<strong>Fix the apt sources that name an older release</strong>",
		"/etc/apt/sources.list.d/pgdg.list (jammy-pgdg → noble-pgdg)", "<strong>Restart what loads them</strong>",
		"restart php8.3-fpm.service (or reboot)", "<strong>Remove these: nothing needs them</strong>",
		`<summary>What Heimdall found</summary>`,
		`action="/hosts/acme/web-01/ai/leftovers"`, ">Ask AI for a plan</button>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	if strings.Index(page, "What to do, in order") > strings.Index(page, "What Heimdall found") {
		t.Error("the steps aren't first")
	}
	w := e.formPost("/hosts/acme/web-01/ai/leftovers", url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/hosts/acme/web-01?for=leftovers&ai=started#release-leftovers" ||
		len(fa.leftovers) != 1 || fa.leftovers[0] != "user:1 acme/web-01" {
		t.Fatalf("start: %d %s %v", w.Code, w.Header().Get("Location"), fa.leftovers)
	}

	ctx := t.Context()
	id, err := e.st.StartAIRun(ctx, h.OrgID, h.ID, store.AILeftovers, "user:1", "my-deployment", testNow, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	plan := ai.LeftoverPlan{Summary: "The pgdg source still names jammy.",
		Steps:    []ai.LeftoverStep{{Title: "Point pgdg at noble", Why: "It gives noble builds.", Packages: []string{"libpq5"}}},
		Packages: []ai.LeftoverAdvice{{Name: "libpq5", Action: ai.LeftoverWait, Why: "<b>old</b>", Heimdall: "still loaded by php8.3-fpm.service, so not removed yet"}},
		Notes:    ai.Notes{"Restart PHP after."}}
	b, _ := json.Marshal(plan)
	if err := e.st.FinishAIRun(ctx, id, "ok", "gpt", 10, 10, "", b, testNow); err != nil {
		t.Fatal(err)
	}
	page = e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{
		`<p class="ai-summary">The pgdg source still names jammy.</p>`, "<strong>Point pgdg at noble</strong>",
		"<td>libpq5</td><td><span class=\"badge bad\">wait</span></td>", "&lt;b&gt;old&lt;/b&gt;",
		"changed by Heimdall: still loaded by php8.3-fpm.service", ">Ask again</button>", "Restart PHP after.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host page with a plan lacks %q", want)
		}
	}
}
