// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/store"
)

// phpConfirm opens a PHP hand-off's confirm page and returns its form,
// ready to send, and the prompt's text.
func phpConfirm(t *testing.T, e *env, query string) (url.Values, string) {
	t.Helper()
	w := e.get("/hosts/acme/app-01/handoff/php?root="+url.QueryEscape(siteRoot)+query, signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("confirm page %s: %d", query, w.Code)
	}
	page := w.Body.String()
	m := msgRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("confirm page %s lacks the prompt:\n%s", query, page)
	}
	form := sendForm(t, page)
	form.Set("csrf", auth.CSRFToken(goodToken))
	return form, html.UnescapeString(m[1])
}

func TestPHPHandoff(t *testing.T) {
	t.Parallel()
	fd := newFakeDiscord(t)
	fs := &fakeStarter{id: testThread}
	e := handoffEnv(t, fd.agent("pr-bot", testBotID), handoff.Agent{Name: "amp", Starter: fs})
	host := e.seedSites()
	ctx := t.Context()
	past, future := testNow.AddDate(-1, 0, 0), testNow.AddDate(2, 0, 0)
	if err := e.st.ReplaceEOL(ctx, "php", []store.EOLCycle{{Cycle: "8.2", EOL: &past}, {Cycle: "8.3", EOL: &future},
		{Cycle: "8.4", EOL: &future}, {Cycle: "8.5", EOL: &future}}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetSiteRepo(ctx, "test", host.ID, siteRoot, "git@github.com:acme/example.com.git"); err != nil {
		t.Fatal(err)
	}
	asRole(e, host.OrgID, store.RoleOperator)

	// The site page links it (the fixture's site runs PHP 8.3).
	page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String()
	if !strings.Contains(page, `href="/hosts/acme/app-01/handoff/php?root=%2Fhome%2Fforge%2Fexample.com"`) || !strings.Contains(page, ">Hand off PHP upgrade</a>") {
		t.Error("the site page doesn't link the PHP hand-off")
	}

	// Stage 1 defaults to the newest supported PHP, and offers the others.
	_, shown := phpConfirm(t, e, "")
	if !strings.Contains(shown, "Make `acme/example.com` run on PHP 8.5 as well as PHP 8.3") || !strings.Contains(shown, "`config.platform.php` to `8.3`") {
		t.Errorf("stage 1 prompt:\n%s", shown)
	}
	cp := e.get("/hosts/acme/app-01/handoff/php?root="+url.QueryEscape(siteRoot), signedIn(e)).Body.String()
	if !strings.Contains(cp, `<option value="8.4">PHP 8.4</option>`) || strings.Contains(cp, `value="8.2"`) || strings.Contains(cp, "pr-bot") {
		t.Error("the target picker is wrong, or offers a Discord agent")
	}

	// A target that isn't newer and supported sends nothing.
	cp = e.get("/hosts/acme/app-01/handoff/php?to=8.2&root="+url.QueryEscape(siteRoot), signedIn(e)).Body.String()
	if !strings.Contains(cp, "PHP 8.2 isn&#39;t a supported version newer than 8.3") || strings.Contains(cp, "handoff-send") {
		t.Error("an older target isn't refused")
	}

	// Send with the target a change-management tool's link named.
	form, shown := phpConfirm(t, e, "&stage=compat&to=8.4")
	if !strings.Contains(shown, "PHP 8.4 as well as PHP 8.3") {
		t.Fatalf("prompt for 8.4:\n%s", shown)
	}
	tampered := url.Values{}
	for k, v := range form {
		tampered[k] = v
	}
	tampered.Set("digest", strings.Repeat("0", 64))
	if w := e.post("/hosts/acme/app-01/handoff/php", tampered, signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict || len(fs.started()) != 0 {
		t.Fatalf("a changed digest: %d, %d started", w.Code, len(fs.started()))
	}
	w := e.post("/hosts/acme/app-01/handoff/php", form, signedIn(e), origin(e.baseURL))
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasSuffix(loc, "&handoff=sent&thread="+testThread) {
		t.Fatalf("send: %d %s", w.Code, loc)
	}
	reqs := fs.started()
	if len(reqs) != 1 || len(fd.sent()) != 0 {
		t.Fatalf("started %d threads, posted %d", len(reqs), len(fd.sent()))
	}
	if r := reqs[0]; !strings.HasPrefix(r.Prompt, shown+"\n\n") || !strings.Contains(r.Prompt, `"format": "heimdall.php-upgrade/v1"`) ||
		r.Project != testProjects[0].ID || !strings.HasPrefix(r.Title, "Heimdall PHP 8.4 · acme/example.com · ") {
		t.Errorf("thread request %+v", r)
	}
	if a := handoffAudits(e); len(a) != 1 || !strings.Contains(a[0], `"kind":"php"`) || !strings.Contains(a[0], `"to":"8.4"`) || !strings.Contains(a[0], `"stage":"compat"`) {
		t.Errorf("audit: %q", a)
	}
	// Once per few minutes.
	form2, _ := phpConfirm(t, e, "&to=8.4")
	if w := e.post("/hosts/acme/app-01/handoff/php", form2, signedIn(e), origin(e.baseURL)); w.Code != http.StatusTooManyRequests || len(fs.started()) != 1 {
		t.Errorf("a second send right away: %d", w.Code)
	}

	// Stage 2: the minimum is the PHP the sites run; one that's newer
	// than a site's is refused.
	_, shown = phpConfirm(t, e, "&stage=floor")
	if !strings.Contains(shown, "Make PHP 8.3 the minimum for `acme/example.com`") || !strings.Contains(shown, "Set `require.php` to `^8.3`") {
		t.Errorf("floor prompt:\n%s", shown)
	}
	cp = e.get("/hosts/acme/app-01/handoff/php?stage=floor&to=8.4&root="+url.QueryEscape(siteRoot), signedIn(e)).Body.String()
	if !strings.Contains(cp, "Not every site on this repository runs PHP 8.4 yet") || strings.Contains(cp, "handoff-send") {
		t.Error("a floor above a site's PHP isn't refused")
	}

	// Amp only; operators only; nonsense refused.
	for _, q := range []string{"&agent=pr-bot", "&stage=nope", "&to=8.x"} {
		if w := e.get("/hosts/acme/app-01/handoff/php?root="+url.QueryEscape(siteRoot)+q, signedIn(e)); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	asRole(e, host.OrgID, store.RoleViewer)
	if w := e.get("/hosts/acme/app-01/handoff/php?root="+url.QueryEscape(siteRoot), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
	if page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String(); strings.Contains(page, "Hand off PHP upgrade") {
		t.Error("viewer sees the button")
	}
}

func TestPHPHandoffNeedsAmp(t *testing.T) {
	t.Parallel()
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)
	if page := e.get(siteURL("acme", "app-01", siteRoot), signedIn(e)).Body.String(); strings.Contains(page, "Hand off PHP upgrade") {
		t.Error("button shown with no Amp agent")
	}
	if w := e.get("/hosts/acme/app-01/handoff/php?root="+url.QueryEscape(siteRoot), signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("page with no Amp agent: %d", w.Code)
	}
}
