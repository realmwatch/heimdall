// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/store"
)

// With no agent chosen, a hand-off uses the one marked default, listed
// first in the picker and marked "(default)".
func TestHandoffDefaultAgent(t *testing.T) {
	t.Parallel()
	fd := newFakeDiscord(t)
	other := fd.agent("other-bot", "98765432109876543")
	other.Default = true
	e := handoffEnv(t, fd.agent("pr-bot", testBotID), other)
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)

	cp := e.get(handoffURL("acme", "app-01", siteRoot, ""), signedIn(e)).Body.String()
	def, pr := strings.Index(cp, `<option value="other-bot" selected>other-bot (default)</option>`), strings.Index(cp, `<option value="pr-bot">pr-bot</option>`)
	if !strings.Contains(cp, "Who it pings:</strong> only other-bot") || def < 0 || pr < def {
		t.Errorf("confirm page with no agent chosen:\n%s", cp)
	}
	// Picking another still works.
	cp = e.get(handoffURL("acme", "app-01", siteRoot, "pr-bot"), signedIn(e)).Body.String()
	if !strings.Contains(cp, "Who it pings:</strong> only pr-bot") || !strings.Contains(cp, `<option value="pr-bot" selected>pr-bot</option>`) {
		t.Errorf("confirm page with pr-bot chosen:\n%s", cp)
	}
}

// A repository's default target branch: set and cleared on the confirm
// page by an operator, preselected when no target is chosen, overridable
// for one hand-off without changing it, and ignored (with a note) once it
// isn't one of the sites' branches.
func TestHandoffRepoBranch(t *testing.T) {
	t.Parallel()
	fd := newFakeDiscord(t)
	e := handoffEnv(t, fd.agent("pr-bot", testBotID))
	prod, root := seedThreeBranches(t, e)
	operator := e.auth.viewer
	const key = "github.com/acme/app"
	path := handoffURL("acme", "web-01", root, "")
	stored := func() string {
		t.Helper()
		b, err := e.st.RepoBranch(t.Context(), prod.OrgID, key)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	set := func(f url.Values) *http.Response {
		t.Helper()
		if f.Get("csrf") == "" {
			f.Set("csrf", auth.CSRFToken(goodToken))
		}
		f.Set("root", root)
		f.Set("agent", "pr-bot")
		return e.post("/hosts/acme/web-01/handoff/branch", f, signedIn(e), origin(e.baseURL)).Result()
	}

	// None stored: the default branch, and a branch can be made the default.
	code, f, _, page := handoffFile(t, e, path)
	if code != http.StatusOK || f.Target.Mode != handoff.TargetDefault || strings.Contains(page, "repository default") {
		t.Fatalf("no stored branch: %d %+v", code, f.Target)
	}
	_, _, _, page = handoffFile(t, e, path+"&target=branch:dev")
	if !strings.Contains(html.UnescapeString(page), "Make <code>dev</code> this repository's default") {
		t.Errorf("no way to make dev the default:\n%s", page)
	}

	// Only an operator, with the CSRF token, and only a known branch.
	e.auth.viewer = &auth.Viewer{UserID: 7, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{prod.OrgID: store.RoleViewer}}}
	if r := set(url.Values{"branch": {"dev"}}); r.StatusCode != http.StatusNotFound {
		t.Errorf("viewer: %d", r.StatusCode)
	}
	e.auth.viewer = operator
	if r := set(url.Values{"branch": {"dev"}, "csrf": {"nope"}}); r.StatusCode != http.StatusForbidden {
		t.Errorf("bad CSRF: %d", r.StatusCode)
	}
	for _, bad := range []string{"release", "x;reboot", ""} {
		if r := set(url.Values{"branch": {bad}}); r.StatusCode != http.StatusNotFound {
			t.Errorf("branch %q: %d", bad, r.StatusCode)
		}
	}
	if b := stored(); b != "" {
		t.Fatalf("stored %q before a valid set", b)
	}
	if r := set(url.Values{"branch": {"dev"}}); r.StatusCode != http.StatusSeeOther || !strings.HasSuffix(r.Header.Get("Location"), "#target") {
		t.Fatalf("set: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if b := stored(); b != "dev" {
		t.Fatalf("stored %q", b)
	}
	if at, _ := e.st.LastAuditAt(t.Context(), "handoff.branch"); at.IsZero() {
		t.Error("handoff.branch not audited")
	}
	if sp := e.get(siteURL("acme", "staging-01", "/var/www/staging.example.com"), signedIn(e)).Body.String(); !strings.Contains(sp, "Hand-offs on this repository go to <code>dev</code> by default") {
		t.Error("the site page doesn't show the repository's default target")
	}

	// Preselected, and what's sent is what was shown.
	code, f, form, page := handoffFile(t, e, path)
	page = html.UnescapeString(page)
	if code != http.StatusOK || f.Target.Mode != handoff.TargetBranch || strings.Join(f.Target.Branches, ",") != "dev" ||
		!strings.Contains(page, `value="branch:dev" checked`) || !strings.Contains(page, "<code>dev</code></strong> <span class=\"muted small\">(repository default)") ||
		!strings.Contains(page, "Hand-offs on this repository go to <code>dev</code>") || strings.Contains(page, "this repository's default</button>") {
		t.Fatalf("stored branch: %d %+v\n%s", code, f.Target, page)
	}
	if form.Get("target") != handoff.TargetBranch || form.Get("branch") != "dev" {
		t.Fatalf("send form: %v", form)
	}
	if w := e.post("/hosts/acme/web-01/handoff", form, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("send: %d\n%s", w.Code, w.Body.String())
	}
	if sent := fd.sent(); len(sent) != 1 || !strings.Contains(sent[0]["content"].(string), "one pull request against `dev` (not the default branch)") {
		t.Errorf("sent %v", sent)
	}

	// An explicit target overrides it for this hand-off only.
	if code, f, form, _ := handoffFile(t, e, path+"&target=default"); code != http.StatusOK || f.Target.Mode != handoff.TargetDefault || form.Get("target") != handoff.TargetDefault {
		t.Errorf("override to the default branch: %d %+v", code, f.Target)
	}
	_, f, _, page = handoffFile(t, e, path+"&target=branch:main")
	if f.Target.Mode != handoff.TargetBranch || f.Target.Branches[0] != "main" || !strings.Contains(html.UnescapeString(page), "Make <code>main</code> this repository's default") {
		t.Errorf("override to main: %+v", f.Target)
	}
	if b := stored(); b != "dev" {
		t.Errorf("an override changed the stored branch to %q", b)
	}

	// A stored branch no site is on any more: the default branch, with a note.
	if err := e.st.SetRepoBranch(t.Context(), "test", prod.OrgID, key, "gone", time.Now()); err != nil {
		t.Fatal(err)
	}
	code, f, _, page = handoffFile(t, e, path)
	if code != http.StatusOK || f.Target.Mode != handoff.TargetDefault ||
		!strings.Contains(html.UnescapeString(page), "default to <code>gone</code>, which isn't one of these sites' branches any more") {
		t.Errorf("stale branch: %d %+v\n%s", code, f.Target, page)
	}

	// Cleared: back to the default branch.
	if r := set(url.Values{"clear": {"1"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("clear: %d", r.StatusCode)
	}
	if b := stored(); b != "" {
		t.Errorf("cleared, still %q", b)
	}
	if _, f, _, _ := handoffFile(t, e, path); f.Target.Mode != handoff.TargetDefault {
		t.Errorf("after clearing: %+v", f.Target)
	}
}

// "All N" sends each repository to its default target: the branch made
// its default when it's one of its sites', else its default branch;
// "each branch" still wins.
func TestHandoffBatchRepoBranch(t *testing.T) {
	t.Parallel()
	e, fd, web1, path := batchEnv(t)
	if err := e.st.SetRepoBranch(t.Context(), "test", web1.OrgID, "github.com/acme/b", "dev", time.Now()); err != nil {
		t.Fatal(err)
	}
	page := html.UnescapeString(e.get(path, signedIn(e)).Body.String())
	if !strings.Contains(page, "into <code>dev</code> (repository default)") || strings.Count(page, "into the default branch") != 2 {
		t.Fatalf("batch page:\n%s", page)
	}
	w := e.post("/handoff/batch", batchForm(t, page), signedIn(e), origin(e.baseURL))
	if res := html.UnescapeString(w.Body.String()); w.Code != http.StatusOK || !strings.Contains(res, "Posted 3 of 3.") {
		t.Fatalf("send: %d\n%s", w.Code, res)
	}
	dev := 0
	for _, b := range fd.sent() {
		if strings.Contains(b["content"].(string), "one pull request against `dev`") {
			dev++
		}
	}
	if dev != 1 {
		t.Errorf("%d messages target dev, want 1", dev)
	}
	page = html.UnescapeString(e.get(path+"&target=each", signedIn(e)).Body.String())
	if strings.Contains(page, "(repository default)") || strings.Count(page, " · each branch") != 1 {
		t.Errorf("each branch:\n%s", page)
	}
}
