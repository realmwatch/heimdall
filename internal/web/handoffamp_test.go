// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/store"
)

const testThread = "T-12345678-aaaa-bbbb-cccc-000000000000"

// fakeStarter stands in for the Amp CLI: it records each thread it's
// asked to start and answers with id, or err.
type fakeStarter struct {
	mu   sync.Mutex
	reqs []handoff.ThreadRequest
	id   string
	err  error
}

func (f *fakeStarter) StartThread(_ context.Context, req handoff.ThreadRequest) (handoff.Thread, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	return handoff.Thread{ID: f.id, URL: handoff.ThreadURL(f.id)}, f.err
}

func (f *fakeStarter) started() []handoff.ThreadRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]handoff.ThreadRequest(nil), f.reqs...)
}

func TestHandoffAmp(t *testing.T) {
	t.Parallel()
	fd := newFakeDiscord(t)
	fs := &fakeStarter{id: testThread}
	e := handoffEnv(t, fd.agent("pr-bot", testBotID), handoff.Agent{Name: "amp", Starter: fs})
	host := e.seedSites()
	asRole(e, host.OrgID, store.RoleOperator)

	// An Amp thread works in the repository: with none known there's
	// nothing to send.
	cp := e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String()
	if !strings.Contains(cp, "this site's isn't known") || strings.Contains(cp, "handoff-send") || strings.Contains(cp, "Start Amp thread") {
		t.Errorf("confirm page without a repository:\n%s", cp)
	}
	if w := e.post("/hosts/acme/app-01/handoff", url.Values{"csrf": {auth.CSRFToken(goodToken)}, "root": {siteRoot}, "agent": {"amp"},
		"request_id": {"0123456789abcdef"}, "digest": {strings.Repeat("0", 64)}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest || len(fs.started()) != 0 {
		t.Fatalf("send without a repository: %d, %d started", w.Code, len(fs.started()))
	}

	if err := e.st.SetSiteRepo(t.Context(), "test", host.ID, siteRoot, "git@github.com:acme/example.com.git"); err != nil {
		t.Fatal(err)
	}
	form, shown := confirm(t, e, "amp")
	cp = html.UnescapeString(e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String())
	for _, want := range []string{"Start Amp thread", "The prompt", "Then, in the prompt: <code>heimdall-handoff-", "Where it goes:</strong> a new Amp thread"} {
		if !strings.Contains(cp, want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}
	if strings.Contains(cp, "Post to Discord") || strings.Contains(cp, "Who it pings") || strings.Contains(shown, "<@") {
		t.Error("an Amp hand-off isn't a Discord message")
	}

	w := e.post("/hosts/acme/app-01/handoff", form, signedIn(e), origin(e.baseURL))
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasSuffix(loc, "&handoff=sent&thread="+testThread) {
		t.Fatalf("send: %d %s", w.Code, loc)
	}
	reqs := fs.started()
	if len(reqs) != 1 || len(fd.sent()) != 0 {
		t.Fatalf("started %d threads, posted %d", len(reqs), len(fd.sent()))
	}
	req := reqs[0]
	if !strings.HasPrefix(req.Prompt, shown+"\n\n") || !strings.Contains(req.Prompt, "```json\n{") ||
		req.Project != "https://github.com/acme/example.com" || !strings.HasPrefix(req.Title, "Heimdall hand-off · acme/example.com · ") {
		t.Errorf("thread request %+v", req)
	}

	// The site page links the thread; an ID that isn't one gets no link.
	page := e.get(siteURL("acme", "app-01", siteRoot)+"&handoff=sent&thread="+testThread, signedIn(e)).Body.String()
	if !strings.Contains(page, `<a href="https://ampcode.com/threads/`+testThread+`" rel="noopener noreferrer">Open the Amp thread ↗</a>`) {
		t.Error("the site page doesn't link the thread")
	}
	page = e.get(siteURL("acme", "app-01", siteRoot)+"&handoff=sent&thread=https://evil.example/x", signedIn(e)).Body.String()
	if strings.Contains(page, "Open the Amp thread") || strings.Contains(page, "evil.example") {
		t.Error("linked a thread that isn't an Amp thread ID")
	}

	rows, err := e.st.AuditFrom(t.Context(), "192.0.2.1", true, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		found = found || r.Action == "handoff.send" && r.OrgID == host.OrgID
	}
	if !found {
		t.Errorf("no handoff.send entry: %+v", rows)
	}
}

func TestHandoffAmpFails(t *testing.T) {
	t.Parallel()
	for name, fs := range map[string]*fakeStarter{
		"error":     {err: errors.New("amp: exit status 1: unauthorized")},
		"no thread": {id: "not-a-thread"},
	} {
		t.Run(name, func(t *testing.T) {
			e := handoffEnv(t, handoff.Agent{Name: "amp", Starter: fs})
			host := e.seedSites()
			asRole(e, host.OrgID, store.RoleOperator)
			if err := e.st.SetSiteRepo(t.Context(), "test", host.ID, siteRoot, "https://github.com/acme/example.com"); err != nil {
				t.Fatal(err)
			}
			form, _ := confirm(t, e, "amp")
			w := e.post("/hosts/acme/app-01/handoff", form, signedIn(e), origin(e.baseURL))
			if loc := w.Header().Get("Location"); !strings.HasSuffix(loc, "&handoff=failed") {
				t.Errorf("send: %d %s", w.Code, loc)
			}
		})
	}
}

// A batch for an Amp agent starts one thread per repository and links
// each; a site with no known repository is left out, and the page says so.
func TestHandoffBatchAmp(t *testing.T) {
	t.Parallel()
	fs := &fakeStarter{id: testThread}
	e := handoffEnv(t, handoff.Agent{Name: "amp", Starter: fs})
	web1, r1 := e.seedComposerHost("acme", "web-01", "a.example.com", "b.example.com")
	_, r2 := e.seedComposerHost("acme", "web-02", "c.example.com")
	if err := e.st.SetDetectedSiteRepos(t.Context(), web1.ID, map[string]string{r1[0]: "https://github.com/acme/a", r1[1]: "https://github.com/acme/b"}); err != nil {
		t.Fatal(err)
	}
	asRole(e, web1.OrgID, store.RoleOperator)
	q := url.Values{"back": {"/"}}
	for _, s := range [][2]string{{"web-01", r1[0]}, {"web-01", r1[1]}, {"web-02", r2[0]}} {
		q.Add("o", "acme")
		q.Add("h", s[0])
		q.Add("r", s[1])
	}
	w := e.get("/handoff/batch?"+q.Encode(), signedIn(e))
	page := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || strings.Count(page, `<section class="handoff-item`) != 2 || !strings.Contains(page, "Start 2 Amp threads") ||
		!strings.Contains(page, "1 repository was left out") || strings.Contains(page, "to Discord") {
		t.Fatalf("batch page: %d\n%s", w.Code, page)
	}
	f := batchForm(t, page)
	f.Set("agent", "amp")
	w = e.post("/handoff/batch", f, signedIn(e), origin(e.baseURL))
	res := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !strings.Contains(res, "Started 2 of 2 Amp threads.") || len(fs.started()) != 2 ||
		strings.Count(res, `<a href="https://ampcode.com/threads/`+testThread+`" rel="noopener noreferrer">Amp thread ↗</a>`) != 2 {
		t.Fatalf("send: %d, %d started\n%s", w.Code, len(fs.started()), res)
	}
}
