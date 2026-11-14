// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/secret"
	"github.com/realmwatch/heimdall/internal/store"
)

// Obviously fake keys: never a real one in a test.
const (
	aliceKey = "sgamp_test_0000000000000000000000alice"
	bobKey   = "sgamp_test_0000000000000000000000bob1"
)

const personalThread = "T-87654321-aaaa-bbbb-cccc-000000000000"

// fakePersonal stands in for cmd/heimdall's personalAmp: one fakeStarter
// per user, recording which key each was made with.
type fakePersonal struct {
	mu       sync.Mutex
	starters map[int64]*fakeStarter
	keys     map[int64][]string // keys Starter and Check were given, by user
	checkErr error
	projects []handoff.Project // the users' projects (nil: testProjects)
}

func (f *fakePersonal) Starter(_ handoff.Agent, userID int64, key string) handoff.Starter {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.starters == nil {
		f.starters, f.keys = map[int64]*fakeStarter{}, map[int64][]string{}
	}
	f.keys[userID] = append(f.keys[userID], key)
	if f.starters[userID] == nil {
		f.starters[userID] = &fakeStarter{id: personalThread, projects: f.projects}
	}
	return f.starters[userID]
}

func (f *fakePersonal) Check(_ context.Context, _ handoff.Agent, userID int64, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		f.starters, f.keys = map[int64]*fakeStarter{}, map[int64][]string{}
	}
	f.keys[userID] = append(f.keys[userID], "check:"+key)
	return f.checkErr
}

func (f *fakePersonal) started(userID int64) []handoff.ThreadRequest {
	f.mu.Lock()
	s := f.starters[userID]
	f.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.started()
}

func (f *fakePersonal) keysOf(userID int64) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys[userID]...)
}

func testSecrets(t *testing.T, b byte) *secret.Sealer {
	t.Helper()
	s, err := secret.NewSealer(bytes.Repeat([]byte{b}, secret.SealKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ampKeyEnv is a hub with agents, personal keys (with a secrets key when
// secrets), and the acme org with app-01's sites on acme/example.com.
// The viewer is alice, a local operator in acme.
func ampKeyEnv(t *testing.T, secrets bool, agents ...handoff.Agent) (*env, *fakePersonal, store.IngestHost, int64) {
	t.Helper()
	fp := &fakePersonal{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Agents, c.PersonalAmp = agents, fp
		if secrets {
			c.Secrets = testSecrets(t, 1)
		}
	})
	host := e.seedSites()
	if err := e.st.SetSiteRepo(t.Context(), "test", host.ID, siteRoot, "https://github.com/acme/example.com"); err != nil {
		t.Fatal(err)
	}
	uid := e.addUser("alice@example.com")
	e.as(uid, "alice@example.com", host.OrgID, store.RoleOperator)
	return e, fp, host, uid
}

func (e *env) addUser(email string) int64 {
	e.t.Helper()
	uid, err := e.st.CreateLocalUser(e.t.Context(), "test", email, strings.Split(email, "@")[0], false, "$argon2id$x", []byte("0123456789abcdefghij"))
	if err != nil {
		e.t.Fatal(err)
	}
	return uid
}

func (e *env) as(uid int64, email string, orgID int64, role store.Role) {
	e.auth.viewer = &auth.Viewer{UserID: uid, Email: email, DisplayName: strings.Split(email, "@")[0], Kind: "local",
		SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgID: role}}}
}

// saveAmpKey confirms it's the viewer (a fresh step-up code) and saves key.
func (e *env) saveAmpKey(key, code string) *http.Response {
	e.t.Helper()
	if w := e.post("/account/amp/confirm", csrfForm("stepup_code", code), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		e.t.Fatalf("confirm: %d\n%s", w.Code, w.Body.String())
	}
	return e.post("/account/amp/save", csrfForm("key", key), signedIn(e), origin(e.baseURL)).Result()
}

// auditDetails are every audit entry's action and detail JSON.
func (e *env) auditDetails() []string {
	e.t.Helper()
	db, err := sql.Open("sqlite", e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(e.t.Context(), `SELECT action, detail FROM audit_log ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a, d string
		if err := rows.Scan(&a, &d); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a+" "+d)
	}
	return out
}

func TestAmpKeyPageHidden(t *testing.T) {
	t.Parallel()
	fd := newFakeDiscord(t)
	// No Amp agent: no page, no link.
	e, _, _, _ := ampKeyEnv(t, true, fd.agent("pr-bot", testBotID))
	if w := e.get("/account/amp", signedIn(e)); w.Code != http.StatusNotFound || strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/account/amp"`) {
		t.Errorf("without an Amp agent: %d", w.Code)
	}
	if w := e.post("/account/amp/save", csrfForm("key", aliceKey), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("save without an Amp agent: %d", w.Code)
	}

	// No secrets key: operators get nothing; an admin gets the page, saying
	// how to turn keys on, with no form.
	e, _, host, uid := ampKeyEnv(t, false, handoff.Agent{Name: "amp", Starter: &fakeStarter{id: testThread}})
	if w := e.get("/account/amp", signedIn(e)); w.Code != http.StatusNotFound || strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/account/amp"`) {
		t.Errorf("operator without a secrets key: %d", w.Code)
	}
	e.auth.viewer.IsAdmin = true
	page := html.UnescapeString(e.get("/account/amp", signedIn(e)).Body.String())
	if !strings.Contains(page, "Not available on this hub") || !strings.Contains(page, "LoadCredential=heimdall-secrets") ||
		strings.Contains(page, `name="key"`) || strings.Contains(page, "/account/amp/confirm") {
		t.Errorf("admin without a secrets key:\n%s", page)
	}
	if w := e.post("/account/amp/confirm", csrfForm("stepup_code", "240001"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("confirm without a secrets key: %d", w.Code)
	}
	// And a hand-off has no choice: the service account.
	e.as(uid, "alice@example.com", host.OrgID, store.RoleOperator)
	cp := html.UnescapeString(e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String())
	if strings.Contains(cp, `name="as"`) || strings.Contains(cp, "save your own Amp key") || !strings.Contains(cp, "<strong>The service account</strong>") {
		t.Errorf("confirm page without a secrets key:\n%s", cp)
	}
}

func TestAmpKeySave(t *testing.T) {
	t.Parallel()
	e, fp, host, uid := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: &fakeStarter{id: testThread}})
	if !strings.Contains(e.get("/", signedIn(e)).Body.String(), `href="/account/amp"`) {
		t.Error("no Amp key link")
	}
	page := html.UnescapeString(e.get("/account/amp", signedIn(e)).Body.String())
	if !strings.Contains(page, "Your Amp key") || !strings.Contains(page, "your own Amp thread list") || !strings.Contains(page, "anyone with root on the hub") && !strings.Contains(page, "Anyone with root on the hub") ||
		strings.Contains(page, `name="key"`) || !strings.Contains(page, `action="/account/amp/confirm"`) {
		t.Fatalf("page before confirming:\n%s", page)
	}

	// Saving needs a fresh step-up, even with the hub's setting off…
	if w := e.post("/account/amp/save", csrfForm("key", aliceKey), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account/amp?ok=expired#key" {
		t.Errorf("save without a step-up: %d %s", w.Code, w.Header().Get("Location"))
	}
	w := e.post("/account/amp/confirm", csrfForm(), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Saving your Amp key") || !strings.Contains(w.Body.String(), `name="stepup_code"`) {
		t.Errorf("confirm without a code: %d", w.Code)
	}
	if w := e.post("/account/amp/confirm", csrfForm("stepup_code", "999999"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusUnauthorized {
		t.Errorf("confirm with a bad code: %d", w.Code)
	}
	// …and the CSRF token.
	if w := e.post("/account/amp/confirm", url.Values{"stepup_code": {"240001"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("confirm without CSRF: %d", w.Code)
	}
	if _, ok, _ := e.st.AmpKeyOf(t.Context(), uid); ok {
		t.Fatal("saved without a step-up")
	}
	if w := e.post("/account/amp/confirm", csrfForm("stepup_code", "240001"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d", w.Code)
	}
	if !strings.Contains(e.get("/account/amp", signedIn(e)).Body.String(), `type="password" name="key"`) {
		t.Error("no key form after confirming")
	}
	if w := e.post("/account/amp/save", url.Values{"key": {aliceKey}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("save without CSRF: %d", w.Code)
	}
	for bad, want := range map[string]string{
		"short":                               "why=short&n=5",
		strings.Repeat("x", 513):              "why=long&n=513",
		"sgamp_test_00000000000\x01000":       "why=char&n=23",
		"sgamp_test_0000000000\u00e90000":     "why=char&n=22",
		"sgamp_ has spaces in it\u200b\u00a0": "why=short&n=19",
	} {
		w := e.post("/account/amp/save", csrfForm("key", bad), signedIn(e), origin(e.baseURL))
		if loc := w.Header().Get("Location"); loc != "/account/amp?ok=invalid&"+want+"#key" {
			t.Errorf("saved %q: %s", bad, loc)
		}
	}
	page = e.get("/account/amp?ok=invalid&why=char&n=23", signedIn(e)).Body.String()
	if !strings.Contains(page, "Character 23 of what you pasted") {
		t.Error("no reason for a refused key")
	}
	if page := e.get("/account/amp?ok=invalid&why=char&n=%3Cb%3E", signedIn(e)).Body.String(); !strings.Contains(page, "That doesn&#39;t look like an API key") {
		t.Error("a bad n isn't the generic notice")
	}
	// Copying adds spaces, line breaks and invisible characters: they're dropped.
	wrapped := "  " + aliceKey[:10] + "\n" + aliceKey[10:20] + " \u200b" + aliceKey[20:] + "\u00a0\n"
	if w := e.post("/account/amp/save", csrfForm("key", wrapped), signedIn(e), origin(e.baseURL)); w.Header().Get("Location") != "/account/amp?ok=saved" {
		t.Fatalf("save: %d %s", w.Code, w.Header().Get("Location"))
	}
	k, ok, err := e.st.AmpKeyOf(t.Context(), uid)
	if err != nil || !ok || k.Hint != "lice" || bytes.Contains(k.Sealed, []byte(aliceKey)) {
		t.Fatalf("stored %+v %v %v", k, ok, err)
	}
	if b, err := testSecrets(t, 1).Open(ampKeyPurpose, uid, k.Sealed); err != nil || string(b) != aliceKey {
		t.Errorf("sealed for alice: %q %v", b, err)
	}

	// Saved: the date and the last four characters, never the key.
	page = html.UnescapeString(e.get("/account/amp?ok=saved", signedIn(e)).Body.String())
	if !strings.Contains(page, "Saved. Use Test") || !strings.Contains(page, testNow.Format("Jan 2, 2006")) || !strings.Contains(page, "ends <code>…lice</code>") ||
		!strings.Contains(page, `action="/account/amp/test"`) || !strings.Contains(page, `action="/account/amp/remove"`) {
		t.Errorf("saved page:\n%s", page)
	}
	if strings.Contains(page, aliceKey) {
		t.Error("the page shows the key")
	}

	// Test runs the CLI with the key, and records it worked.
	w = e.post("/account/amp/test", csrfForm(), signedIn(e), origin(e.baseURL))
	if res := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(res, "It works") || strings.Contains(res, aliceKey) {
		t.Errorf("test: %d\n%s", w.Code, res)
	}
	if got := fp.keysOf(uid); len(got) != 1 || got[0] != "check:"+aliceKey {
		t.Errorf("checked with %q", got)
	}
	if k, _, _ := e.st.AmpKeyOf(t.Context(), uid); k.TestedAt.IsZero() {
		t.Error("the test wasn't recorded")
	}
	// A failure shows the CLI's reason, escaped and with the key masked.
	fp.checkErr = errors.New("exit status 1: <b>unauthorized</b> for " + aliceKey)
	w = e.post("/account/amp/test", csrfForm(), signedIn(e), origin(e.baseURL))
	if res := w.Body.String(); !strings.Contains(res, "The test failed") || !strings.Contains(res, "&lt;b&gt;unauthorized&lt;/b&gt; for [key]") || strings.Contains(res, aliceKey) {
		t.Errorf("failed test:\n%s", res)
	}

	// Another user sees no key, and can't test or use alice's.
	bob := e.addUser("bob@example.com")
	e.as(bob, "bob@example.com", host.OrgID, store.RoleOperator)
	page = e.get("/account/amp", signedIn(e)).Body.String()
	if strings.Contains(page, "lice") || strings.Contains(page, "Saved key") {
		t.Errorf("bob sees alice's key:\n%s", page)
	}
	if w := e.post("/account/amp/test", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusBadRequest || len(fp.keysOf(bob)) != 0 {
		t.Errorf("bob's test: %d", w.Code)
	}
	if w := e.post("/account/amp/remove", csrfForm(), signedIn(e), origin(e.baseURL)); w.Header().Get("Location") != "/account/amp?ok=none" {
		t.Errorf("bob's remove: %s", w.Header().Get("Location"))
	}
	if _, ok, _ := e.st.AmpKeyOf(t.Context(), uid); !ok {
		t.Fatal("bob removed alice's key")
	}

	// Alice removes hers.
	e.as(uid, "alice@example.com", host.OrgID, store.RoleOperator)
	if w := e.post("/account/amp/remove", csrfForm(), signedIn(e), origin(e.baseURL)); w.Header().Get("Location") != "/account/amp?ok=removed" {
		t.Errorf("remove: %s", w.Header().Get("Location"))
	}
	if _, ok, _ := e.st.AmpKeyOf(t.Context(), uid); ok {
		t.Error("not removed")
	}

	// The audit log has the save and the removal, never the key.
	var actions []string
	for _, d := range e.auditDetails() {
		if strings.Contains(d, aliceKey) || strings.Contains(d, "lice") {
			t.Errorf("audit carries the key: %s", d)
		}
		if strings.HasPrefix(d, "user.amp_key") {
			actions = append(actions, strings.Fields(d)[0])
		}
	}
	if strings.Join(actions, " ") != "user.amp_key_set user.amp_key_removed" {
		t.Errorf("audit: %v", actions)
	}
}

// A key that doesn't start sgamp_ is saved, with a note.
func TestAmpKeyPrefixNote(t *testing.T) {
	t.Parallel()
	e, _, _, _ := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: &fakeStarter{id: testThread}})
	w := e.saveAmpKey("test_key_0000000000000000000000", "240001")
	if loc := w.Header.Get("Location"); loc != "/account/amp?ok=saved&note=prefix" {
		t.Fatalf("save: %s", loc)
	}
	if !strings.Contains(e.get("/account/amp?ok=saved&note=prefix", signedIn(e)).Body.String(), "usually start with sgamp_") {
		t.Error("no note")
	}
}

// A key sealed with another secrets key (the key was replaced) is as good
// as none: hand-offs run as the service account, and the page says so.
func TestAmpKeyUnreadable(t *testing.T) {
	t.Parallel()
	svc := &fakeStarter{id: testThread}
	e, fp, _, uid := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: svc})
	if err := e.st.SetAmpKey(t.Context(), "test", uid, testSecrets(t, 2).Seal(ampKeyPurpose, uid, []byte(aliceKey)), "lice", testNow); err != nil {
		t.Fatal(err)
	}
	if page := html.UnescapeString(e.get("/account/amp", signedIn(e)).Body.String()); !strings.Contains(page, "can't be read with the hub's current secrets key") {
		t.Errorf("page:\n%s", page)
	}
	cp := e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String()
	if strings.Contains(cp, `name="as" value="personal"`) || len(fp.keysOf(uid)) != 0 {
		t.Errorf("offered an unreadable key")
	}
}

// sendForm is the confirm page's send form, ready to post.
func sendForm(t *testing.T, page string) url.Values {
	t.Helper()
	i := strings.Index(page, `class="actions handoff-send"`)
	if i < 0 {
		t.Fatalf("no send form:\n%s", page)
	}
	form := page[i:]
	form = form[:strings.Index(form, "</form>")]
	f := url.Values{}
	for _, m := range hiddenRe.FindAllStringSubmatch(form, -1) {
		f.Add(m[1], html.UnescapeString(m[2]))
	}
	return f
}

func handoffAudits(e *env) []string {
	var out []string
	for _, d := range e.auditDetails() {
		if strings.HasPrefix(d, "handoff.send ") {
			out = append(out, d)
		}
	}
	return out
}

// With a key of their own, a viewer's Amp hand-off runs as them by
// default; they can choose the service account instead.
func TestHandoffAsPersonal(t *testing.T) {
	t.Parallel()
	svc := &fakeStarter{id: testThread}
	e, fp, _, uid := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: svc})

	// Without a key: as today, the service account, and a pointer to
	// saving one.
	cp := html.UnescapeString(e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String())
	if strings.Contains(cp, `name="as" value="personal"`) || !strings.Contains(cp, `<a href="/account/amp">save your own Amp key</a>`) {
		t.Errorf("confirm page without a key:\n%s", cp)
	}
	if w := e.saveAmpKey(aliceKey, "240001"); w.Header.Get("Location") != "/account/amp?ok=saved" {
		t.Fatalf("save: %s", w.Header.Get("Location"))
	}

	w := e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e))
	cp = html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !strings.Contains(cp, `<input type="radio" name="as" value="personal" checked data-autosubmit>`) ||
		!strings.Contains(cp, "Start Amp thread as you") || !strings.Contains(cp, "started with your own Amp API key: it's in your Amp thread list, uses your Amp plan's included usage") {
		t.Fatalf("confirm page with a key:\n%s", cp)
	}
	if strings.Contains(cp, aliceKey) {
		t.Fatal("the confirm page shows the key")
	}
	personalForm := sendForm(t, cp)
	if personalForm.Get("as") != asPersonal {
		t.Fatalf("send form: %v", personalForm)
	}

	// The service account's page: another digest.
	cpSvc := html.UnescapeString(e.get(withAs(handoffURL("acme", "app-01", siteRoot, "amp"), asService), signedIn(e)).Body.String())
	svcForm := sendForm(t, cpSvc)
	if svcForm.Get("as") != asService || svcForm.Get("digest") == personalForm.Get("digest") || strings.Contains(cpSvc, "Start Amp thread as you") ||
		!strings.Contains(cpSvc, `<input type="radio" name="as" value="service" checked data-autosubmit>`) {
		t.Fatalf("service account's page: %v", svcForm)
	}
	// Switching who it runs as after confirming sends nothing.
	switched := url.Values{}
	for k, v := range personalForm {
		switched[k] = v
	}
	switched.Set("as", asService)
	if w := e.post("/hosts/acme/app-01/handoff", switched, signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict || len(svc.started()) != 0 || len(fp.started(uid)) != 0 {
		t.Fatalf("switched run-as: %d", w.Code)
	}

	// Sent as alice: her starter, with her key; the service account's
	// starts nothing.
	w = e.post("/hosts/acme/app-01/handoff", personalForm, signedIn(e), origin(e.baseURL))
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasSuffix(loc, "&handoff=sent&thread="+personalThread) {
		t.Fatalf("send as alice: %d %s", w.Code, loc)
	}
	if reqs := fp.started(uid); len(reqs) != 1 || reqs[0].Project != testProjects[0].ID || len(svc.started()) != 0 {
		t.Fatalf("started as alice %d, as the service account %d", len(fp.started(uid)), len(svc.started()))
	}
	for _, k := range fp.keysOf(uid) {
		if k != aliceKey {
			t.Errorf("started with key %q", k)
		}
	}
	audits := handoffAudits(e)
	if len(audits) != 1 || !strings.Contains(audits[0], `"as":"personal"`) || strings.Contains(audits[0], aliceKey) {
		t.Errorf("audit: %q", audits)
	}
}

func TestHandoffAsService(t *testing.T) {
	t.Parallel()
	svc := &fakeStarter{id: testThread}
	e, fp, _, uid := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: svc})
	e.saveAmpKey(aliceKey, "240001")
	cp := html.UnescapeString(e.get(withAs(handoffURL("acme", "app-01", siteRoot, "amp"), asService), signedIn(e)).Body.String())
	w := e.post("/hosts/acme/app-01/handoff", sendForm(t, cp), signedIn(e), origin(e.baseURL))
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasSuffix(loc, "&handoff=sent&thread="+testThread) {
		t.Fatalf("send: %d %s", w.Code, loc)
	}
	if len(svc.started()) != 1 || len(fp.started(uid)) != 0 {
		t.Errorf("started as the service account %d, as alice %d", len(svc.started()), len(fp.started(uid)))
	}
	if a := handoffAudits(e); len(a) != 1 || !strings.Contains(a[0], `"as":"service"`) {
		t.Errorf("audit: %q", a)
	}
}

// A personal start that fails is logged and audited like any other, with
// a generic notice; the key is never in either.
func TestHandoffAsPersonalFails(t *testing.T) {
	t.Parallel()
	e, fp, _, uid := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: &fakeStarter{id: testThread}})
	e.saveAmpKey(aliceKey, "240001")
	cp := html.UnescapeString(e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String())
	f := sendForm(t, cp)
	fp.starters[uid].err = errors.New("amp: exit status 1: unauthorized")
	fp.starters[uid].id = ""
	w := e.post("/hosts/acme/app-01/handoff", f, signedIn(e), origin(e.baseURL))
	if loc := w.Header().Get("Location"); !strings.HasSuffix(loc, "&handoff=failed") {
		t.Fatalf("send: %s", loc)
	}
	if a := handoffAudits(e); len(a) != 1 || !strings.Contains(a[0], `"as":"personal"`) || !strings.Contains(a[0], `"ok":false`) || strings.Contains(a[0], "unauthorized") {
		t.Errorf("audit: %q", a)
	}
}

// A user's projects are their own: the picked project is used when they
// can see it, else the one matching the repository.
func TestHandoffAsPersonalProjects(t *testing.T) {
	t.Parallel()
	svc := &fakeStarter{id: testThread}
	e, fp, host, _ := ampKeyEnv(t, true, handoff.Agent{Name: "amp", Starter: svc})
	// The service account's operators picked a project alice can't see.
	hidden := handoff.Project{ID: "22222222-0000-0000-0000-000000000001", Namespace: "acme", Name: "svc-only", RepositoryURL: "https://github.com/acme/example.com"}
	svc.projects = append([]handoff.Project{hidden}, testProjects...)
	fp.projects = testProjects
	if err := e.st.SetAmpProject(t.Context(), "test", host.OrgID, "github.com/acme/example.com", "amp", hidden.ID, testNow); err != nil {
		t.Fatal(err)
	}
	e.saveAmpKey(aliceKey, "240001")
	cp := html.UnescapeString(e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String())
	if !strings.Contains(cp, "<strong>acme/example</strong> <span class=\"muted small\">matched by repository</span>") || strings.Contains(cp, "svc-only") {
		t.Errorf("alice's project:\n%s", cp)
	}
	// The service account keeps its pick.
	cp = html.UnescapeString(e.get(withAs(handoffURL("acme", "app-01", siteRoot, "amp"), asService), signedIn(e)).Body.String())
	if !strings.Contains(cp, "<strong>acme/svc-only</strong> <span class=\"muted small\">picked for this repository</span>") {
		t.Errorf("the service account's project:\n%s", cp)
	}
	// Nothing alice can see: the page says it's her projects.
	fp.mu.Lock()
	fp.starters = nil
	fp.projects = testProjects[1:]
	fp.mu.Unlock()
	cp = html.UnescapeString(e.get(handoffURL("acme", "app-01", siteRoot, "amp"), signedIn(e)).Body.String())
	if !strings.Contains(cp, "None of your Amp projects uses this repository") || strings.Contains(cp, "Start Amp thread") {
		t.Errorf("no project of alice's:\n%s", cp)
	}
}

// One choice for the whole batch.
func TestHandoffBatchAsPersonal(t *testing.T) {
	t.Parallel()
	svc := &fakeStarter{id: testThread}
	fp := &fakePersonal{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Agents, c.PersonalAmp, c.Secrets = []handoff.Agent{{Name: "amp", Starter: svc}}, fp, testSecrets(t, 1)
	})
	web1, r1 := e.seedComposerHost("acme", "web-01", "a.example.com", "b.example.com")
	if err := e.st.SetDetectedSiteRepos(t.Context(), web1.ID, map[string]string{r1[0]: "https://github.com/acme/a", r1[1]: "https://github.com/acme/b"}); err != nil {
		t.Fatal(err)
	}
	uid := e.addUser("alice@example.com")
	e.as(uid, "alice@example.com", web1.OrgID, store.RoleOperator)
	e.saveAmpKey(aliceKey, "240001")
	q := url.Values{"back": {"/"}}
	for _, r := range r1 {
		q.Add("o", "acme")
		q.Add("h", "web-01")
		q.Add("r", r)
	}
	page := html.UnescapeString(e.get("/handoff/batch?"+q.Encode(), signedIn(e)).Body.String())
	if !strings.Contains(page, `<input type="radio" name="as" value="personal" checked data-autosubmit>`) || !strings.Contains(page, "Start 2 Amp threads as you") {
		t.Fatalf("batch page:\n%s", page)
	}
	f := batchForm(t, page)
	f.Set("agent", "amp")
	if f.Get("as") != asPersonal {
		t.Fatalf("form: %v", f)
	}
	// Switched to the service account after confirming: nothing is sent.
	sw := url.Values{}
	for k, v := range f {
		sw[k] = v
	}
	sw.Set("as", asService)
	if w := e.post("/handoff/batch", sw, signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict || len(svc.started())+len(fp.started(uid)) != 0 {
		t.Fatalf("switched: %d", w.Code)
	}
	w := e.post("/handoff/batch", f, signedIn(e), origin(e.baseURL))
	if res := html.UnescapeString(w.Body.String()); w.Code != http.StatusOK || !strings.Contains(res, "Started 2 of 2 Amp threads.") {
		t.Fatalf("send: %d\n%s", w.Code, res)
	}
	if len(fp.started(uid)) != 2 || len(svc.started()) != 0 {
		t.Errorf("started as alice %d, as the service account %d", len(fp.started(uid)), len(svc.started()))
	}
	for _, a := range handoffAudits(e) {
		if !strings.Contains(a, `"as":"personal"`) {
			t.Errorf("audit: %s", a)
		}
	}
}
