// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestPlansFlow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	// The fake viewer is user 1; plans record who created and ticked them.
	if _, err := e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12")); err != nil {
		t.Fatal(err)
	}
	form := func(kv ...string) url.Values {
		v := url.Values{"csrf": {auth.CSRFToken(goodToken)}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	w := e.post("/plans", form("name", "October", "org", "acme"), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/plans/1" {
		t.Fatalf("create: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := e.post("/plans/1/add", form("hostref", "acme/web-01", "batch", "2"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	if w := e.post("/plans/1/done", form("org", "acme", "host", "web-01"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("done: %d", w.Code)
	}
	body := e.get("/plans/1", signedIn(e)).Body.String()
	if !strings.Contains(body, "web-01") || !strings.Contains(body, "waiting for a clean check-in") {
		t.Errorf("plan page:\n%s", body)
	}
	if !strings.Contains(e.get("/plans", signedIn(e)).Body.String(), "October") {
		t.Error("plans list missing the plan")
	}
	// CSRF is required like every other POST.
	if w := e.post("/plans/1/undo", url.Values{"org": {"acme"}, "host": {"web-01"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("no csrf: %d", w.Code)
	}
}

func TestPlansRespectScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	// The fake viewer is user 1; plans record who created and ticked them.
	if _, err := e.st.CreateLocalUser(t.Context(), "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreatePlan(t.Context(), "test", 0, "acme", "acme plan"); err != nil {
		t.Fatal(err)
	}
	orgs, _ := e.st.ListOrgs(t.Context())
	// A viewer can see the plan but not change it.
	e.auth.viewer = &auth.Viewer{UserID: 1, Email: "v@example.com", SessionToken: goodToken,
		Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleViewer}}}
	if w := e.get("/plans/1", signedIn(e)); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "mark done") {
		t.Errorf("viewer page: %d", w.Code)
	}
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "hostref": {"acme/web-01"}}
	if w := e.post("/plans/1/add", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("viewer add: %d", w.Code)
	}
	// Someone without access to acme doesn't learn the plan exists.
	e.auth.viewer.Scope = store.Scope{Orgs: map[int64]store.Role{}}
	if w := e.get("/plans/1", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("no access: %d", w.Code)
	}
}

func TestPlanAddsSeveralHosts(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	ctx := t.Context()
	if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", "web-02", nil); err != nil {
		t.Fatal(err)
	}
	e.seedOrg("other", "db-01")
	if _, err := e.st.CreatePlan(ctx, "test", 0, "acme", "October"); err != nil {
		t.Fatal(err)
	}
	add := func(batch string, refs ...string) int {
		f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "batch": {batch}, "hostref": refs}
		return e.post("/plans/1/add", f, signedIn(e), origin(e.baseURL)).Code
	}
	inPlan := func() map[string]int {
		items, err := e.st.PlanItems(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, it := range items {
			got[it.Host.Name] = it.Batch
		}
		return got
	}

	page := e.get("/plans/1", signedIn(e)).Body.String()
	for _, want := range []string{`value="acme/web-01" data-bulk-row`, `value="acme/web-02" data-bulk-row`, "data-bulk-all"} {
		if !strings.Contains(page, want) {
			t.Errorf("add form missing %q", want)
		}
	}
	if code := add("1"); code != http.StatusBadRequest {
		t.Errorf("nothing ticked: %d", code)
	}
	// One bad host means nothing is added.
	if code := add("1", "acme/web-01", "other/db-01"); code != http.StatusBadRequest {
		t.Errorf("host from another org: %d", code)
	}
	if code := add("1", "acme/web-01", "acme/missing"); code != http.StatusBadRequest {
		t.Errorf("unknown host: %d", code)
	}
	if got := inPlan(); len(got) != 0 {
		t.Errorf("rejected adds left hosts behind: %v", got)
	}
	if code := add("3", "acme/web-01", "acme/web-02", "acme/web-01"); code != http.StatusSeeOther {
		t.Fatalf("add both: %d", code)
	}
	if got := inPlan(); len(got) != 2 || got["web-01"] != 3 || got["web-02"] != 3 {
		t.Errorf("plan items: %v", got)
	}
	if strings.Contains(e.get("/plans/1", signedIn(e)).Body.String(), `value="acme/web-01"`) {
		t.Error("hosts already in the plan are still offered")
	}
}

// A plan links each batch's hosts that aren't done to the change tool, one
// link per batch and org; with action_url off, or for a viewer,
// there's none.
func TestPlanUpdatesLinks(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
	e.seed()
	ctx := t.Context()
	if _, err := e.st.CreateLocalUser(ctx, "test", "admin@example.com", "", true, "$argon2id$x", []byte("secretsecretsecret12")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web-02", "web-03"} {
		if _, _, err := e.st.AddHost(ctx, "test", "acme", "prod", name, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.st.CreatePlan(ctx, "test", 0, "acme", "October"); err != nil {
		t.Fatal(err)
	}
	add := func(batch string, refs ...string) {
		f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "batch": {batch}, "hostref": refs}
		if w := e.post("/plans/1/add", f, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
			t.Fatalf("add: %d", w.Code)
		}
	}
	add("2", "acme/web-03")
	add("1", "acme/web-01", "acme/web-02")
	page := e.get("/plans/1", signedIn(e)).Body.String()
	b1 := `href="https://changes.example.com/propose?action=updates.install&amp;org=acme&amp;host=&amp;hosts=web-01%2Cweb-02" target="_blank" rel="noopener noreferrer">Batch 1: install updates on 2 hosts</a>`
	b2 := `href="https://changes.example.com/propose?action=updates.install&amp;org=acme&amp;host=&amp;hosts=web-03" target="_blank" rel="noopener noreferrer">Batch 2: install updates on 1 host</a>`
	if i, j := strings.Index(page, b1), strings.Index(page, b2); i < 0 || j < i {
		t.Errorf("plan page lacks the batch links in order:\n%s", page)
	}
	// A host marked done drops out of its batch's link.
	if w := e.post("/plans/1/done", url.Values{"csrf": {auth.CSRFToken(goodToken)}, "org": {"acme"}, "host": {"web-01"}}, signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("done: %d", w.Code)
	}
	if page = e.get("/plans/1", signedIn(e)).Body.String(); !strings.Contains(page, `host=&amp;hosts=web-02" target="_blank" rel="noopener noreferrer">Batch 1: install updates on 1 host</a>`) {
		t.Errorf("done host still linked:\n%s", page)
	}
	// A viewer can't propose changes from the plan.
	asRole(e, 1, store.RoleViewer)
	if strings.Contains(e.get("/plans/1", signedIn(e)).Body.String(), "install updates on") {
		t.Error("a viewer gets the links")
	}
}

func TestPlanUpdateLinksChunks(t *testing.T) {
	items := make([]store.PlanItem, actionHostsMax+1)
	for i := range items {
		items[i] = store.PlanItem{Batch: 1, Host: store.IngestHost{OrgSlug: "acme", Name: "web-" + strconv.Itoa(i)}}
	}
	items = append(items, store.PlanItem{Batch: 1, Host: store.IngestHost{OrgSlug: "other", Name: "db-01"}})
	got := planUpdateLinks(ChangeLink{ActionURL: "https://changes.example.com/p?action={action}&org={org}&host={host}&{params}"}, items)
	if len(got) != 3 || got[0].Hosts != actionHostsMax || got[1].Hosts != 1 || got[1].Org != "acme" || got[2].Org != "other" || got[2].URL != "https://changes.example.com/p?action=updates.install&org=other&host=&hosts=db-01" {
		t.Errorf("links %+v", got[1:])
	}
	if planUpdateLinks(ChangeLink{}, items) != nil {
		t.Error("links with action_url off")
	}
}
