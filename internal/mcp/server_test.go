// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

type env struct {
	t     *testing.T
	st    *store.Store
	srv   *Server
	token string
	uid   int64
}

func newEnv(t *testing.T) *env {
	st := storetest.New(t)
	ctx := t.Context()
	for _, org := range []string{"acme", "globex"} {
		st.CreateOrg(ctx, "test", org, "")
		st.CreateEnv(ctx, "test", org, "prod", "")
		st.AddHost(ctx, "test", org, "prod", "web-"+org, []string{"web"})
	}
	uid, err := st.CreateLocalUser(ctx, "test", "viewer@example.com", "", false, "$argon2id$x", []byte("secretsecretsecret12"))
	if err != nil {
		t.Fatal(err)
	}
	st.Grant(ctx, "test", "viewer@example.com", "acme", store.RoleViewer)
	token, _, err := st.CreateMCPToken(ctx, "test", uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{BaseURL: "https://hub.example.ts.net", Version: "test"}, st,
		slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, st: st, srv: srv, token: token, uid: uid}
}

func (e *env) do(method, body string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, Path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+e.token)
	r.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

func (e *env) call(method string, params any) map[string]any {
	e.t.Helper()
	p, _ := json.Marshal(params)
	w := e.do("POST", `{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+string(p)+`}`)
	if w.Code != 200 {
		e.t.Fatalf("%s: HTTP %d %s", method, w.Code, w.Body.String())
	}
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func (e *env) tool(name string, args map[string]any) map[string]any {
	e.t.Helper()
	res := e.call("tools/call", map[string]any{"name": name, "arguments": args})
	r, ok := res["result"].(map[string]any)
	if !ok {
		e.t.Fatalf("%s: %v", name, res)
	}
	sc := r["structuredContent"].(map[string]any)
	if sc["note"] != untrustedNote {
		e.t.Error("result missing the untrusted-data note")
	}
	return sc
}

func TestProtocol(t *testing.T) {
	e := newEnv(t)
	init := e.call("initialize", map[string]any{"protocolVersion": "2025-03-26"})
	if v := init["result"].(map[string]any)["protocolVersion"]; v != "2025-03-26" {
		t.Errorf("negotiated %v", v)
	}
	if w := e.do("POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`); w.Code != http.StatusAccepted {
		t.Errorf("notification: %d", w.Code)
	}
	tools := e.call("tools/list", nil)["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 10 {
		t.Errorf("%d tools", len(tools))
	}
	if errObj, _ := e.call("nope", nil)["error"].(map[string]any); errObj["code"] != float64(-32601) {
		t.Errorf("unknown method: %v", errObj)
	}
	if w := e.do("GET", ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", maxRequest) + `"}}`
	if w := e.do("POST", big); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d", w.Code)
	}
}

func TestAuthAndOrigin(t *testing.T) {
	e := newEnv(t)
	tok := e.token
	e.token = "hmd_mcp_" + strings.Repeat("A", 43)
	if w := e.do("POST", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", w.Code)
	}
	e.token = tok
	if w := e.do("POST", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "Origin", "https://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", w.Code)
	}
	if w := e.do("POST", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "Origin", "https://hub.example.ts.net"); w.Code != 200 {
		t.Errorf("own origin: %d", w.Code)
	}
	tokens, _ := e.st.ListMCPTokens(t.Context(), e.uid)
	e.st.RevokeMCPToken(t.Context(), "test", e.uid, tokens[0].ID)
	if w := e.do("POST", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", w.Code)
	}
}

func TestDisabledUserLosesAccess(t *testing.T) {
	e := newEnv(t)
	e.st.SetUserDisabled(t.Context(), "test", "viewer@example.com", true)
	if w := e.do("POST", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("disabled user: %d", w.Code)
	}
}

func TestToolsRespectScope(t *testing.T) {
	e := newEnv(t)
	res := e.tool("search", map[string]any{"query": "host:web"})
	b, _ := json.Marshal(res["data"])
	if !bytes.Contains(b, []byte("web-acme")) || bytes.Contains(b, []byte("web-globex")) {
		t.Errorf("search leaked across orgs: %s", b)
	}
	// Another org's host looks missing, not forbidden.
	res = e.tool("host", map[string]any{"org": "globex", "host": "web-globex"})
	if d := res["data"].(map[string]any); !strings.Contains(d["error"].(string), "not found") {
		t.Errorf("other org's host: %v", d)
	}
	res = e.tool("host", map[string]any{"host": "web-acme"}) // org inferred: only one visible
	if d := res["data"].(map[string]any); d["status"] != "registered, never reported" {
		t.Errorf("own host: %v", d)
	}
	// Bad input is a tool error the model can read.
	res = e.tool("search", map[string]any{"query": "<script>"})
	if _, ok := res["data"].(map[string]any)["error"]; !ok {
		t.Errorf("bad query: %v", res)
	}
}

func TestFindingAndMachineTools(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	own, _ := e.st.HostByName(ctx, "acme", "web-acme")
	other, _ := e.st.HostByName(ctx, "globex", "web-globex")
	if err := e.st.PutAdvisory(ctx, store.Advisory{ID: "CVE-2099-0001", Modified: time.Now(), Severity: "high", Raw: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	f := []store.Finding{{AdvisoryID: "CVE-2099-0001", Ecosystem: "Debian:12", Package: "openssl", Version: "1", FixedVersion: "2",
		Binaries: []string{"libssl3"}}}
	for _, h := range []store.IngestHost{own, other} {
		if _, _, err := e.st.SetFindings(ctx, h.ID, f, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	ownF, _ := e.st.OpenFindings(ctx, own.ID)
	otherF, _ := e.st.OpenFindings(ctx, other.ID)

	res := e.tool("finding", map[string]any{"ids": []int64{ownF[0].ID, otherF[0].ID}})
	d := res["data"].(map[string]any)
	list := d["findings"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["status"] != "open" || list[0].(map[string]any)["host"] != "web-acme" ||
		fmt.Sprint(list[0].(map[string]any)["binaries"]) != "[libssl3]" {
		t.Errorf("findings %v", list)
	}
	if nf := d["not_found"].([]any); len(nf) != 1 || nf[0] != float64(otherF[0].ID) {
		t.Errorf("another org's finding should look missing: %v", d["not_found"])
	}
	if _, _, err := e.st.SetFindings(ctx, own.ID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	res = e.tool("finding", map[string]any{"ids": []int64{ownF[0].ID}})
	if got := res["data"].(map[string]any)["findings"].([]any)[0].(map[string]any); got["status"] != "resolved" || got["resolved_at"] == nil {
		t.Errorf("resolved finding %v", got)
	}
	res = e.tool("finding", map[string]any{"ids": []any{"x"}})
	if _, ok := res["data"].(map[string]any)["error"]; !ok {
		t.Errorf("bad ids: %v", res)
	}

	m := strings.Repeat("ab", 32)
	e.st.RecordMachine(ctx, own.ID, m)
	e.st.RecordMachine(ctx, other.ID, strings.Repeat("cd", 32))
	res = e.tool("host", map[string]any{"machine": m})
	if d := res["data"].(map[string]any); d["machine"] != m || d["host"] != "web-acme" {
		t.Errorf("host by machine: %v", d)
	}
	res = e.tool("host", map[string]any{"org": "globex", "machine": strings.Repeat("cd", 32)})
	if d := res["data"].(map[string]any); !strings.Contains(fmt.Sprint(d["error"]), "not found") {
		t.Errorf("other org's host by machine: %v", d)
	}
}
