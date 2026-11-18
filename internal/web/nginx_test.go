// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/feeds/nginx"
	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/store"
)

// A host running nginx.org's nginx renders it under Runtimes (marked
// outdated, with its HTTP/2 and restart state) and gets the nginx card.
func TestHostPageNginx(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	host := e.seed()
	ctx := t.Context()
	raw, err := os.ReadFile("../snapshot/testdata/debian12.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	pkgs := snap["packages"].([]any)
	snap["packages"] = append(pkgs, map[string]any{"name": "nginx", "version": "1.30.6-1~bookworm", "arch": "amd64",
		"source_name": "nginx", "source_version": "1.30.6-1~bookworm"})
	snap["collected_at"] = testNow.Add(time.Minute).Format(time.RFC3339)
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow.Add(time.Minute) }}
	if res, err := acc.Accept(ctx, host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("snapshot: %+v %v", res, err)
	}
	a := nginx.Advisory{ID: "NGINX-CVE-2026-123007", CVE: "CVE-2026-123007", Name: "Memory corruption in HTTP/2 flow control",
		Severity: "high", Vulnerable: [][2]string{{"1.9.5", "1.31.8"}}, Good: []string{"1.30.7", "1.31.9"}, Feature: "http2"}
	if err := e.st.PutAdvisory(ctx, store.Advisory{ID: a.ID, Modified: testNow, Summary: a.Name, Severity: "high",
		Raw: a.OSV(), Aliases: []string{a.CVE}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.SetFindings(ctx, host.ID, []store.Finding{{AdvisoryID: a.ID, Ecosystem: nginx.Ecosystem, Package: "nginx",
		Version: "1.30.6-1~bookworm", Binaries: []string{"nginx"}, FixedVersion: "1.30.7"}}, testNow); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetHostNginx(ctx, host.ID, store.NginxState{Servers: 4, HTTP2: 2, Restart: "yes",
		RootHTTP2: map[string]bool{"/srv/a": true}}, testNow); err != nil {
		t.Fatal(err)
	}
	body := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{
		`<strong>nginx</strong>`, `rt-v rt-v-outdated`, `>1.30.6</span>`,
		`>restart needed</a>`, `>HTTP/2 on</a>`, `id="nginx-h"`, `on</strong> in 2 of 4 server blocks`,
		`>nginx.org</a>`, `>HTTP/2 on</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if strings.Contains(body, "apache") {
		t.Error("Apache listed though it isn't installed")
	}
}
