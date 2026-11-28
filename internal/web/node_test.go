// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

const nvmBin = "/home/acme/.nvm/versions/node/v20.11.0/bin/node"

// seedNodeHost is web-01 with NodeSource's nodejs 20 as the default, an
// /opt/node/22 that's behind its major and runs /srv/app, an
// /opt/node/18 nothing uses, nvm's 20 running /srv/legacy, and
// build-only sites needing 22 and 16.
func seedNodeHost(t *testing.T, e *env) store.IngestHost {
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
		map[string]any{"name": "nodejs", "version": "20.19.6-1nodesource1", "arch": "amd64"})
	var sites []any
	for _, root := range []string{"/srv/app", "/srv/legacy", "/srv/build", "/srv/old"} {
		sites = append(sites, map[string]any{"root": root, "document_root": root + "/public", "server_names": []string{strings.TrimPrefix(root, "/srv/") + ".example.com"},
			"web_server": "nginx", "php_fpm_version": "", "readable": true, "framework": "", "framework_version": "", "php_requirement": "",
			"composer_packages": []any{}, "npm_packages": []any{}})
	}
	snap["sites"] = sites
	snap["format"] = "heimdall.snapshot/v4"
	snap["containers"], snap["lockfiles"] = []any{}, []any{}
	raw, _ := json.Marshal(snap)
	s, err := snapshot.DecodeBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SaveReport(ctx, store.NewSnapshot{Host: h, Source: "push", ReceivedAt: testNow, PayloadSHA256: sha256.Sum256(raw), Snapshot: s}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetHostNode(ctx, h.ID, store.HostNode{
		Bins: []store.NodeBin{
			{Path: "/usr/bin/node", Version: "20.19.6"},
			{Path: "/opt/node/22/bin/node", Version: "22.11.0", Running: true},
			{Path: "/opt/node/18/bin/node", Version: "18.20.8"},
			{Path: nvmBin, Version: "20.11.0", Running: true},
		},
		Sites: map[string]store.NodeSite{
			"/srv/app":    {Bin: "/opt/node/22/bin/node", Requirement: "22"},
			"/srv/legacy": {Bin: nvmBin},
			"/srv/build":  {Requirement: "^20"},
			"/srv/old":    {Requirement: "16"},
		},
	}, testNow); err != nil {
		t.Fatal(err)
	}
	day := func(y int, m time.Month, d int) *time.Time { t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC); return &t }
	if err := e.st.ReplaceEOL(ctx, "nodejs", []store.EOLCycle{
		{Cycle: "24", ReleaseDate: day(2025, 5, 6), EOL: day(2028, 4, 30), Latest: "24.11.1"},
		{Cycle: "23", ReleaseDate: day(2024, 10, 16), EOL: day(2025, 6, 1), Latest: "23.11.1"},
		{Cycle: "22", ReleaseDate: day(2024, 4, 24), EOL: day(2027, 4, 30), Latest: "22.21.1"},
		{Cycle: "20", ReleaseDate: day(2023, 4, 18), EOL: day(2026, 4, 30), Latest: "20.19.6"},
		{Cycle: "18", ReleaseDate: day(2022, 4, 19), EOL: day(2025, 4, 30), Latest: "18.20.8"},
		{Cycle: "16", ReleaseDate: day(2021, 4, 20), EOL: day(2023, 9, 11), Latest: "16.20.2"},
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestNodeProposals(t *testing.T) {
	t.Parallel()
	const action = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.ChangeLink.ActionURL = action })
	h := seedNodeHost(t, e)
	link := func(params string) string {
		return `href="https://changes.example.com/propose?action=` + params + `"`
	}

	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	for _, want := range []string{
		`default (apt)`, `title="/opt/node/22/bin/node">/opt/node/22</span>`, `>nvm</span>`,
		`22.21.1 out`, `title="/srv/app">1 site</span>`,
		link(`nodejs.update&amp;org=acme&amp;host=web-01&amp;node=%2Fopt%2Fnode%2F22`),
		link(`nodejs.remove&amp;org=acme&amp;host=web-01&amp;node=%2Fopt%2Fnode%2F18`),
		link(`nodejs.migrate&amp;org=acme&amp;host=web-01&amp;node=%2Fhome%2Facme%2F.nvm%2Fversions%2Fnode%2Fv20.11.0%2Fbin%2Fnode&amp;site=%2Fsrv%2Flegacy`),
		link(`nodejs.default_upgrade&amp;org=acme&amp;host=web-01&amp;from=20`),
		`Requirements Node.js 24 wouldn't meet: /srv/build, /srv/old`, `Propose default upgrade (2 blocked)`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks %s", want)
		}
	}
	// 22 is in use; nvm's needs no update; a default with nothing newer
	// gets nothing.
	for _, not := range []string{"node=%2Fopt%2Fnode%2F22\" target=\"_blank\" rel=\"noopener noreferrer\" title=\"Opens your change-management tool to draft removing",
		"nodejs.remove&amp;org=acme&amp;host=web-01&amp;node=%2Fopt%2Fnode%2F22"} {
		if strings.Contains(page, not) {
			t.Errorf("host page has %s", not)
		}
	}

	site := func(root string) string {
		return e.get("/hosts/acme/web-01/site?root="+root, signedIn(e)).Body.String()
	}
	app := site("/srv/app")
	if !strings.Contains(app, "runs <code title=\"/opt/node/22/bin/node\">") || !strings.Contains(app, "requirement met") ||
		!strings.Contains(app, link(`nodejs.upgrade&amp;org=acme&amp;host=web-01&amp;from=22&amp;site=%2Fsrv%2Fapp`)) || strings.Contains(app, "(build)") {
		t.Errorf("app site page: %s", nodeFact(app))
	}
	build := site("/srv/build")
	if !strings.Contains(build, "Build only") || !strings.Contains(build, "Propose Node.js upgrade (build)") ||
		!strings.Contains(build, link(`nodejs.upgrade&amp;org=acme&amp;host=web-01&amp;from=20&amp;site=%2Fsrv%2Fbuild`)) || strings.Contains(build, "nodejs.install") {
		t.Errorf("build site page: %s", nodeFact(build))
	}
	// 16 is end-of-life: no install, but an upgrade.
	old := site("/srv/old")
	if !strings.Contains(old, "no Node.js meets it") || strings.Contains(old, "nodejs.install") || !strings.Contains(old, "from=16") {
		t.Errorf("old site page: %s", nodeFact(old))
	}

	// A viewer sees the versions but no proposals.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{h.OrgID: store.RoleViewer}}}
	if p := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); !strings.Contains(p, "/opt/node/22") || strings.Contains(p, "action=nodejs.") {
		t.Error("a viewer gets Node.js proposals, or no versions")
	}
}

func TestNodeInstallProposal(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
	h := seedNodeHost(t, e)
	// /srv/build now needs 24, which nothing installed meets.
	n, _ := e.st.HostNodes(t.Context())
	hn := n[h.ID]
	hn.Sites["/srv/build"] = store.NodeSite{Requirement: "24"}
	if err := e.st.SetHostNode(t.Context(), h.ID, hn, testNow); err != nil {
		t.Fatal(err)
	}
	p := e.get("/hosts/acme/web-01/site?root=/srv/build", signedIn(e)).Body.String()
	if !strings.Contains(p, `href="https://changes.example.com/propose?action=nodejs.install&amp;org=acme&amp;host=web-01&amp;major=24"`) ||
		!strings.Contains(p, "Propose installing Node.js 24") || strings.Contains(p, "nodejs.upgrade") {
		t.Errorf("install: %s", nodeFact(p))
	}
}

func TestNodeProposalsNeedActionURL(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	seedNodeHost(t, e)
	if p := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); !strings.Contains(p, "/opt/node/22") || strings.Contains(p, "nodejs.") {
		t.Error("proposals without action_url")
	}
}

func nodeFact(page string) string {
	_, s, _ := strings.Cut(page, `id="node"`)
	s, _, _ = strings.Cut(s, "</div></div></div>")
	return s
}

// A patch plan's Default Node.js column: hosts whose apt Node.js is
// end-of-life.
func TestPlanDefaultNodeColumn(t *testing.T) {
	eol := planRow{Reported: true, F: fleetHost{R: report.Host{Runtimes: []report.Runtime{
		{Name: "nodejs", Version: "20.19.6", Kind: "apt", Life: &report.Lifecycle{Known: true, EOL: true}},
		{Name: "nodejs", Version: "18.20.8", Kind: "opt", Life: &report.Lifecycle{Known: true, EOL: true}},
	}}}}
	if c := eol.Cell("nodejs.default_upgrade"); !c.Need || c.Text != "Node.js 20" || !strings.Contains(eol.Needs(), "nodejs.default_upgrade") {
		t.Errorf("EoL default: %+v %q", c, eol.Needs())
	}
	// Only /opt's is end-of-life: not the default's job.
	ok := planRow{Reported: true, F: fleetHost{R: report.Host{Runtimes: []report.Runtime{
		{Name: "nodejs", Version: "22.11.0", Kind: "apt", Life: &report.Lifecycle{Known: true}},
		{Name: "nodejs", Version: "18.20.8", Kind: "opt", Life: &report.Lifecycle{Known: true, EOL: true}},
	}}}}
	if c := ok.Cell("nodejs.default_upgrade"); c.Need {
		t.Errorf("supported default: %+v", c)
	}
}
