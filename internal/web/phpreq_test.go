// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// A site whose PHP-FPM composer.json doesn't allow says so; one it allows
// says that. (A template's if is true for a pointer to false, so the
// unmet case once showed as met.)
func TestSitePHPRequirementPill(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
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
	var sites []any
	for root, fpm := range map[string]string{"/srv/old": "8.1", "/srv/new": "8.3"} {
		sites = append(sites, map[string]any{"root": root, "document_root": root + "/public", "server_names": []string{strings.TrimPrefix(root, "/srv/") + ".example.com"},
			"web_server": "nginx", "php_fpm_version": fpm, "readable": true, "framework": "", "framework_version": "", "php_requirement": "^8.2",
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
	old := e.get("/hosts/acme/web-01/site?root=/srv/old", signedIn(e)).Body.String()
	if !strings.Contains(old, "PHP 8.1 not allowed") || strings.Contains(old, "runs on 8.1 ✓") {
		t.Error("8.1 under ^8.2 isn't flagged")
	}
	if p := e.get("/hosts/acme/web-01/site?root=/srv/new", signedIn(e)).Body.String(); !strings.Contains(p, "runs on 8.3 ✓") {
		t.Error("8.3 under ^8.2 isn't shown as allowed")
	}
}
