// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/leftovers"
	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// A noble host upgraded from jammy: its release leftovers card lists the
// stale source, the old build, the obsolete package and the service that
// loads it, offers the cleanup action with no params, and its leftover's
// finding says no update fixes it.
func TestHostPageReleaseLeftovers(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.ChangeLink.ActionURL = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
	})
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
		"o=libtinfo5|6.3-2;b=libpq5|16.4-1.pgdg22.04+1|jammy-pgdg")
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

	page := e.get("/hosts/acme/web-01?show=all", signedIn(e)).Body.String()
	for _, want := range []string{
		`id="release-leftovers"`, `<span class="sev sev-medium">medium</span>`,
		"This server runs Ubuntu 24.04 (noble) but still has parts of Ubuntu 22.04 (jammy)",
		"<code>/etc/apt/sources.list.d/pgdg.list</code>", "<td>noble-pgdg</td>",
		"<code>php8.3-fpm.service</code>", "maps <code>libpq.so.5</code> from libpq5",
		"<td>libtinfo5</td>", "<td>libpq5</td>", "only some processes",
		`href="https://changes.example.com/propose?action=release.cleanup&amp;org=acme&amp;host=web-01&amp;"`,
		"built for Ubuntu 22.04 (jammy)", "no update: a leftover",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("host page lacks %q", want)
		}
	}

	// No leftovers, no card and no button.
	plain := kernelCaseEnv(t)
	if page := plain.get("/hosts/acme/"+storetest.OldKernelHost, signedIn(plain)).Body.String(); strings.Contains(page, "release-leftovers") ||
		strings.Contains(page, "release.cleanup") {
		t.Error("a host without leftovers shows the card")
	}
}
