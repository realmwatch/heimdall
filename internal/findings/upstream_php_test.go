// SPDX-License-Identifier: AGPL-3.0-or-later

package findings

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/ingest"
	"github.com/realmwatch/heimdall/internal/netx"
	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
)

// reportPHP stores a Debian 12 snapshot with PHP's binaries built from
// source at version, optionally with an update pending to pending.
func (e *env) reportPHP(source, version, pending string, binaries ...string) {
	e.t.Helper()
	b, err := os.ReadFile("../snapshot/testdata/debian12.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var s snapshot.Snapshot
	json.Unmarshal(b, &s)
	s.Updates = nil
	no := false
	for _, name := range binaries {
		s.Packages = append(s.Packages, snapshot.Package{Name: name, Version: version, Arch: "amd64", SourceName: source, SourceVersion: version})
		if pending != "" {
			s.Updates = append(s.Updates, snapshot.Update{Name: name, Arch: "amd64", Version: pending, Security: &no})
		}
	}
	s.CollectedAt = e.now
	raw, _ := json.Marshal(s)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return e.now }}
	if res, err := acc.Accept(e.t.Context(), e.host, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("store snapshot: %+v %v", res, err)
	}
}

func (e *env) phpSyncer() *Syncer {
	e.t.Helper()
	list, err := os.ReadFile("../feeds/php/testdata/advisories.json")
	if err != nil {
		e.t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(list) }))
	e.t.Cleanup(srv.Close)
	return &Syncer{Store: e.st, Engine: e.eng, HTTP: netx.NewForTest(srv.Client()), PHPURL: srv.URL + "/advisories",
		Feeds: config.Feeds{OSV: true, PHP: true}, Now: func() time.Time { return e.now },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// phpFindings maps the host's open PHP findings by their CVE (or GHSA).
func (e *env) phpFindings() map[string]store.ReportFinding {
	e.t.Helper()
	out := map[string]store.ReportFinding{}
	for _, f := range e.open() {
		if strings.HasPrefix(f.AdvisoryID, "PHP-") {
			id := strings.TrimPrefix(f.AdvisoryID, "PHP-")
			if len(f.CVEs) > 0 {
				id = f.CVEs[0]
			}
			out[id] = f
		}
	}
	return out
}

// Surý's PHP: judged by PHP's own advisories, only where the part of PHP
// each is about is installed, never queried as Debian's, with the
// branch's fix; resolved by the update.
func TestUpstreamPHPSuryBuild(t *testing.T) {
	e := newEnv(t)
	const ver = "8.4.27-1+0~20251121.1+debian12~1.gbp0a1b2c"
	e.reportPHP("php8.4", ver, "8.4.28-1+0~20251201.1+debian12~1.gbp3d4e5f", "php8.4-cli", "php8.4-common", "php8.4-fpm")
	s := e.phpSyncer()
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := e.phpFindings()
	// FPM's and the core's; not SOAP's (php8.4-soap isn't installed), not
	// the old one (8.4 was never affected).
	if want := []string{"CVE-2026-990001", "CVE-2026-990002"}; !slices.Equal(keys(got), want) {
		t.Fatalf("findings = %v, want %v", keys(got), want)
	}
	f := got["CVE-2026-990001"]
	if f.FixedVersion != "8.4.28" || !f.FixPending || f.Package != "php8.4" || f.Version != ver || f.Severity != "critical" ||
		!slices.Equal(f.Binaries, []string{"php8.4-cli", "php8.4-common", "php8.4-fpm"}) {
		t.Errorf("990001 = %+v", f)
	}
	for _, q := range e.osv.queried {
		if strings.Contains(q, " php8.4") {
			t.Errorf("Surý's build was queried as Debian's: %q", q)
		}
	}

	e.now = e.now.Add(time.Hour)
	e.reportPHP("php8.4", "8.4.28-1+0~20251201.1+debian12~1.gbp3d4e5f", "", "php8.4-cli", "php8.4-common", "php8.4-fpm")
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	if got := e.phpFindings(); len(got) != 0 {
		t.Errorf("after the update: %v", keys(got))
	}
}

// An end-of-life branch is flagged with no fix to offer, and a component
// installed from its own package counts.
func TestUpstreamPHPNoBranchFix(t *testing.T) {
	e := newEnv(t)
	e.reportPHP("php8.1", "8.1.34-9+ubuntu22.04.1+deb.sury.org+1", "", "php8.1-cli", "php8.1-common", "php8.1-fpm")
	if err := e.phpSyncer().Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := e.phpFindings()
	if want := []string{"CVE-2026-990001", "CVE-2026-990002"}; !slices.Equal(keys(got), want) {
		t.Fatalf("findings = %v, want %v", keys(got), want)
	}
	for id, f := range got {
		if f.FixedVersion != "" {
			t.Errorf("%s offers %q on 8.1", id, f.FixedVersion)
		}
	}
}

// The distro's own PHP is left to the distro's advisories: it backports
// fixes, so its upstream version says little.
func TestUpstreamPHPDistroBuild(t *testing.T) {
	e := newEnv(t)
	e.reportPHP("php8.2", "8.2.29-1~deb12u1", "", "php8.2-cli", "php8.2-common", "php8.2-fpm")
	if err := e.phpSyncer().Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := e.phpFindings(); len(got) != 0 {
		t.Errorf("distro build: %v", keys(got))
	}
	if !slices.ContainsFunc(e.osv.queried, func(q string) bool { return strings.HasPrefix(q, "Debian:12 php8.2 ") }) {
		t.Errorf("Debian's PHP wasn't queried: %v", e.osv.queried)
	}
}

// PHP's advisories survive pruning, and one the list drops is withdrawn.
func TestUpstreamPHPPruneAndWithdraw(t *testing.T) {
	e := newEnv(t)
	e.reportPHP("php8.4", "8.4.27-1+ubuntu24.04.1+deb.sury.org+1", "", "php8.4-cli", "php8.4-fpm")
	if err := e.phpSyncer().Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := e.st.PruneAdvisories(ctx, e.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	recs, err := e.st.UpstreamAdvisories(ctx, "PHP-")
	if err != nil || len(recs) != 4 {
		t.Fatalf("after prune: %d, %v", len(recs), err)
	}
	if n, err := e.st.WithdrawUpstream(ctx, "PHP-", []string{"PHP-GHSA-2222-3333-4444"}, e.now); err != nil || n != 3 {
		t.Fatalf("withdraw = %d, %v", n, err)
	}
	if _, err := e.eng.EvaluateHost(ctx, e.host); err != nil {
		t.Fatal(err)
	}
	if got := keys(e.phpFindings()); !slices.Equal(got, []string{"CVE-2026-990001"}) {
		t.Errorf("after withdrawal: %v", got)
	}
}
