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

// reportNginx stores a Debian 12 snapshot with nginx (and nginx-common)
// at version, optionally with an update pending to pending.
func (e *env) reportNginx(version, pending string) {
	e.t.Helper()
	b, err := os.ReadFile("../snapshot/testdata/debian12.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var s snapshot.Snapshot
	json.Unmarshal(b, &s)
	for _, name := range []string{"nginx", "nginx-common"} {
		s.Packages = append(s.Packages, snapshot.Package{Name: name, Version: version, Arch: "amd64", SourceName: "nginx", SourceVersion: version})
	}
	s.Updates = nil
	if pending != "" {
		no := false
		s.Updates = []snapshot.Update{{Name: "nginx", Arch: "amd64", Version: pending, Security: &no}}
	}
	s.CollectedAt = e.now
	raw, _ := json.Marshal(s)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return e.now }}
	if res, err := acc.Accept(e.t.Context(), e.host, "push", raw); err != nil || res.Status != http.StatusCreated {
		e.t.Fatalf("store snapshot: %+v %v", res, err)
	}
}

// upstreamSyncer serves the nginx feed's test list.
func (e *env) upstreamSyncer() *Syncer {
	e.t.Helper()
	list, err := os.ReadFile("../feeds/nginx/testdata/advisories.xml")
	if err != nil {
		e.t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(list) }))
	e.t.Cleanup(srv.Close)
	return &Syncer{Store: e.st, Engine: e.eng, HTTP: netx.NewForTest(srv.Client()), NginxURL: srv.URL + "/advisories.xml",
		Feeds: config.Feeds{OSV: true, Nginx: true}, Now: func() time.Time { return e.now },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// nginxFindings maps the host's open nginx.org findings to their fix.
func (e *env) nginxFindings() map[string]store.ReportFinding {
	e.t.Helper()
	out := map[string]store.ReportFinding{}
	for _, f := range e.open() {
		if strings.HasPrefix(f.AdvisoryID, "NGINX-") {
			out[strings.TrimPrefix(f.AdvisoryID, "NGINX-")] = f
		}
	}
	return out
}

func keys(m map[string]store.ReportFinding) []string {
	return slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
}

// nginx.org's build: judged by nginx.org's advisories with nginx.org's
// fixes, whatever Debian has published, and never queried as Debian's.
func TestUpstreamNginxOrgBuild(t *testing.T) {
	e := newEnv(t)
	e.osv.records = map[string]bool{"DEBIAN-CVE-2026-113425": true}
	e.reportNginx("1.30.6-1~bookworm", "1.30.7-1~bookworm")
	s := e.upstreamSyncer()
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := e.nginxFindings()
	want := []string{"CVE-2026-113425", "CVE-2026-121810", "CVE-2026-123007", "CVE-2026-55555"}
	if !slices.Equal(keys(got), want) {
		t.Fatalf("findings = %v, want %v", keys(got), want)
	}
	f := got["CVE-2026-123007"]
	if f.FixedVersion != "1.30.7" || !f.FixPending || f.Package != "nginx" || f.Version != "1.30.6-1~bookworm" ||
		!slices.Equal(f.Binaries, []string{"nginx", "nginx-common"}) || f.Severity != "high" || !slices.Contains(f.CVEs, "CVE-2026-123007") {
		t.Errorf("123007 = %+v", f)
	}
	if f := got["CVE-2026-55555"]; f.FixedVersion != "" || f.FixPending {
		t.Errorf("an advisory nothing fixes offers %q", f.FixedVersion)
	}
	for _, q := range e.osv.queried {
		if strings.Contains(q, " nginx ") {
			t.Errorf("nginx.org's build was queried as Debian's: %q", q)
		}
	}

	// Upgraded: everything but the unfixed one resolves.
	e.now = e.now.Add(time.Hour)
	e.reportNginx("1.30.7-1~bookworm", "")
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	if got := keys(e.nginxFindings()); !slices.Equal(got, []string{"CVE-2026-55555"}) {
		t.Errorf("after the upgrade: %v", got)
	}
}

// Debian's own build: nginx.org's advisories stand in only for the CVEs
// Debian hasn't published a record of, with no fix offered, until it does.
func TestUpstreamDistroBuild(t *testing.T) {
	e := newEnv(t)
	e.osv.records = map[string]bool{"DEBIAN-CVE-2026-113425": true}
	e.reportNginx("1.22.1-9+deb12u2", "")
	s := e.upstreamSyncer()
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := e.nginxFindings()
	if want := []string{"CVE-2026-123007", "CVE-2026-55555"}; !slices.Equal(keys(got), want) {
		t.Fatalf("findings = %v, want %v", keys(got), want)
	}
	if f := got["CVE-2026-123007"]; f.FixedVersion != "" || f.Version != "1.22.1-9+deb12u2" {
		t.Errorf("a distro build must not be offered nginx.org's fix: %+v", f)
	}
	// Debian is still queried for its own build.
	if !slices.ContainsFunc(e.osv.queried, func(q string) bool { return q == "Debian:12 nginx 1.22.1-9+deb12u2" }) {
		t.Errorf("Debian's nginx wasn't queried: %v", e.osv.queried)
	}

	// Debian publishes its record of 123007: the next sync sees it, and the
	// stand-in resolves.
	e.osv.records["DEBIAN-CVE-2026-123007"] = true
	e.now = e.now.Add(6 * time.Hour)
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := keys(e.nginxFindings()); !slices.Equal(got, []string{"CVE-2026-55555"}) {
		t.Errorf("after Debian's record: %v", got)
	}
}

// A pair never checked (the lookup failed) counts as published: a failed
// check must not flag every CVE nginx ever had on distro builds.
func TestUpstreamUncheckedDistro(t *testing.T) {
	e := newEnv(t)
	e.osv.recordsDown = true
	e.reportNginx("1.22.1-9+deb12u2", "")
	s := e.upstreamSyncer()
	if err := s.syncUpstream(t.Context()); err == nil || !strings.Contains(err.Error(), "lookups failed") {
		t.Fatalf("sync = %v, want the failed lookups reported", err)
	}
	if _, err := e.eng.EvaluateHost(t.Context(), e.host); err != nil {
		t.Fatal(err)
	}
	if got := e.nginxFindings(); len(got) != 0 {
		t.Errorf("unchecked: %v", keys(got))
	}
}

// The collector says where a package came from: one from another apt
// source is third-party even when its version doesn't look like
// nginx.org's.
func TestUpstreamOrigins(t *testing.T) {
	e := newEnv(t)
	e.reportNginx("1.30.6-2", "")
	if err := e.st.SetHostOrigins(t.Context(), e.host.ID, map[string]string{"nginx": "acme-repo", "nginx-common": "acme-repo"}, e.now); err != nil {
		t.Fatal(err)
	}
	s := e.upstreamSyncer()
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f := e.nginxFindings()["CVE-2026-123007"]; f.FixedVersion != "1.30.7" {
		t.Errorf("third-party by origin: %+v", f)
	}
	for _, q := range e.osv.queried {
		if strings.Contains(q, " nginx ") {
			t.Errorf("queried as Debian's: %q", q)
		}
	}
}

// A sync that no longer lists an advisory withdraws it, and prune keeps
// the rest though no query result refers to them.
func TestUpstreamWithdrawAndPrune(t *testing.T) {
	e := newEnv(t)
	e.reportNginx("1.30.6-1~bookworm", "")
	s := e.upstreamSyncer()
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := e.st.PruneAdvisories(ctx, e.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	recs, err := e.st.UpstreamAdvisories(ctx, "NGINX-")
	if err != nil || len(recs) != 7 {
		t.Fatalf("after prune: %d, %v", len(recs), err)
	}
	if n, err := e.st.WithdrawUpstream(ctx, "NGINX-", []string{"NGINX-CVE-2026-123007"}, e.now); err != nil || n != 6 {
		t.Fatalf("withdraw = %d, %v", n, err)
	}
	if _, err := e.eng.EvaluateHost(ctx, e.host); err != nil {
		t.Fatal(err)
	}
	if got := keys(e.nginxFindings()); !slices.Equal(got, []string{"CVE-2026-123007"}) {
		t.Errorf("after withdrawal: %v", got)
	}
}
