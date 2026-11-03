// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFindingIDsStayStableAndResolve(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	h := addFindingHost(t, s, "acme", "web-01", "DEBIAN-CVE-2099-0001", "CVE-2099-0001")
	fs := []Finding{{AdvisoryID: "DEBIAN-CVE-2099-0001", Ecosystem: "Debian:12", Package: "openssl", Version: "1", FixedVersion: "2",
		Binaries: []string{"libssl3", "openssl"}}}
	if _, _, err := s.SetFindings(ctx, h.ID, fs, newsNow); err != nil {
		t.Fatal(err)
	}
	open, err := s.OpenFindings(ctx, h.ID)
	if err != nil || len(open) != 1 || open[0].ID == 0 {
		t.Fatalf("open findings %+v %v", open, err)
	}
	id := open[0].ID

	// The next report with the same finding keeps its id.
	if _, _, err := s.SetFindings(ctx, h.ID, fs, newsNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.OpenFindings(ctx, h.ID); len(again) != 1 || again[0].ID != id {
		t.Errorf("id changed across reports: %+v, want %d", again, id)
	}
	got, err := s.FindingsByID(ctx, []int64{id, id + 1000})
	if err != nil || len(got) != 1 {
		t.Fatalf("FindingsByID %+v %v", got, err)
	}
	if f := got[0]; f.Org != "acme" || f.Host != "web-01" || f.Package != "openssl" || f.Fixed != "2" || !f.ResolvedAt.IsZero() ||
		len(f.CVEs) != 1 || f.CVEs[0] != "CVE-2099-0001" || strings.Join(f.Binaries, ",") != "libssl3,openssl" {
		t.Errorf("open finding %+v", f)
	}

	// Patched: resolved, still found by id, then reopened with the same id.
	patched := newsNow.Add(2 * time.Hour)
	if _, _, err := s.SetFindings(ctx, h.ID, nil, patched); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.FindingsByID(ctx, []int64{id}); len(got) != 1 || !got[0].ResolvedAt.Equal(patched) {
		t.Errorf("resolved finding %+v", got)
	}
	if _, _, err := s.SetFindings(ctx, h.ID, fs, patched.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.FindingsByID(ctx, []int64{id}); len(got) != 1 || !got[0].ResolvedAt.IsZero() {
		t.Errorf("reopened finding %+v", got)
	}

	if _, err := s.FindingsByID(ctx, make([]int64, MaxFindingIDs+1)); err == nil {
		t.Error("no cap on ids")
	}
}

func TestHostByMachine(t *testing.T) {
	t.Parallel()
	s, ctx := newStore(t), t.Context()
	h := addFindingHost(t, s, "acme", "web-01", "DEBIAN-CVE-2099-0001", "CVE-2099-0001")
	m := strings.Repeat("ab", 32)
	if err := s.RecordMachine(ctx, h.ID, strings.ToUpper(m)); err != nil {
		t.Fatal(err)
	}
	got, err := s.HostByMachine(ctx, "acme", m)
	if err != nil || got.ID != h.ID {
		t.Fatalf("HostByMachine %+v %v", got, err)
	}
	if mm, err := s.HostMachine(ctx, h.ID); err != nil || mm != m {
		t.Errorf("HostMachine %q %v", mm, err)
	}
	if _, err := s.HostByMachine(ctx, "acme", strings.Repeat("cd", 32)); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown machine: %v", err)
	}
	if _, err := s.HostByMachine(ctx, "acme", "not-a-hash"); err == nil {
		t.Error("bad hash accepted")
	}
}
