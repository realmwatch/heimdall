// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"testing"
	"time"
)

func TestRepoBranches(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	org, err := s.CreateOrg(ctx, "test", "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateOrg(ctx, "test", "other", "")
	if err != nil {
		t.Fatal(err)
	}
	const repo = "github.com/acme/app"
	if b, err := s.RepoBranch(ctx, org.ID, repo); err != nil || b != "" {
		t.Fatalf("none set: %q %v", b, err)
	}
	if err := s.SetRepoBranch(ctx, "test", org.ID, repo, "dev", time.Now()); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.RepoBranch(ctx, org.ID, repo); b != "dev" {
		t.Errorf("set: %q", b)
	}
	if at, _ := s.LastAuditAt(ctx, "handoff.branch"); at.IsZero() {
		t.Error("handoff.branch not audited")
	}
	// Per org: another org's hand-offs on the repository are unaffected.
	if b, _ := s.RepoBranch(ctx, other.ID, repo); b != "" {
		t.Errorf("other org: %q", b)
	}
	if err := s.SetRepoBranch(ctx, "test", org.ID, repo, "env/beta", time.Now()); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.RepoBranch(ctx, org.ID, repo); b != "env/beta" {
		t.Errorf("replaced: %q", b)
	}
	if err := s.SetRepoBranch(ctx, "test", org.ID, repo, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.RepoBranch(ctx, org.ID, repo); b != "" {
		t.Errorf("cleared: %q", b)
	}
	var ve *ValidationError
	for _, bad := range []string{"x; reboot", "../main", "a..b", "main.lock"} {
		if err := s.SetRepoBranch(ctx, "test", org.ID, repo, bad, time.Now()); !errors.As(err, &ve) || ve.Field != "branch" {
			t.Errorf("accepted branch %q: %v", bad, err)
		}
	}
	if err := s.SetRepoBranch(ctx, "test", org.ID, "", "dev", time.Now()); !errors.As(err, &ve) || ve.Field != "repo" {
		t.Errorf("accepted no repository: %v", err)
	}
}
