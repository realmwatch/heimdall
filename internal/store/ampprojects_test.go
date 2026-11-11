// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
	"time"
)

func TestAmpProjects(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	org, err := s.CreateOrg(ctx, "test", "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	const repo, pid = "github.com/acme/app", "0d0c0b0a-1234-4abc-8def-000000000001"
	if id, err := s.AmpProject(ctx, org.ID, repo, "amp"); err != nil || id != "" {
		t.Fatalf("none picked: %q %v", id, err)
	}
	if err := s.SetAmpProject(ctx, "test", org.ID, repo, "amp", pid, time.Now()); err != nil {
		t.Fatal(err)
	}
	if id, _ := s.AmpProject(ctx, org.ID, repo, "amp"); id != pid {
		t.Errorf("picked: %q", id)
	}
	// Per agent: another agent's hand-offs still match automatically.
	if id, _ := s.AmpProject(ctx, org.ID, repo, "amp-2"); id != "" {
		t.Errorf("other agent: %q", id)
	}
	if err := s.SetAmpProject(ctx, "test", org.ID, repo, "amp", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if id, _ := s.AmpProject(ctx, org.ID, repo, "amp"); id != "" {
		t.Errorf("cleared: %q", id)
	}
	if err := s.SetAmpProject(ctx, "test", org.ID, repo, "amp", "x; DROP", time.Now()); err == nil {
		t.Error("accepted a bad project ID")
	}
}
