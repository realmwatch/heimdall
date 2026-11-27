// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/leftovers"
	"github.com/realmwatch/heimdall/internal/store"
)

func leftoverFinding() *leftovers.Finding {
	return &leftovers.Finding{Kind: leftovers.Kind, Release: "Ubuntu 22.04 (jammy)", Codename: "jammy",
		Sources: []leftovers.StaleSource{{File: "sources.list.d/ondrej-ubuntu-php-focal.list", URI: "http://ppa.launchpad.net/ondrej/php/ubuntu",
			Suite: "focal", Release: "Ubuntu 20.04 (focal)", Current: "jammy"}},
		Obsolete: []leftovers.Leftover{
			{Name: "libargon2-1", Version: "0~20190702-0.1+ubuntu20.04.1+deb.sury.org+1", Plan: leftovers.PlanReview, Reason: "loaded by php8.1-fpm.service"},
			{Name: "libpcre16-3", Version: "2:8.45-1+ubuntu20.04.1+deb.sury.org+1", Plan: leftovers.PlanReplace},
			{Name: "libfoo1", Version: "1.0-1", Plan: leftovers.PlanReview, Reason: "needed by bar", NeededBy: []string{"bar"}},
		},
		Vendor: []leftovers.Leftover{{Name: "acme-agent", Version: "7.2.0"}},
		UsedBy: []leftovers.Use{{PID: 10, Unit: "php8.1-fpm.service", Library: "/usr/lib/x86_64-linux-gnu/libargon2.so.1", Package: "libargon2-1"},
			{PID: 11, Unit: "php8.1-fpm.service", Library: "/usr/lib/x86_64-linux-gnu/libargon2.so.1", Package: "libargon2-1"}},
		UsageScan: "full", Remediation: []string{"old text"},
	}
}

func TestParseLeftoversOverrides(t *testing.T) {
	f := leftoverFinding()
	ans := map[string]any{
		"summary": "The PHP source still names focal.\x07",
		"steps": []any{map[string]any{"title": "Point the PHP source at jammy", "why": "It gives jammy builds.",
			"packages": []any{"libargon2-1", "libpcre16-3", "made-up"}}},
		"packages": []any{
			map[string]any{"name": "libargon2-1", "action": "remove", "why": "old"},      // loaded: wait
			map[string]any{"name": "libpcre16-3", "action": "fix_source", "why": "sury"}, // fine
			map[string]any{"name": "libfoo1", "action": "remove", "why": "old"},          // needed: wait
			map[string]any{"name": "acme-agent", "action": "remove", "why": "old"},       // vendor: keep
			map[string]any{"name": "made-up", "action": "remove", "why": "x"},            // dropped
			map[string]any{"name": "libpcre16-3", "action": "remove", "why": "dup"},      // duplicate: dropped
		},
		"notes": []any{"A panel may rewrite the source."},
	}
	b, _ := json.Marshal(ans)
	p, err := ParseLeftovers("```json\n"+string(b)+"\n```", f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Summary != "The PHP source still names focal." || len(p.Steps) != 1 || strings.Join(p.Steps[0].Packages, ",") != "libargon2-1,libpcre16-3" {
		t.Fatalf("plan = %+v", p)
	}
	got := map[string]LeftoverAdvice{}
	for _, a := range p.Packages {
		got[a.Name] = a
	}
	if len(p.Packages) != 4 || got["libargon2-1"].Action != LeftoverWait || !strings.Contains(got["libargon2-1"].Heimdall, "loaded by php8.1-fpm.service") ||
		got["libpcre16-3"].Action != LeftoverFixSource || got["libpcre16-3"].Heimdall != "" ||
		got["libfoo1"].Action != LeftoverWait || !strings.Contains(got["libfoo1"].Heimdall, "needed by bar") ||
		got["acme-agent"].Action != LeftoverKeep {
		t.Fatalf("packages = %+v", p.Packages)
	}
	if _, err := ParseLeftovers(`{"summary": ""}`, f); err == nil {
		t.Error("an empty summary was accepted")
	}
	if _, err := ParseLeftovers(`not json`, f); err == nil {
		t.Error("non-JSON was accepted")
	}
}

func TestLeftoverFacts(t *testing.T) {
	f := leftoverFinding()
	b, err := LeftoverFacts(f, 100000)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Count(s, `"unit":"php8.1-fpm.service"`) != 1 || strings.Contains(s, `"pid":10`) || strings.Contains(s, "old text") ||
		!strings.Contains(s, `"heimdall_steps"`) || !strings.Contains(s, "Fix the apt sources") {
		t.Fatalf("facts = %s", s)
	}
	if len(f.UsedBy) != 2 || len(f.Remediation) != 1 {
		t.Error("the finding was changed")
	}
	if _, err := LeftoverFacts(f, 10); err == nil {
		t.Error("facts over budget accepted")
	}
	r := leftoverPrompt(b)
	if r.SchemaName != LeftoverSchemaName || !strings.Contains(r.System, "release upgrade") || !strings.Contains(r.User, dataBegin) {
		t.Errorf("prompt = %+v", r.SchemaName)
	}
}

func TestLeftoverViewOf(t *testing.T) {
	good, _ := json.Marshal(LeftoverPlan{Summary: "ok"})
	runs := []store.AIRun{{Status: "error", Error: "x", CreatedAt: now}, {Status: "ok", Result: good, CreatedAt: now.Add(-time.Hour), Deployment: "d"}}
	v := LeftoverViewOf(runs, now, time.Minute)
	if v.Plan == nil || v.Plan.Summary != "ok" || v.Error != "x" || v.Running {
		t.Fatalf("view = %+v", v)
	}
	if v := LeftoverViewOf([]store.AIRun{{Status: "running", CreatedAt: now}}, now, time.Minute); !v.Running {
		t.Error("not running")
	}
}

func TestStartLeftoversWithoutLeftovers(t *testing.T) {
	st, org, host := seed(t)
	p := &fakeProvider{text: `{}`}
	svc := newService(st, p)
	id, err := st.StartAIRun(t.Context(), org.ID, host.ID, store.AILeftovers, "user:1", "my-deployment", now, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	svc.runLeftovers(id, "user:1", org, host) // the Debian 12 fixture has no leftovers
	runs, _ := st.AIRunsOf(t.Context(), org.ID, host.ID, store.AILeftovers, 5)
	if len(runs) != 1 || runs[0].Status != "error" || len(p.got) != 0 {
		t.Fatalf("runs = %+v, calls %d", runs, len(p.got))
	}
	if err := svc.StartLeftovers(t.Context(), "user:1", org, host); !errors.Is(err, store.ErrAITooSoon) {
		t.Errorf("second start: %v", err)
	}
}
