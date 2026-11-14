// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// fleet is a set of hosts reporting hourly, each from its own address.
type fleet struct {
	e     *env
	hosts map[string]store.IngestHost
}

func newFleet(t *testing.T, ips map[string]string) *fleet {
	f := &fleet{e: newEnv(t), hosts: map[string]store.IngestHost{}}
	for name, ip := range ips {
		h := f.e.host(name)
		f.hosts[name] = h
		if err := f.e.st.RecordReportIP(t.Context(), h.ID, ip); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// report stores a report from each named host at the env's current time.
func (f *fleet) report(names ...string) {
	f.e.t.Helper()
	now := f.e.now
	for _, n := range names {
		f.e.gap, f.e.now = time.Nanosecond, now.Add(-time.Nanosecond)
		f.e.push(f.hosts[n], snap{pkgs: base})
	}
	f.e.now = now
}

// hour moves an hour on, with the named hosts reporting.
func (f *fleet) hour(names ...string) {
	f.e.now = f.e.now.Add(time.Hour)
	f.report(names...)
}

func (f *fleet) check() FleetAlerts {
	f.e.t.Helper()
	got, err := f.e.eng.CheckFleetQuiet(f.e.t.Context())
	if err != nil {
		f.e.t.Fatal(err)
	}
	return got
}

func (f *fleet) states() []store.FleetQuiet {
	f.e.t.Helper()
	qs, err := f.e.st.FleetQuietStates(f.e.t.Context())
	if err != nil {
		f.e.t.Fatal(err)
	}
	return qs
}

var acmeIPs = map[string]string{
	"hub-01": "127.0.0.1", // the hub's own collector
	"web-01": "203.0.113.1", "web-02": "203.0.113.2", "web-03": "203.0.113.3", "web-04": "203.0.113.4",
}

var all = []string{"hub-01", "web-01", "web-02", "web-03", "web-04"}

func TestFleetQuietLifecycle(t *testing.T) {
	f := newFleet(t, acmeIPs)
	ctx := t.Context()
	for range 5 {
		f.hour(all...)
	}
	if got := f.check(); len(got.Down)+len(got.Back) != 0 || len(f.states()) != 0 {
		t.Fatalf("all reporting: %+v", got)
	}
	stopped := f.e.now
	// The public ingest goes down: only the hub's own collector and one
	// host (on another path) keep reporting.
	f.hour("hub-01", "web-04")
	if got := f.check(); len(got.Down) != 0 || len(f.states()) != 0 {
		t.Fatalf("an hour quiet is a missed report, not an outage: %+v", got)
	}
	f.hour("hub-01", "web-04")
	f.e.now = f.e.now.Add(time.Minute)
	if got := f.check(); len(got.Down) != 0 {
		t.Fatalf("alerted before the condition held: %+v", got)
	}
	if qs := f.states(); len(qs) != 1 || qs[0].Down() {
		t.Fatalf("pending episode: %+v", qs)
	}
	f.e.now = f.e.now.Add(FleetHold)
	got := f.check()
	if len(got.Down) != 1 || len(got.Back) != 0 {
		t.Fatalf("down: %+v", got)
	}
	q := got.Down[0]
	if q.Quiet != 3 || q.Total != 5 || q.Still != "hub" || !q.QuietSince.Equal(stopped) || len(q.Hosts) != 3 {
		t.Fatalf("episode: %+v", q)
	}
	h := q.Headline(f.e.now)
	if want := "Public ingest looks down: 3 of 5 hosts in acme stopped reporting since " + stopped.Format("15:04") +
		" UTC; the hub's own collector still reports."; h != want {
		t.Fatalf("headline:\n got %q\nwant %q", h, want)
	}
	if err := f.e.eng.MarkFleetAlerts(ctx, got); err != nil {
		t.Fatal(err)
	}
	if qs := f.states(); len(qs) != 1 || !qs[0].Down() {
		t.Fatalf("banner state: %+v", qs)
	}
	// Once per episode, however long it lasts.
	for range 30 {
		f.hour("hub-01", "web-04")
		if got := f.check(); len(got.Down)+len(got.Back) != 0 {
			t.Fatalf("alerted again: %+v", got)
		}
	}
	// Ingest is back.
	f.hour(all...)
	if got := f.check(); len(got.Back) != 0 {
		t.Fatalf("back before it stayed back: %+v", got)
	}
	if qs := f.states(); len(qs) != 1 || qs[0].Down() {
		t.Fatalf("clearing: %+v", qs)
	}
	f.e.now = f.e.now.Add(FleetHold)
	got = f.check()
	if len(got.Back) != 1 || len(got.Down) != 0 || got.Back[0].OrgSlug != "acme" {
		t.Fatalf("back: %+v", got)
	}
	if err := f.e.eng.MarkFleetAlerts(ctx, got); err != nil {
		t.Fatal(err)
	}
	if qs := f.states(); len(qs) != 0 {
		t.Fatalf("episode not closed: %+v", qs)
	}
	if got := f.check(); len(got.Down)+len(got.Back) != 0 {
		t.Fatalf("after back: %+v", got)
	}
}

func TestFleetQuietUnsentIsRetried(t *testing.T) {
	f := newFleet(t, acmeIPs)
	for range 5 {
		f.hour(all...)
	}
	f.hour("hub-01")
	f.hour("hub-01")
	f.e.now = f.e.now.Add(time.Minute)
	f.check()
	f.e.now = f.e.now.Add(FleetHold)
	if got := f.check(); len(got.Down) != 1 {
		t.Fatalf("down: %+v", got)
	}
	// Not marked (no destination took it): sent again next time.
	f.e.now = f.e.now.Add(5 * time.Minute)
	if got := f.check(); len(got.Down) != 1 {
		t.Fatalf("retry: %+v", got)
	}
}

func TestFleetQuietOneHostIsNotTheFleet(t *testing.T) {
	f := newFleet(t, acmeIPs)
	for range 5 {
		f.hour(all...)
	}
	for range 6 {
		f.hour("hub-01", "web-01", "web-02", "web-03")
		f.check()
	}
	if qs := f.states(); len(qs) != 0 {
		t.Fatalf("one quiet host opened a fleet episode: %+v", qs)
	}
}

func TestFleetQuietSkipsWindowsAndSuppressions(t *testing.T) {
	f := newFleet(t, acmeIPs)
	ctx := t.Context()
	for range 5 {
		f.hour(all...)
	}
	// Planned work on two hosts, the silence rule muted on a third.
	for _, h := range []string{"web-01", "web-02"} {
		if _, err := f.e.st.CreateWindow(ctx, "test", store.Window{OrgSlug: "acme", Host: h,
			Starts: f.e.now, Ends: f.e.now.Add(8 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.e.st.Suppress(ctx, "test", 0, f.hosts["web-03"], "silence", f.e.now.Add(8*time.Hour), "known outage", f.e.now); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		f.hour("hub-01", "web-04")
		f.e.now = f.e.now.Add(FleetHold)
		if got := f.check(); len(got.Down) != 0 {
			t.Fatalf("excused hosts counted: %+v", got)
		}
	}
	if qs := f.states(); len(qs) != 0 {
		t.Fatalf("episode: %+v", qs)
	}
}

// Ingest from outside stops while tailnet hosts keep reporting: alert even
// though the outside hosts are a minority.
func TestFleetQuietOutsideCutOff(t *testing.T) {
	f := newFleet(t, map[string]string{
		"app-01": "100.64.0.1", "app-02": "100.64.0.2", "app-03": "100.64.0.3", "app-04": "fd7a:115c:a1e0::4",
		"web-01": "198.51.100.1", "web-02": "198.51.100.2",
	})
	inside := []string{"app-01", "app-02", "app-03", "app-04"}
	for range 5 {
		f.hour(append(inside, "web-01", "web-02")...)
	}
	f.hour(inside...)
	f.hour(inside...)
	f.e.now = f.e.now.Add(time.Minute)
	f.check()
	f.e.now = f.e.now.Add(FleetHold)
	got := f.check()
	if len(got.Down) != 1 || !got.Down[0].Outside || got.Down[0].Still != "tailnet" || got.Down[0].Quiet != 2 {
		t.Fatalf("down: %+v", got)
	}
	if h := got.Down[0].Headline(f.e.now); !strings.HasPrefix(h, "Public ingest looks down: 2 of 6 hosts in acme") ||
		!strings.Contains(h, "every one that reports from outside") || !strings.HasSuffix(h, "hosts on the tailnet still report.") {
		t.Fatalf("headline: %q", h)
	}
}

// After the hub itself was down, hosts get their usual time to report
// again before they count as quiet.
func TestFleetQuietHubRestart(t *testing.T) {
	f := newFleet(t, acmeIPs)
	for range 5 {
		f.hour(all...)
	}
	f.e.now = f.e.now.Add(10 * time.Hour) // the hub was off
	f.e.eng.Started = f.e.now
	f.report("hub-01")
	f.e.now = f.e.now.Add(30 * time.Minute)
	f.check()
	f.e.now = f.e.now.Add(FleetHold)
	if got := f.check(); len(got.Down) != 0 || len(f.states()) != 0 {
		t.Fatalf("a hub restart looked like an outage: %+v", got)
	}
}
