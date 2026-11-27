// SPDX-License-Identifier: AGPL-3.0-or-later

package privilege

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// forgeRange stores a synced Forge range, as the daily deploy-service sync does.
func (e *ruleEnv) forgeRange() {
	e.t.Helper()
	if err := e.st.ReplaceIPLabels(e.t.Context(), 0, "service:forge", []store.IPLabel{{Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Kind: store.IPKindAutomation, Name: "Laravel Forge"}}, now); err != nil {
		e.t.Fatal(err)
	}
}

// accessSummaries returns the open privileged_access anomalies' summaries.
func (e *ruleEnv) accessSummaries() []string {
	e.t.Helper()
	var out []string
	for _, a := range e.open("privileged_access") {
		out = append(out, a.Summary)
	}
	return out
}

func TestDeployServiceSessionsExempt(t *testing.T) {
	e := newRuleEnv(t)
	e.forgeRange()
	// Forge from its synced range, as root and as forge: not counted.
	e.report(ev(-time.Hour, "root-ssh", "root", "198.51.100.7"), ev(-time.Hour, "sudo", "forge", "198.51.100.8"))
	if got := e.accessSummaries(); len(got) != 0 {
		t.Fatalf("deploy-service sessions counted: %v", got)
	}
	// The forge account from an unknown address is only a name: it counts,
	// and the address is still unknown.
	if got := e.report(ev(-50*time.Minute, "root-ssh", "forge", "203.0.113.9")); strings.Join(got, ",") != "privilege_unknown_source 203.0.113.9" {
		t.Fatalf("raised %v", got)
	}
	if got := e.accessSummaries(); len(got) != 1 || !strings.Contains(got[0], "1 privileged access ") || !strings.Contains(got[0], "1 root SSH by forge from 203.0.113.9") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestDeployServiceSessionsCounted(t *testing.T) {
	e := newRuleEnv(t)
	e.forgeRange()
	if err := e.st.SetIPPolicy(t.Context(), "test", store.IPPolicy{OrgID: e.host.OrgID, AllowServices: true, CountServices: true}, now); err != nil {
		t.Fatal(err)
	}
	if got := e.report(ev(-time.Hour, "root-ssh", "root", "198.51.100.7")); len(got) != 0 {
		t.Fatalf("raised %v", got) // known address: no source alert either way
	}
	if got := e.accessSummaries(); len(got) != 1 || !strings.Contains(got[0], "1 root SSH by root from 198.51.100.7") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestMixedDayCountsNonExempt(t *testing.T) {
	e := newRuleEnv(t)
	e.forgeRange()
	e.label("192.0.2.0/24", store.IPKindStaff)
	if _, err := e.st.CreateWindow(t.Context(), "test", store.Window{OrgSlug: "acme", Host: "web-01",
		Starts: now.Add(-5 * time.Hour), Ends: now.Add(-4 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.report(ev(-3*time.Hour, "root-ssh", "root", "198.51.100.7"), ev(-2*time.Hour, "root-ssh", "root", "198.51.100.7"), // Forge
		ev(-time.Hour, "sudo", "chris", "192.0.2.7"),         // staff
		ev(-time.Hour, "sudo", "chris", ""),                  // local
		ev(-50*time.Minute, "su", "forge", "203.0.113.9"),    // the name only
		ev(-270*time.Minute, "sudo", "chris", "203.0.113.1")) // in a window
	got := e.accessSummaries()
	if len(got) != 1 || !strings.HasPrefix(got[0], "3 privileged accesses ") || !strings.Contains(got[0], "2 sudo, 1 su") ||
		strings.Contains(got[0], "198.51.100.7") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestAccessSummaryNamesSources(t *testing.T) {
	e := newRuleEnv(t)
	e.report(ev(-time.Hour, "sudo", "alice", "203.0.113.7"), ev(-time.Hour, "sudo", "alice", ""))
	if got := e.accessSummaries(); len(got) != 1 || !strings.HasSuffix(got[0], ": 2 sudo by alice, alice from 203.0.113.7") {
		t.Fatalf("anomalies = %v", got)
	}
	// Many people and places: the first few are named, the rest counted.
	e.report(ev(-50*time.Minute, "sudo", "bob", "203.0.113.8"), ev(-49*time.Minute, "sudo", "carol", "203.0.113.9"),
		ev(-48*time.Minute, "su", "dave", "203.0.113.10"), ev(-47*time.Minute, "su", "erin", "203.0.113.11"))
	if got := e.accessSummaries(); len(got) != 1 || !strings.HasSuffix(got[0], ": 4 sudo, 2 su by alice, alice from 203.0.113.7, bob from 203.0.113.8, carol from 203.0.113.9 +2 more") {
		t.Fatalf("anomalies = %v", got)
	}
}

// agentPlan sets the org's agent account and, if open, puts the host in
// an open patch plan.
func (e *ruleEnv) agentPlan(account string, open bool) {
	e.t.Helper()
	ctx := e.t.Context()
	if err := e.st.SetIPPolicy(ctx, "test", store.IPPolicy{OrgID: e.host.OrgID, AllowServices: true, AgentAccount: account}, now); err != nil {
		e.t.Fatal(err)
	}
	if !open {
		return
	}
	p, err := e.st.CreatePlan(ctx, "test", 0, "acme", "November patching")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.AddToPlan(ctx, "test", p.ID, e.host, 1); err != nil {
		e.t.Fatal(err)
	}
}

func TestAgentSudoInOpenPlanExempt(t *testing.T) {
	e := newRuleEnv(t)
	e.agentPlan("agent", true)
	e.report(ev(-3*time.Hour, "sudo", "agent", ""), ev(-2*time.Hour, "sudo", "agent", ""), ev(-time.Hour, "sudo", "agent", ""))
	if got := e.accessSummaries(); len(got) != 0 {
		t.Fatalf("the agent's sudo in an open plan counted: %v", got)
	}
}

func TestAgentSudoOutsidePlanCounted(t *testing.T) {
	e := newRuleEnv(t)
	e.agentPlan("agent", false)
	e.report(ev(-3*time.Hour, "sudo", "agent", ""), ev(-2*time.Hour, "sudo", "agent", ""), ev(-time.Hour, "sudo", "agent", ""))
	if got := e.accessSummaries(); len(got) != 1 || !strings.Contains(got[0], "3 sudo by agent") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestAgentExemptionIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   store.PrivilegeEvent
		want string
	}{
		{"remote source", ev(-time.Hour, "sudo", "agent", "192.0.2.10"), "1 sudo by agent from 192.0.2.10"},
		{"unknown source", ev(-time.Hour, "sudo", "agent", "?"), "1 sudo by agent"},
		{"another account", ev(-time.Hour, "sudo", "alice", ""), "1 sudo by alice"},
		{"root SSH", ev(-time.Hour, "root-ssh", "agent", ""), "1 root SSH by agent"},
		{"su", ev(-time.Hour, "su", "agent", ""), "1 su by agent"},
		{"no username", ev(-time.Hour, "sudo", "", ""), "1 sudo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRuleEnv(t)
			e.agentPlan("agent", true)
			e.report(tc.ev)
			if got := e.accessSummaries(); len(got) != 1 || !strings.HasSuffix(got[0], tc.want) {
				t.Fatalf("anomalies = %v, want one ending %q", got, tc.want)
			}
		})
	}
}

func TestAgentMixedDay(t *testing.T) {
	e := newRuleEnv(t)
	e.agentPlan("agent", true)
	e.report(ev(-3*time.Hour, "sudo", "agent", ""), ev(-2*time.Hour, "sudo", "agent", ""), ev(-time.Hour, "sudo", "alice", ""))
	if got := e.accessSummaries(); len(got) != 1 || !strings.HasPrefix(got[0], "1 privileged access ") || !strings.HasSuffix(got[0], ": 1 sudo by alice") {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestAgentAccountUnsetCounts(t *testing.T) {
	e := newRuleEnv(t)
	e.agentPlan("", true) // in a plan, but no account set: nothing is exempt
	e.report(ev(-time.Hour, "sudo", "agent", ""))
	if got := e.accessSummaries(); len(got) != 1 {
		t.Fatalf("anomalies = %v", got)
	}
}

func TestAgentAccountValidated(t *testing.T) {
	e := newRuleEnv(t)
	for _, bad := range []string{"root", "Agent", "a b", "-x", strings.Repeat("a", 33)} {
		if err := e.st.SetIPPolicy(t.Context(), "test", store.IPPolicy{OrgID: e.host.OrgID, AgentAccount: bad}, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := e.st.SetIPPolicy(t.Context(), "test", store.IPPolicy{OrgID: e.host.OrgID, AgentAccount: " deploy-agent "}, now); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.st.IPPolicy(t.Context(), e.host.OrgID); p.AgentAccount != "deploy-agent" {
		t.Fatalf("stored %q", p.AgentAccount)
	}
}
