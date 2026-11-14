// SPDX-License-Identifier: AGPL-3.0-or-later

package handoff

import "testing"

// The default agent: the one marked default, else the first Amp agent,
// else the first.
func TestDefaultAgent(t *testing.T) {
	bot, bot2 := Agent{Name: "pr-bot"}, Agent{Name: "my-bot"}
	amp2 := Agent{Name: "amp-2", Starter: nopStarter{}}
	marked := bot2
	marked.Default = true
	for _, tc := range []struct {
		agents []Agent
		want   string
	}{
		{[]Agent{bot, bot2}, "pr-bot"},
		{[]Agent{bot, ampAgent, amp2}, "amp"},
		{[]Agent{bot, ampAgent, marked}, "my-bot"},
	} {
		if a, ok := DefaultAgent(tc.agents); !ok || a.Name != tc.want {
			t.Errorf("DefaultAgent(%v) = %q, %v; want %q", tc.agents, a.Name, ok, tc.want)
		}
	}
	if _, ok := DefaultAgent(nil); ok {
		t.Error("a default agent with none configured")
	}
}
