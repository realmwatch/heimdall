// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"strings"
	"testing"
)

func TestParseAgents(t *testing.T) {
	for in, want := range map[string]string{"v1 -": "-", "v1 my-agent": "my-agent", "v1 a-agent,b.c_d-agent": "a-agent,b.c_d-agent"} {
		if got, ok := parseAgents(in); !ok || got != want {
			t.Errorf("parseAgents(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "v1", "v1 ", "v2 a", "a-agent", "v1 A-agent", "v1 a,,b", "v1 a b", "v1 " + strings.Repeat("a,", 600) + "a"} {
		if got, ok := parseAgents(bad); ok {
			t.Errorf("parseAgents(%q) accepted as %q", bad, got)
		}
	}
}
