// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// The host tool lists every Node.js binary the collector reported.
func TestHostToolNodeInstalls(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	now := time.Now()
	_, h := storetest.SeedKernelCases(t, e.st, "acme", now)
	if err := e.st.SetHostNode(ctx, h.ID, store.HostNode{
		Bins:  []store.NodeBin{{Path: "/opt/node/22/bin/node", Version: "22.11.0", Running: true}},
		Sites: map[string]store.NodeSite{"/srv/app": {Bin: "/opt/node/22/bin/node", Requirement: "22"}},
	}, now); err != nil {
		t.Fatal(err)
	}
	res := e.tool("host", map[string]any{"host": h.Name})
	b, _ := json.Marshal(res["data"].(map[string]any)["node_installs"])
	if want := `[{"kind":"opt","major":"22","path":"/opt/node/22/bin/node","running":true,"sites":["/srv/app"],"version":"22.11.0"}]`; string(b) != want {
		t.Errorf("node_installs = %s, want %s", b, want)
	}
}
