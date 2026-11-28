// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

// The Python python3 runs is the distro's build, with no end-of-life
// date of python.org's; a deadsnakes Python beside it keeps its own.
func TestHostPageDistroPython(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	ctx := t.Context()
	e.st.CreateOrg(ctx, "test", "acme", "Acme")
	e.st.CreateEnv(ctx, "test", "acme", "prod", "")
	e.st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	h, err := e.st.HostByName(ctx, "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	json.Unmarshal(storetest.KernelCaseSnapshot(t, storetest.OldKernelHost, testNow), &snap)
	snap["packages"] = append(snap["packages"].([]any),
		map[string]any{"name": "python3", "version": "3.10.6-1~22.04.1", "arch": "amd64", "source_name": "python3-defaults", "source_version": "3.10.6-1~22.04.1"},
		map[string]any{"name": "python3.10", "version": "3.10.12-1~22.04.10", "arch": "amd64"},
		map[string]any{"name": "python3.12", "version": "3.12.9-1+jammy1", "arch": "amd64"})
	raw, _ := json.Marshal(snap)
	s, err := snapshot.DecodeBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SaveReport(ctx, store.NewSnapshot{Host: h, Source: "push", ReceivedAt: testNow, PayloadSHA256: sha256.Sum256(raw), Snapshot: s}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetHostOrigins(ctx, h.ID, map[string]string{"python3.12": "LP-PPA-deadsnakes"}, testNow); err != nil {
		t.Fatal(err)
	}

	page := e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	_, py, ok := strings.Cut(page, "<strong>python</strong>")
	if !ok {
		t.Fatal("no python runtime on the host page")
	}
	py, _, _ = strings.Cut(py, `</section>`)
	rows := map[string]string{}
	for _, row := range strings.Split(py, `<div class="rt-ver">`)[1:] {
		for _, v := range []string{"3.10.12", "3.12.9"} {
			if strings.Contains(row, ">"+v+"<") {
				rows[v] = row
			}
		}
	}
	if r := rows["3.10.12"]; !strings.Contains(r, "Ubuntu's build") || !strings.Contains(r, "python.org's end-of-life dates don't apply") {
		t.Errorf("3.10 isn't Ubuntu's build: %s", r)
	}
	if r := rows["3.12.9"]; r == "" || strings.Contains(r, "s build") || !strings.Contains(r, "EoL") {
		t.Errorf("deadsnakes' 3.12 should keep python.org's dates: %s", r)
	}
}
