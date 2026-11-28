// SPDX-License-Identifier: AGPL-3.0-or-later

package store_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

func TestHostNodeRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	h, _ := st.HostByName(ctx, "acme", "web-01")
	if n, err := st.HostNodes(ctx); err != nil || len(n) != 0 {
		t.Fatalf("before: %v %v", n, err)
	}
	at := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	want := store.HostNode{
		Bins:  []store.NodeBin{{Path: "/opt/node/22/bin/node", Version: "22.11.0", Running: true}, {Path: "/usr/bin/node"}},
		Sites: map[string]store.NodeSite{"/srv/app": {Bin: "/opt/node/22/bin/node", Requirement: ">=18 <23"}},
	}
	if err := st.SetHostNode(ctx, h.ID, want, at); err != nil {
		t.Fatal(err)
	}
	// Replaced, not merged.
	if err := st.SetHostNode(ctx, h.ID, want, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := st.HostNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := n[h.ID]
	if !got.SeenAt.Equal(at.Add(time.Hour)) {
		t.Errorf("seen %v", got.SeenAt)
	}
	got.SeenAt = time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if err := st.SetHostNode(ctx, h.ID, store.HostNode{}, at); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.HostNodes(ctx); len(n[h.ID].Bins) != 0 || n[h.ID].Sites == nil {
		t.Errorf("empty: %+v", n[h.ID])
	}
}
