// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReportHookSigns(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	var got []*http.Request
	var bodies [][]byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, bodies = append(got, r), append(bodies, b)
		if len(got) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // retried, and signed again
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	tick := 0
	h := &ReportHook{URL: srv.URL + "/hooks/heimdall", Secret: secret, Client: srv.Client(),
		Retry: Retry{Sleep: func(context.Context, time.Duration) error { return nil }},
		Now:   func() time.Time { tick++; return at.Add(time.Duration(tick) * time.Second) }}
	ev := ReportEvent{Event: "report.received", Org: "acme", Host: "web-01", SnapshotID: 42, Changed: true, ReceivedAt: at}
	if err := h.Send(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d attempts", len(got))
	}
	for i, r := range got {
		ts := r.Header.Get(ReportTimestampHeader)
		if want := ReportSignature(secret, ts, bodies[i]); r.Header.Get(ReportSignatureHeader) != want {
			t.Errorf("attempt %d: signature %q, want %q", i, r.Header.Get(ReportSignatureHeader), want)
		}
		if r.Header.Get(ReportEventHeader) != "report.received" || r.Header.Get(ReportDeliveryHeader) == "" {
			t.Errorf("attempt %d headers %v", i, r.Header)
		}
	}
	if got[0].Header.Get(ReportTimestampHeader) == got[1].Header.Get(ReportTimestampHeader) {
		t.Error("a retry reused the timestamp")
	}
	var sent map[string]any
	json.Unmarshal(bodies[1], &sent)
	if sent["org"] != "acme" || sent["host"] != "web-01" || sent["snapshot_id"] != float64(42) || sent["changed"] != true ||
		sent["delivery"] != got[1].Header.Get(ReportDeliveryHeader) {
		t.Errorf("body %s", bodies[1])
	}
	for _, k := range []string{"packages", "findings", "inventory"} {
		if strings.Contains(string(bodies[1]), k) {
			t.Errorf("body carries %s: %s", k, bodies[1])
		}
	}
	// Known value, so receivers in other languages can check their code.
	// (printf '1700000000.{}' | openssl dgst -sha256 -hmac secret)
	if s := ReportSignature([]byte("secret"), "1700000000", []byte(`{}`)); s != "sha256=b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163" {
		t.Errorf("reference signature %s", s)
	}
}

func TestReportHookRefuses(t *testing.T) {
	ok := &http.Client{}
	for name, h := range map[string]*ReportHook{
		"short secret": {URL: "https://example.com/h", Secret: []byte("short"), Client: ok},
		"plain http":   {URL: "http://example.com/h", Secret: make([]byte, 32), Client: ok},
		"no client":    {URL: "https://example.com/h", Secret: make([]byte, 32)},
	} {
		if err := h.Send(t.Context(), ReportEvent{Event: "test"}); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
}
