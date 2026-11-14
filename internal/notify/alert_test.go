// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAlertWebhook(t *testing.T) {
	var got []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	a := Alert{Kind: "silent", GeneratedAt: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		Hosts: []string{"acme/web-01", "acme/db-01\r\nBcc: x"}, Count: 2, AlertAfter: "3h0m0s", URL: "https://heimdall.internal/anomalies"}

	w := &Webhook{URL: srv.URL, Format: "json", Client: srv.Client()}
	if err := w.SendAlert(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var back Alert
	if err := json.Unmarshal(got, &back); err != nil || back.Kind != "silent" || back.Count != 2 ||
		back.Hosts[0] != "acme/web-01" || strings.ContainsAny(back.Hosts[1], "\r\n") {
		t.Errorf("json payload = %s (%v)", got, err)
	}
	if a.Hosts[1] != "acme/db-01\r\nBcc: x" {
		t.Error("SendAlert modified the caller's slice")
	}

	w.Format = "slack"
	if err := w.SendAlert(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var slack map[string]string
	json.Unmarshal(got, &slack)
	if !strings.HasPrefix(slack["text"], "Heimdall: 2 hosts stopped reporting") || !strings.Contains(slack["text"], "  acme/web-01\n") ||
		!strings.Contains(slack["text"], "more than 3h,") {
		t.Errorf("slack payload = %s", got)
	}

	a.Kind, a.Hosts, a.Count = "back", a.Hosts[:1], 1
	if s := a.Subject(); s != "Heimdall: 1 host is reporting again" {
		t.Errorf("subject = %q", s)
	}
}

func TestIngestAlerts(t *testing.T) {
	at := time.Date(2026, 10, 23, 23, 0, 0, 0, time.UTC)
	fleet := &AlertFleet{Org: "acme", Quiet: 9, Total: 11, QuietSince: at.Add(-45 * time.Minute), Still: "hub",
		Headline: "Public ingest looks down: 9 of 11 hosts in acme stopped reporting since 22:15 UTC; the hub's own collector still reports."}
	a := Alert{Kind: KindIngestDown, GeneratedAt: at, Hosts: []string{"acme/web-01", "acme/web-02"}, Count: 9, Fleet: fleet,
		URL: "https://heimdall.example.com/hosts"}
	if s := a.Subject(); s != "Heimdall: public ingest looks down (acme)" {
		t.Errorf("subject = %q", s)
	}
	if a.Severity() != "high" {
		t.Errorf("severity = %q", a.Severity())
	}
	txt := a.Text()
	if !strings.HasPrefix(txt, fleet.Headline) || !strings.Contains(txt, "  acme/web-01\n") || !strings.Contains(txt, "reverse proxy") {
		t.Errorf("text:\n%s", txt)
	}
	a = Alert{Kind: KindIngestBack, GeneratedAt: at.Add(2 * time.Hour), Fleet: fleet}
	if s := a.Subject(); s != "Heimdall: ingest is back (acme)" || a.Severity() != "ok" {
		t.Errorf("back subject = %q, severity %q", s, a.Severity())
	}
	if txt := a.Text(); !strings.HasPrefix(txt, "Ingest is back: hosts in acme are reporting again as of 2026-10-24 01:00 UTC, after going quiet at 2026-10-23 22:15 UTC.") {
		t.Errorf("back text:\n%s", txt)
	}
}
