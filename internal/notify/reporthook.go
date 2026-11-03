// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// ReportEvent is what the report webhook sends when the hub accepts a
// host's report. It names the report and nothing in it: a receiver that
// wants the findings reads them over MCP, with its own token.
type ReportEvent struct {
	Event      string `json:"event"`    // "report.received", or "test"
	Delivery   string `json:"delivery"` // random, unique per event: the receiver's replay check
	Org        string `json:"org"`
	Host       string `json:"host"`
	SnapshotID int64  `json:"snapshot_id"`
	// Changed: the inventory differed from the host's last report, and the
	// host's findings were recomputed before this was sent. An unchanged
	// report is a heartbeat; its findings are as they were.
	Changed    bool      `json:"changed"`
	ReceivedAt time.Time `json:"received_at"`
}

// Report webhook request headers. The signature is the hex HMAC-SHA256,
// keyed with the shared secret, of the timestamp, a ".", and the body.
const (
	ReportEventHeader     = "X-Heimdall-Event"
	ReportDeliveryHeader  = "X-Heimdall-Delivery"
	ReportTimestampHeader = "X-Heimdall-Timestamp" // Unix seconds
	ReportSignatureHeader = "X-Heimdall-Signature" // "sha256=<hex>"
)

// ReportHook posts signed ReportEvents to one https URL.
type ReportHook struct {
	URL    string
	Secret []byte
	// Client must be supplied by the caller (an allowlisted client for the
	// URL's host only).
	Client *http.Client
	Retry  Retry
	Now    func() time.Time // nil = time.Now
}

// NewDelivery returns a fresh delivery id.
func NewDelivery() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ReportSignature signs a timestamp and body with secret, as the
// X-Heimdall-Signature header carries it.
func ReportSignature(secret []byte, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// Send posts ev, retrying like the other webhooks. Each attempt is signed
// with a fresh timestamp, so a retry isn't refused as stale.
func (h *ReportHook) Send(ctx context.Context, ev ReportEvent) error {
	if h.Client == nil {
		return errors.New("notify: report webhook needs an HTTP client")
	}
	if len(h.Secret) < 16 {
		return errors.New("notify: report webhook secret is missing or too short")
	}
	if _, err := WebhookURL(h.URL); err != nil {
		return errors.New("notify: report webhook: " + err.Error())
	}
	if ev.Delivery == "" {
		ev.Delivery = NewDelivery()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	now := h.Now
	if now == nil {
		now = time.Now
	}
	header := func() http.Header {
		ts := strconv.FormatInt(now().Unix(), 10)
		return http.Header{
			ReportEventHeader:     {ev.Event},
			ReportDeliveryHeader:  {ev.Delivery},
			ReportTimestampHeader: {ts},
			ReportSignatureHeader: {ReportSignature(h.Secret, ts, body)},
		}
	}
	return postBodyWith(ctx, h.Client, h.Retry, h.URL, "report webhook", body, "application/json", header)
}
