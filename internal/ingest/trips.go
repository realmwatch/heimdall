// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/realmwatch/heimdall/internal/store"
)

// Tripwire reports (docs/tripwires.md): apps on a host write trips to a
// spool directory, and the collector sends them in a request of their own,
// to the same URL as reports so a proxy that passes only that path still
// works. TripsHeader marks it; the body is one trip per line (NDJSON).
// A bad line is dropped, never the request, so one bad file can't hold up
// the rest.
const (
	TripsHeader      = "X-Heimdall-Trips" // "v1"
	TripsContentType = "application/x-ndjson"
	tripSchema       = "viti.trip.v1"

	maxTripsPerPush = 500
	maxTripLine     = 16 << 10
	maxTripDetail   = 8 << 10
	// Trips older than this, or further in the future than MaxSkew, are dropped.
	maxTripAge = 30 * 24 * time.Hour
	// Trip requests per host per hour, apart from rate_per_host: they come
	// after a report, and from the change watch.
	tripsPerHour = 60
)

var (
	tripULID     = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	tripName     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	tripMethod   = regexp.MustCompile(`^[A-Z]{1,16}$`)
	tripCtxKey   = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	tripSeverity = []string{"noise", "low", "high", "critical"}
	// The request headers a trip may carry (the package's own allowlist).
	tripHeaders = []string{"accept", "accept-language", "referer", "user-agent",
		"cf-connecting-ip", "cf-ray", "cf-ipcountry", "cf-visitor"}
)

type tripJSON struct {
	Schema     string `json:"schema"`
	ID         string `json:"id"`
	Site       string `json:"site"`
	Root       string `json:"root"`
	Tripwire   string `json:"tripwire"`
	Token      string `json:"token"`
	Severity   string `json:"severity"`
	OccurredAt string `json:"occurred_at"`
	Request    *struct {
		IP        string            `json:"ip"`
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		QueryKeys []string          `json:"query_keys"`
		Headers   map[string]string `json:"headers"`
	} `json:"request"`
	Actor struct {
		UserID *string `json:"user_id"`
	} `json:"actor"`
	Context        map[string]any `json:"context"`
	PackageVersion string         `json:"package_version"`
}

// tripText is s without control characters, cut to max bytes (at a rune
// boundary).
func tripText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// parseTrips reads a trips body. Lines that aren't a valid trip are
// skipped; so are duplicates within the body.
func parseTrips(body []byte, now time.Time) []store.Trip {
	var out []store.Trip
	seen := map[string]bool{}
	lines := bufio.NewScanner(bytes.NewReader(body))
	lines.Buffer(make([]byte, 0, 4096), 4*maxTripLine) // a longer line ends the body
	for lines.Scan() && len(out) < maxTripsPerPush {
		t, ok := parseTrip(lines.Bytes(), now)
		if ok && !seen[t.ID] {
			seen[t.ID] = true
			out = append(out, t)
		}
	}
	return out
}

func parseTrip(line []byte, now time.Time) (store.Trip, bool) {
	var j tripJSON
	if len(line) > maxTripLine || len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &j) != nil {
		return store.Trip{}, false
	}
	at, err := time.Parse(time.RFC3339, j.OccurredAt)
	if j.Schema != tripSchema || !tripULID.MatchString(j.ID) || !tripName.MatchString(j.Tripwire) ||
		!slices.Contains(tripSeverity, j.Severity) || err != nil ||
		at.Before(now.Add(-maxTripAge)) || at.After(now.Add(MaxSkew)) {
		return store.Trip{}, false
	}
	t := store.Trip{ID: j.ID, OccurredAt: at.UTC(), Tripwire: j.Tripwire, Severity: j.Severity,
		Site: tripText(j.Site, 255), Root: tripText(j.Root, 512), Token: tripText(j.Token, 255)}
	if j.Actor.UserID != nil {
		t.UserID = tripText(*j.Actor.UserID, 64)
	}
	detail := map[string]any{}
	if r := j.Request; r != nil {
		if a, err := netip.ParseAddr(r.IP); err == nil && a.Zone() == "" {
			t.IP = a.Unmap().String()
		}
		if tripMethod.MatchString(r.Method) {
			t.Method = r.Method
		}
		t.Path = tripText(r.Path, 512)
		keys := []string{}
		for _, k := range r.QueryKeys[:min(len(r.QueryKeys), 50)] {
			keys = append(keys, tripText(k, 64))
		}
		detail["query_keys"] = keys
		headers := map[string]string{}
		for _, h := range tripHeaders {
			if v := tripText(r.Headers[h], 512); v != "" {
				headers[h] = v
			}
		}
		detail["headers"] = headers
	}
	ctx := map[string]any{}
	for k, v := range j.Context {
		if len(ctx) == 20 || !tripCtxKey.MatchString(k) {
			continue
		}
		switch v := v.(type) {
		case string:
			ctx[k] = tripText(v, 200)
		case float64, bool, nil:
			ctx[k] = v
		case []any:
			list := []any{}
			for _, e := range v[:min(len(v), 50)] {
				switch e := e.(type) {
				case string:
					list = append(list, tripText(e, 200))
				case float64, bool, nil:
					list = append(list, e)
				}
			}
			ctx[k] = list
		}
	}
	detail["context"] = ctx
	detail["package_version"] = tripText(j.PackageVersion, 64)
	b, err := json.Marshal(detail)
	if err != nil || len(b) > maxTripDetail {
		delete(detail, "context")
		if b, err = json.Marshal(detail); err != nil {
			return store.Trip{}, false
		}
	}
	t.Detail = string(b)
	return t, true
}

// trips answers a trips request: 200 once stored (the collector deletes
// what it sent only then), 202 for a host waiting for approval (kept).
func (h *Handler) trips(w http.ResponseWriter, r *http.Request, host store.IngestHost, raw []byte, bodyCode int, bodyErr error, log *slog.Logger) {
	if onlyHeader(r, TripsHeader) != "v1" {
		respond(w, http.StatusBadRequest, "unsupported "+TripsHeader)
		return
	}
	if !h.tripsLimit.allow(strconv.FormatInt(host.ID, 10)) {
		log.Warn("trips rejected: rate limited")
		respond(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if host.Awaiting {
		w.Header().Set(PendingHeader, "1")
		respond(w, http.StatusAccepted, "waiting for approval")
		return
	}
	if bodyErr != nil {
		log.Warn("trips rejected: bad body", "status", bodyCode, "err", bodyErr)
		respond(w, bodyCode, bodyErr.Error())
		return
	}
	now := h.acc.Now()
	parsed := parseTrips(raw, now)
	fresh, err := h.store.RecordTrips(r.Context(), host.ID, parsed, now)
	if err != nil {
		log.Error("could not store trips", "err", err)
		unavailable(w, "hub busy, retry later")
		return
	}
	raised := h.raiseTrips(r.Context(), log, host, fresh, now)
	log.Info("trips stored", "sent", bytes.Count(raw, []byte("\n")), "valid", len(parsed), "new", len(fresh), "anomalies", raised)
	respond(w, http.StatusOK, fmt.Sprintf("stored %d trips", len(fresh)))
}

// raiseTrips opens a tripwire anomaly for each new trip above noise: high
// for high and critical (alerted at once), low for low (viti:test's). One
// stays open per tripwire, token, address and day until acknowledged.
// Noise is only stored.
func (h *Handler) raiseTrips(ctx context.Context, log *slog.Logger, host store.IngestHost, fresh []store.Trip, now time.Time) int {
	n := 0
	for _, t := range fresh {
		if t.Severity == "noise" {
			continue
		}
		sev := "high"
		if t.Severity == "low" {
			sev = "low"
		}
		day := t.OccurredAt.Format(time.DateOnly)
		a := store.Anomaly{Rule: "tripwire", Severity: sev, Summary: tripSummary(t), Detail: map[string]any{
			"key":      t.Tripwire + "\x00" + t.Token + "\x00" + t.IP + "\x00" + day,
			"trip_id":  t.ID,
			"tripwire": t.Tripwire, "token": t.Token, "severity": t.Severity,
			"site": t.Site, "ip": t.IP, "path": t.Path, "user_id": t.UserID,
		}}
		ok, err := h.store.AddAnomaly(ctx, host.ID, 0, a, now)
		if err != nil {
			log.Error("could not raise tripwire anomaly", "err", err)
			return n
		}
		if ok {
			n++
		}
	}
	return n
}

// tripSummary, e.g. `Tripwire honey_user ("admin-login") tripped on
// app.example.com from 203.0.113.9 by signed-in user 42 (critical)`.
func tripSummary(t store.Trip) string {
	s := "Tripwire " + t.Tripwire
	if t.Token != "" && t.Token != t.Tripwire {
		s += fmt.Sprintf(" (%q)", tripText(t.Token, 80))
	}
	s += " tripped"
	if t.Site != "" {
		s += " on " + tripText(t.Site, 80)
	}
	if t.IP != "" {
		s += " from " + t.IP
	}
	if t.UserID != "" {
		s += " by signed-in user " + t.UserID
	}
	return s + " (" + t.Severity + ")"
}
