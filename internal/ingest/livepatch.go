// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// LivepatchHeader is the host's live patch state, sent only where the
// kernel can take live patches:
//
//	X-Heimdall-Livepatch: v1 applied=1 state=applied version=108.1 support=supported checked=1764000000 reboot=kernel fixes=CVE-2026-1234,CVE-2026-2345
//
// applied is the kernel's own word; state, version, support and fixes are
// Canonical's client's, checked when it said so; reboot what a pending
// reboot is for (kernel, other). "-" is unknown or none. Without it (an
// older collector, or no live patching) the stored state is left.
const LivepatchHeader = "X-Heimdall-Livepatch"

// parseLivepatch parses a LivepatchHeader value. ok is false when it's
// malformed.
func parseLivepatch(v string, now time.Time) (l store.HostLivepatch, ok bool) {
	if len(v) > 8192 {
		return l, false
	}
	f := strings.Fields(v)
	if len(f) != 8 || f[0] != "v1" {
		return l, false
	}
	vals := map[string]string{}
	for _, kv := range f[1:] {
		k, val, found := strings.Cut(kv, "=")
		if !found || val == "" {
			return l, false
		}
		vals[k] = val
	}
	get := func(k string) string {
		if s := vals[k]; s != "-" && len(s) <= 40 {
			return s
		}
		return ""
	}
	switch vals["applied"] {
	case "1":
		l.Applied = true
	case "0":
	default:
		return l, false
	}
	l.State, l.Version, l.Support = get("state"), get("version"), get("support")
	if c := vals["checked"]; c != "-" {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil || n <= 0 || time.Unix(n, 0).After(now.Add(24*time.Hour)) {
			return l, false
		}
		l.Checked = time.Unix(n, 0).UTC()
	}
	switch r := vals["reboot"]; r {
	case "kernel", "other":
		l.Reboot = r
	case "-":
	default:
		return l, false
	}
	if fx, ok := vals["fixes"]; !ok {
		return l, false
	} else if fx != "-" {
		l.Fixes = strings.Split(fx, ",")
	}
	return l, true
}

func (h *Handler) recordLivepatch(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(LivepatchHeader)
	if len(vals) != 1 {
		return
	}
	l, ok := parseLivepatch(vals[0], h.acc.Now())
	if !ok {
		log.Warn("ignored a malformed " + LivepatchHeader + " header")
		return
	}
	if err := h.store.SetHostLivepatch(ctx, host.ID, l, h.acc.Now()); err != nil {
		log.Warn("live patch state not recorded", "err", err)
	}
}
