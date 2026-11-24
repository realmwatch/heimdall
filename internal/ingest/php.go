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

// PHPHeader says which PHP versions the host uses outside its sites'
// PHP-FPM sockets:
//
//	X-Heimdall-PHP: v2 cli=8.4 fpm=8.3,8.4
//
// cli is the version the command line `php` runs, fpm the versions whose
// PHP-FPM is running; "-" for none. v2 (collector 0.5.45 on) finds them by
// master process and pool socket too, so its list is complete; v1 only
// read pid files, which many hosts don't write. A header for the same reason as
// SiteReposHeader (older hubs reject unknown snapshot fields). Without it
// (an older collector) the stored state is left as it is.
const PHPHeader = "X-Heimdall-PHP"

// parsePHP parses a PHPHeader value. ok is false when it's malformed.
func parsePHP(v string) (cli string, fpm []string, known, ok bool) {
	if len(v) > 512 {
		return "", nil, false, false
	}
	f := strings.Fields(v)
	if len(f) != 3 || (f[0] != "v1" && f[0] != "v2") {
		return "", nil, false, false
	}
	known = f[0] == "v2"
	c, ok1 := strings.CutPrefix(f[1], "cli=")
	p, ok2 := strings.CutPrefix(f[2], "fpm=")
	if !ok1 || !ok2 {
		return "", nil, false, false
	}
	if c != "-" {
		if !store.ValidPHPVersion(c) {
			return "", nil, false, false
		}
		cli = c
	}
	fpm = []string{}
	if p != "-" {
		for x := range strings.SplitSeq(p, ",") {
			if !store.ValidPHPVersion(x) {
				return "", nil, false, false
			}
			fpm = append(fpm, x)
		}
	}
	return cli, fpm, known, true
}

func (h *Handler) recordPHP(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(PHPHeader)
	if len(vals) != 1 {
		return
	}
	cli, fpm, known, ok := parsePHP(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + PHPHeader + " header")
		return
	}
	if err := h.store.SetHostPHP(ctx, host.ID, cli, fpm, known, h.acc.Now()); err != nil {
		log.Warn("PHP state not recorded", "err", err)
	}
}

// AptHeader says when the host's apt package lists were last refreshed
// successfully, as a Unix time ("-" when there's no stamp):
//
//	X-Heimdall-Apt: v1 refreshed=1764000000
//
// Pending updates come from those lists, so old ones hide new updates.
// Without it (an older collector, or no apt) the stored state is left.
const AptHeader = "X-Heimdall-Apt"

// parseApt parses an AptHeader value: zero refreshed when there's no
// stamp. ok is false when it's malformed or the time is absurd.
func parseApt(v string, now time.Time) (refreshed time.Time, ok bool) {
	f := strings.Fields(v)
	if len(v) > 128 || len(f) != 2 || f[0] != "v1" {
		return time.Time{}, false
	}
	r, ok := strings.CutPrefix(f[1], "refreshed=")
	if !ok {
		return time.Time{}, false
	}
	if r == "-" {
		return time.Time{}, true
	}
	n, err := strconv.ParseInt(r, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	t := time.Unix(n, 0).UTC()
	if t.After(now.Add(24 * time.Hour)) {
		return time.Time{}, false
	}
	return t, true
}

func (h *Handler) recordApt(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(AptHeader)
	if len(vals) != 1 {
		return
	}
	at, ok := parseApt(vals[0], h.acc.Now())
	if !ok {
		log.Warn("ignored a malformed " + AptHeader + " header")
		return
	}
	if err := h.store.SetHostApt(ctx, host.ID, at, h.acc.Now()); err != nil {
		log.Warn("apt state not recorded", "err", err)
	}
}
