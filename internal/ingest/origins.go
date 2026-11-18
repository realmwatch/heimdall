// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// OriginsHeader names the installed packages that came from an apt source
// other than the distro's, grouped by that source's Origin:
//
//	X-Heimdall-Origins: v1 nginx=nginx,nginx-module-njs;LP-PPA-ondrej-php=php8.3-fpm
//
// "v1" alone means every package is the distro's. Their versions aren't
// the distro's, so findings don't judge them by the distro's advisories
// (internal/findings/upstream.go). A header for the same reason as
// PHPHeader. Without it (an older collector, or no apt) the stored state
// is left as it is.
const OriginsHeader = "X-Heimdall-Origins"

// maxOrigins caps the header (the collector sends at most 6000 characters)
// and how many packages it may name.
const (
	maxOriginsLen = 8000
	maxOriginPkgs = 2000
)

var (
	originRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,40}$`)
	originPkgRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,199}$`)
)

// parseOrigins parses an OriginsHeader value into package name → origin.
// ok is false when it's malformed.
func parseOrigins(v string) (map[string]string, bool) {
	if len(v) > maxOriginsLen {
		return nil, false
	}
	rest, ok := strings.CutPrefix(v, "v1")
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return out, true
	}
	if strings.ContainsAny(rest, " \t") {
		return nil, false
	}
	for group := range strings.SplitSeq(rest, ";") {
		origin, pkgs, ok := strings.Cut(group, "=")
		if !ok || !originRe.MatchString(origin) || pkgs == "" {
			return nil, false
		}
		for p := range strings.SplitSeq(pkgs, ",") {
			if !originPkgRe.MatchString(p) {
				return nil, false
			}
			if len(out) >= maxOriginPkgs {
				return nil, false
			}
			out[p] = origin
		}
	}
	return out, true
}

func (h *Handler) recordOrigins(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(OriginsHeader)
	if len(vals) != 1 {
		return
	}
	origins, ok := parseOrigins(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + OriginsHeader + " header")
		return
	}
	if err := h.store.SetHostOrigins(ctx, host.ID, origins, h.acc.Now()); err != nil {
		log.Warn("package origins not recorded", "err", err)
	}
}
