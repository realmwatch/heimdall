// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/realmwatch/heimdall/internal/snapshot"
	"github.com/realmwatch/heimdall/internal/store"
)

// SitesHeader lists the host's nginx sites by vhost file (collector 0.5.46
// on): each enabled site's, and the sites whose vhost is there but not
// enabled, with their server names:
//
//	X-Heimdall-Sites: v1 on <root> <file>;off <root> <file> <name>,<name>
//
// <file> is "-" when the collector couldn't name it. A disabled site is
// left out of the snapshot (no packages, no findings, no PHP in use), so
// this is the only record of it. "v1" alone: no nginx sites. A header for
// the same reason as SiteReposHeader. Bad entries are dropped. Without it
// (an older collector) the stored list is left as it is.
const SitesHeader = "X-Heimdall-Sites"

const maxSitesHeader = 8 << 10

// parseSites parses a SitesHeader value. ok is false when it's malformed.
func parseSites(v string) (sites []store.SiteVhost, ok bool) {
	if len(v) > maxSitesHeader {
		return nil, false
	}
	rest, found := strings.CutPrefix(v, "v1")
	if !found || (rest != "" && rest[0] != ' ') {
		return nil, false
	}
	sites = []store.SiteVhost{}
	seen := map[string]bool{}
	for entry := range strings.SplitSeq(strings.TrimSpace(rest), ";") {
		f := strings.Fields(entry)
		if len(f) < 3 || len(f) > 4 || (f[0] != "on" && f[0] != "off") {
			continue
		}
		root, file := f[1], f[2]
		if !snapshot.ValidSitePath(root) || seen[root] || len(sites) == store.MaxSiteVhosts {
			continue
		}
		if file == "-" || !snapshot.ValidSitePath(file) {
			file = ""
		}
		site := store.SiteVhost{Root: root, Vhost: file, Enabled: f[0] == "on"}
		if len(f) == 4 && !site.Enabled {
			for n := range strings.SplitSeq(f[3], ",") {
				if snapshot.ValidServerName(n) && len(site.Names) < 20 {
					site.Names = append(site.Names, n)
				}
			}
		}
		seen[root] = true
		sites = append(sites, site)
	}
	return sites, true
}

func (h *Handler) recordSites(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(SitesHeader)
	if len(vals) != 1 {
		return
	}
	sites, ok := parseSites(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + SitesHeader + " header")
		return
	}
	if err := h.store.SetHostSiteVhosts(ctx, host.ID, sites); err != nil {
		log.Warn("site vhosts not recorded", "err", err)
	}
}
