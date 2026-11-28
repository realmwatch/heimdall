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

// NodeHeader says which Node.js binaries the host has, which run, and
// each site's Node:
//
//	X-Heimdall-Node: v1 bin=<path>@<version>@<running> ... site=<root>|<bin>|<requirement> ...
//
// <version> and a site's <bin> and <requirement> are "-" when unknown;
// <running> is 0 or 1; a requirement's spaces are "+". A header for the
// same reason as SiteReposHeader. Bad entries are dropped; they never
// fail the push. Without it (an older collector) the stored state is
// left as it is.
const NodeHeader = "X-Heimdall-Node"

var (
	nodePathRe    = regexp.MustCompile(`^/[A-Za-z0-9._~/+-]{1,250}$`)
	nodeVersionRe = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4}$`)
	siteRootRe    = regexp.MustCompile(`^/[A-Za-z0-9._~/+@-]{0,500}$`)
	nodeReqRe     = regexp.MustCompile(`^[0-9A-Za-z./^~<>=|*+ -]{1,64}$`)
)

// parseNode parses a NodeHeader value. ok is false when it's malformed.
func parseNode(v string) (n store.HostNode, ok bool) {
	if len(v) > 8<<10 {
		return n, false
	}
	f := strings.Fields(v)
	if len(f) == 0 || f[0] != "v1" {
		return n, false
	}
	n.Bins, n.Sites = []store.NodeBin{}, map[string]store.NodeSite{}
	seen := map[string]bool{}
	for _, e := range f[1:] {
		switch {
		case strings.HasPrefix(e, "bin="):
			parts := strings.Split(strings.TrimPrefix(e, "bin="), "@")
			if len(parts) != 3 || !nodePathRe.MatchString(parts[0]) || strings.Contains(parts[0], "..") ||
				(parts[1] != "-" && !nodeVersionRe.MatchString(parts[1])) || (parts[2] != "0" && parts[2] != "1") ||
				seen[parts[0]] || len(n.Bins) == store.MaxNodeBins {
				continue
			}
			seen[parts[0]] = true
			b := store.NodeBin{Path: parts[0], Running: parts[2] == "1"}
			if parts[1] != "-" {
				b.Version = parts[1]
			}
			n.Bins = append(n.Bins, b)
		case strings.HasPrefix(e, "site="):
			parts := strings.SplitN(strings.TrimPrefix(e, "site="), "|", 3)
			if len(parts) != 3 || !siteRootRe.MatchString(parts[0]) || strings.Contains(parts[0], "..") || len(n.Sites) == store.MaxNodeSites {
				continue
			}
			var s store.NodeSite
			if parts[1] != "-" {
				if !nodePathRe.MatchString(parts[1]) || strings.Contains(parts[1], "..") {
					continue
				}
				s.Bin = parts[1]
			}
			if parts[2] != "-" {
				r := strings.ReplaceAll(parts[2], "+", " ")
				if !nodeReqRe.MatchString(r) {
					continue
				}
				s.Requirement = r
			}
			if s == (store.NodeSite{}) {
				continue
			}
			n.Sites[parts[0]] = s
		}
	}
	return n, true
}

func (h *Handler) recordNode(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(NodeHeader)
	if len(vals) != 1 {
		return
	}
	n, ok := parseNode(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + NodeHeader + " header")
		return
	}
	if err := h.store.SetHostNode(ctx, host.ID, n, h.acc.Now()); err != nil {
		log.Warn("Node.js state not recorded", "err", err)
	}
}
