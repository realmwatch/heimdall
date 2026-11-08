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

// AgentsHeader carries the systemd services named *-agent installed on the
// host: "v1 name,name", or "v1 -" for none. A collector that can't tell
// sends no header, which leaves the stored value alone.
const AgentsHeader = "X-Heimdall-Agents"

const maxAgentsHeader = 1024

var agentsRe = regexp.MustCompile(`^(-|[a-z0-9][a-z0-9_.-]{0,127}(,[a-z0-9][a-z0-9_.-]{0,127})*)$`)

// parseAgents returns the stored form of a header value.
func parseAgents(v string) (string, bool) {
	list, ok := strings.CutPrefix(strings.TrimSpace(v), "v1 ")
	if !ok || len(v) > maxAgentsHeader || !agentsRe.MatchString(list) {
		return "", false
	}
	return list, true
}

func (h *Handler) recordAgents(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(AgentsHeader)
	if len(vals) != 1 {
		return
	}
	list, ok := parseAgents(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + AgentsHeader + " header")
		return
	}
	if err := h.store.SetHostAgents(ctx, host.ID, list); err != nil {
		log.Warn("host agents not recorded", "err", err)
	}
}
