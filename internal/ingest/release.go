// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/realmwatch/heimdall/internal/leftovers"
	"github.com/realmwatch/heimdall/internal/store"
)

// recordRelease stores the collector's leftovers.Header: apt sources and
// packages left from an older release, and what loads them. Without it
// (an older collector, or no apt) the stored state is left as it is.
func (h *Handler) recordRelease(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(leftovers.Header)
	if len(vals) != 1 {
		return
	}
	st, err := leftovers.Parse(vals[0])
	if err != nil {
		log.Warn("ignored a malformed "+leftovers.Header+" header", "err", err)
		return
	}
	b, err := json.Marshal(st)
	if err == nil {
		err = h.store.SetHostRelease(ctx, host.ID, b, h.acc.Now())
	}
	if err != nil {
		log.Warn("release state not recorded", "err", err)
	}
}
