// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// NginxHeader carries what the collector read from nginx's configuration:
//
//	X-Heimdall-Nginx: v1 servers=5 h2=3 h3=1 pp=0 mail=0 resolver=1 mp4=0 restart=0;r=/srv/a/public|h2;r=/srv/b|-
//
// how many http server blocks there are and how many speak HTTP/2 and
// HTTP/3, whether the PROXY protocol, mail{}, a resolver and mp4 are in
// use, whether nginx needs a restart (1, 0, - not running, ? unknown), and
// each server root's HTTP/2. "none" means nginx isn't installed. A header
// for the same reason as PHPHeader; without it the stored state is left
// as it is.
const NginxHeader = "X-Heimdall-Nginx"

const (
	maxNginxLen   = 4096
	maxNginxRoots = 200
)

// parseNginx parses a NginxHeader value. none is true for "none"; ok is
// false when it's malformed.
func parseNginx(v string) (st store.NginxState, none, ok bool) {
	if v == "none" {
		return st, true, true
	}
	if len(v) > maxNginxLen {
		return st, false, false
	}
	parts := strings.Split(v, ";")
	f := strings.Fields(parts[0])
	if len(f) != 9 || f[0] != "v1" {
		return st, false, false
	}
	want := []string{"servers", "h2", "h3", "pp", "mail", "resolver", "mp4", "restart"}
	vals := map[string]string{}
	for i, kv := range f[1:] {
		k, val, found := strings.Cut(kv, "=")
		if !found || k != want[i] {
			return st, false, false
		}
		vals[k] = val
	}
	num := func(k string) (int, bool) {
		n, err := strconv.Atoi(vals[k])
		return n, err == nil && n >= 0 && n <= 100000 && strconv.Itoa(n) == vals[k]
	}
	flag := func(k string) (bool, bool) {
		switch vals[k] {
		case "1":
			return true, true
		case "0":
			return false, true
		}
		return false, false
	}
	var oks [7]bool
	st.Servers, oks[0] = num("servers")
	st.HTTP2, oks[1] = num("h2")
	st.HTTP3, oks[2] = num("h3")
	st.ProxyProtocol, oks[3] = flag("pp")
	st.Mail, oks[4] = flag("mail")
	st.Resolver, oks[5] = flag("resolver")
	st.MP4, oks[6] = flag("mp4")
	for _, o := range oks {
		if !o {
			return st, false, false
		}
	}
	if st.HTTP2 > st.Servers || st.HTTP3 > st.Servers {
		return st, false, false
	}
	switch vals["restart"] {
	case "1":
		st.Restart = "yes"
	case "0":
		st.Restart = "no"
	case "-":
		st.Restart = "stopped"
	case "?":
		st.Restart = "unknown"
	default:
		return st, false, false
	}
	for _, r := range parts[1:] {
		rec, found := strings.CutPrefix(r, "r=")
		if !found {
			return st, false, false
		}
		root, h2, found := strings.Cut(rec, "|")
		if !found || !strings.HasPrefix(root, "/") || len(root) > 512 || (h2 != "h2" && h2 != "-") {
			return st, false, false
		}
		if st.RootHTTP2 == nil {
			st.RootHTTP2 = map[string]bool{}
		}
		if len(st.RootHTTP2) >= maxNginxRoots {
			break
		}
		// Two server blocks with one root (http and https): either
		// speaking HTTP/2 counts.
		st.RootHTTP2[root] = st.RootHTTP2[root] || h2 == "h2"
	}
	return st, false, true
}

func (h *Handler) recordNginx(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(NginxHeader)
	if len(vals) != 1 {
		return
	}
	st, none, ok := parseNginx(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + NginxHeader + " header")
		return
	}
	var err error
	if none {
		err = h.store.ClearHostNginx(ctx, host.ID)
	} else {
		err = h.store.SetHostNginx(ctx, host.ID, st, h.acc.Now())
	}
	if err != nil {
		log.Warn("nginx settings not recorded", "err", err)
	}
}
