// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"maps"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseNginx(t *testing.T) {
	st, none, ok := parseNginx("v1 servers=5 h2=3 h3=1 pp=1 mail=0 resolver=1 mp4=0 restart=1;r=/srv/a/public|h2;r=/srv/b|-;r=/srv/a/public|-")
	want := store.NginxState{Servers: 5, HTTP2: 3, HTTP3: 1, ProxyProtocol: true, Resolver: true, Restart: "yes",
		RootHTTP2: map[string]bool{"/srv/a/public": true, "/srv/b": false}}
	if !ok || none || st.Servers != want.Servers || st.HTTP2 != want.HTTP2 || st.HTTP3 != want.HTTP3 || st.ProxyProtocol != want.ProxyProtocol ||
		st.Mail || !st.Resolver || st.MP4 || st.Restart != "yes" || !maps.Equal(st.RootHTTP2, want.RootHTTP2) {
		t.Errorf("got %+v %v %v", st, none, ok)
	}
	if _, none, ok := parseNginx("none"); !none || !ok {
		t.Error("none")
	}
	for in, restart := range map[string]string{"0": "no", "-": "stopped", "?": "unknown"} {
		st, _, ok := parseNginx("v1 servers=0 h2=0 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=" + in)
		if !ok || st.Restart != restart || st.RootHTTP2 != nil {
			t.Errorf("restart=%s: %+v %v", in, st, ok)
		}
	}
	for _, bad := range []string{
		"",
		"v2 servers=0 h2=0 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0",
		"v1 servers=0 h2=0 h3=0 pp=0 mail=0 resolver=0 mp4=0",                      // missing restart
		"v1 h2=0 servers=0 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0",            // order
		"v1 servers=1 h2=2 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0",            // more h2 than servers
		"v1 servers=-1 h2=0 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0",           // negative
		"v1 servers=01 h2=0 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0",           // not canonical
		"v1 servers=1 h2=0 h3=0 pp=2 mail=0 resolver=0 mp4=0 restart=0",            // flag
		"v1 servers=1 h2=0 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=x",            // restart
		"v1 servers=1 h2=1 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0;x=/srv|h2",  // record kind
		"v1 servers=1 h2=1 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0;r=srv|h2",   // relative root
		"v1 servers=1 h2=1 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=0;r=/srv|yes", // h2 value
	} {
		if _, _, ok := parseNginx(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
