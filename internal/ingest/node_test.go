// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"reflect"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseNode(t *testing.T) {
	n, ok := parseNode("v1 bin=/opt/node/22/bin/node@22.11.0@1 bin=/usr/bin/node@-@0 bin=/home/acme/.nvm/versions/node/v18.20.4/bin/node@18.20.4@1" +
		" site=/home/acme/example.com|/opt/node/22/bin/node|v22 site=/var/www/app|-|>=18+<21+||+^22 site=/srv/none|-|-" +
		" bin=/opt/node/22/bin/node@22.12.0@0 bin=relative@1.2.3@1 bin=/opt/x/../node@1.2.3@0 bin=/opt/node/20/bin/node@20@0 bin=/opt/n@1.2.3@2" +
		" site=relative|-|v20 site=/srv/bad|/usr/bin/node|$(reboot) site=/srv/../etc|-|20 junk")
	if !ok {
		t.Fatal("rejected")
	}
	want := store.HostNode{
		Bins: []store.NodeBin{
			{Path: "/opt/node/22/bin/node", Version: "22.11.0", Running: true},
			{Path: "/usr/bin/node"},
			{Path: "/home/acme/.nvm/versions/node/v18.20.4/bin/node", Version: "18.20.4", Running: true},
		},
		Sites: map[string]store.NodeSite{
			"/home/acme/example.com": {Bin: "/opt/node/22/bin/node", Requirement: "v22"},
			"/var/www/app":           {Requirement: ">=18 <21 || ^22"},
		},
	}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("parseNode =\n%+v\nwant\n%+v", n, want)
	}
	if n, ok := parseNode("v1"); !ok || len(n.Bins) != 0 || len(n.Sites) != 0 {
		t.Errorf("v1 alone: %+v %v", n, ok)
	}
	for _, bad := range []string{"", "v2 bin=/usr/bin/node@-@0", strings.Repeat("x", 9000)} {
		if _, ok := parseNode(bad); ok {
			t.Errorf("parseNode(%.20q) accepted", bad)
		}
	}
}
