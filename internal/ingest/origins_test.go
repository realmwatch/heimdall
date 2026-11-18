// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"maps"
	"strings"
	"testing"
)

func TestParseOrigins(t *testing.T) {
	for _, c := range []struct {
		in   string
		want map[string]string
		ok   bool
	}{
		{"v1 nginx=nginx,nginx-module-njs;LP-PPA-ondrej-php=php8.3-fpm",
			map[string]string{"nginx": "nginx", "nginx-module-njs": "nginx", "php8.3-fpm": "LP-PPA-ondrej-php"}, true},
		{"v1", map[string]string{}, true},
		{"v1 ", map[string]string{}, true},
		{"v1 Acme-Corp=acme-agent", map[string]string{"acme-agent": "Acme-Corp"}, true},
		{"v2 nginx=nginx", nil, false},
		{"v1 nginx=", nil, false},
		{"v1 =nginx", nil, false},
		{"v1 nginx=Nginx", nil, false},    // package names are lower case
		{"v1 ngi nx=nginx", nil, false},   // a space inside
		{"v1 nginx=nginx;", nil, false},   // a trailing empty group
		{"v1 a/b=nginx", nil, false},      // origin characters
		{"v1 nginx=nginx,,x", nil, false}, // an empty name
		{"v1 nginx=nginx\"x", nil, false}, // a quote
		{"v1x nginx=nginx", nil, false},   // not the version token
	} {
		got, ok := parseOrigins(c.in)
		if ok != c.ok || (ok && !maps.Equal(got, c.want)) {
			t.Errorf("parseOrigins(%q) = %v %v, want %v %v", c.in, got, ok, c.want, c.ok)
		}
	}
	long := "v1 x=" + strings.Repeat("a", maxOriginsLen)
	if _, ok := parseOrigins(long); ok {
		t.Error("an oversized header was accepted")
	}
	var b strings.Builder
	b.WriteString("v1 x=p0")
	for i := 1; i <= maxOriginPkgs; i++ {
		b.WriteString(",p")
		b.WriteString(strings.Repeat("1", 1+i%3))
	}
	if got, ok := parseOrigins(b.String()); ok && len(got) > maxOriginPkgs {
		t.Errorf("accepted %d packages", len(got))
	}
}
