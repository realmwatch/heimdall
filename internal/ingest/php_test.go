// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseApt(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	if at, ok := parseApt("v1 refreshed=1764000000", now); !ok || at != time.Unix(1764000000, 0).UTC() {
		t.Errorf("a time: %v %v", at, ok)
	}
	if at, ok := parseApt("v1 refreshed=-", now); !ok || !at.IsZero() {
		t.Errorf("no stamp: %v %v", at, ok)
	}
	for _, bad := range []string{"v2 refreshed=1", "v1 refreshed=x", "v1 refreshed=0", "v1", "v1 refreshed=1 x", "v1 refreshed=" + strconv.FormatInt(now.Add(48*time.Hour).Unix(), 10)} {
		if _, ok := parseApt(bad, now); ok {
			t.Errorf("parseApt(%q) accepted", bad)
		}
	}
}

func TestParsePHP(t *testing.T) {
	for _, c := range []struct {
		in  string
		cli string
		fpm []string
		ok  bool
	}{
		{"v1 cli=8.4 fpm=8.3,8.4", "8.4", []string{"8.3", "8.4"}, true},
		{"v1 cli=- fpm=-", "", []string{}, true},
		{"v1 cli=8.10 fpm=8.10", "8.10", []string{"8.10"}, true},
		{"v2 cli=8.4 fpm=8.1", "8.4", []string{"8.1"}, true},
		{"v3 cli=8.4 fpm=-", "", nil, false},
		{"v1 cli=8.4", "", nil, false},
		{"v1 cli=8.4; fpm=-", "", nil, false},
		{"v1 cli=8 fpm=-", "", nil, false},
		{"v1 cli=8.4 fpm=8.3,x", "", nil, false},
		{"v1 cli=8.4 fpm=8.3 extra", "", nil, false},
	} {
		cli, fpm, known, ok := parsePHP(c.in)
		if ok != c.ok || cli != c.cli || (ok && !slices.Equal(fpm, c.fpm)) || known != (ok && strings.HasPrefix(c.in, "v2")) {
			t.Errorf("parsePHP(%q) = %q %q %v, want %q %q %v", c.in, cli, fpm, ok, c.cli, c.fpm, c.ok)
		}
	}
}
