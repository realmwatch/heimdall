// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"slices"
	"testing"
	"time"
)

func TestParseLivepatch(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	l, ok := parseLivepatch("v1 applied=1 state=applied version=108.1 support=supported checked=1764000000 reboot=kernel fixes=CVE-2026-1234,CVE-2026-2345", now)
	if !ok || !l.Applied || l.State != "applied" || l.Version != "108.1" || l.Support != "supported" || l.Reboot != "kernel" ||
		l.Checked != time.Unix(1764000000, 0).UTC() || !slices.Equal(l.Fixes, []string{"CVE-2026-1234", "CVE-2026-2345"}) {
		t.Errorf("full: %+v %v", l, ok)
	}
	l, ok = parseLivepatch("v1 applied=0 state=- version=- support=- checked=- reboot=- fixes=-", now)
	if !ok || l.Applied || l.State != "" || !l.Checked.IsZero() || l.Fixes != nil || l.Reboot != "" {
		t.Errorf("unknowns: %+v %v", l, ok)
	}
	for _, bad := range []string{
		"v2 applied=1 state=- version=- support=- checked=- reboot=- fixes=-",
		"v1 applied=yes state=- version=- support=- checked=- reboot=- fixes=-",
		"v1 applied=1 state=- version=- support=- checked=x reboot=- fixes=-",
		"v1 applied=1 state=- version=- support=- checked=- reboot=maybe fixes=-",
		"v1 applied=1 state=- version=- support=- checked=- reboot=-",
		"v1 applied=1 state=- version=- support=- checked=- reboot=- other=-",
	} {
		if _, ok := parseLivepatch(bad, now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
