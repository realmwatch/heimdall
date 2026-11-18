// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"fmt"
	"slices"

	"github.com/realmwatch/heimdall/internal/store"
)

// runtimeStatus marks each runtime exploited or outdated from the host's
// open OS findings on its package and the package's pending update.
func runtimeStatus(host *Host, pkgs []store.InventoryPackage) {
	pending := map[string]string{}
	for _, p := range pkgs {
		if p.PendingVersion != "" {
			pending[p.Name] = p.PendingVersion
		}
	}
	for i := range host.Runtimes {
		rt := &host.Runtimes[i]
		var kev, news, fixable int
		for _, f := range host.Findings {
			if f.Site != "" || (f.Package != rt.Package && !slices.Contains(f.Binaries, rt.Package)) {
				continue
			}
			switch {
			case f.KEV:
				kev++
			case f.InNews:
				news++
			}
			if f.Fixed != "" {
				fixable++
			}
		}
		switch {
		case kev > 0 || news > 0:
			rt.Status = "exploited"
			rt.StatusNote = exploitedNote(kev, news)
		case pending[rt.Package] != "":
			rt.Status = "outdated"
			rt.StatusNote = "An update to " + pending[rt.Package] + " is pending"
		case fixable > 0:
			rt.Status = "outdated"
			rt.StatusNote = fmt.Sprintf("A fix is released for %d of its findings", fixable)
		}
	}
}

func exploitedNote(kev, news int) string {
	switch {
	case kev > 0 && news > 0:
		return fmt.Sprintf("%d known-exploited finding%s (CISA KEV) and %d in a live incident in the news", kev, plural(kev), news)
	case kev > 0:
		return fmt.Sprintf("%d known-exploited finding%s (CISA KEV)", kev, plural(kev))
	}
	return fmt.Sprintf("%d finding%s named by a live incident in the news", news, plural(news))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
