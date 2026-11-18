// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestRuntimeStatus(t *testing.T) {
	host := Host{
		Runtimes: []Runtime{
			{Name: "nginx", Version: "1.30.6", Package: "nginx"},
			{Name: "php", Version: "8.3.6", Package: "php8.3-cli"},
			{Name: "php", Version: "8.1.2", Package: "php8.1-cli"},
			{Name: "python", Version: "3.12.3", Package: "python3.12"},
			{Name: "nodejs", Version: "20.1.0", Package: "nodejs"},
		},
		Findings: []Finding{
			{Package: "nginx", Binaries: []string{"nginx"}, Fixed: "1.30.7"},
			{Package: "php8.3", Binaries: []string{"php8.3-cli", "php8.3-fpm"}, KEV: true},
			{Package: "php8.1", Binaries: []string{"php8.1-cli"}, InNews: true, Fixed: "8.1.2-1ubuntu2.20"},
			// A site's finding never colors the OS runtime.
			{Package: "nodejs", Site: "/srv/app", KEV: true},
		},
	}
	runtimeStatus(&host, []store.InventoryPackage{{Name: "python3.12", PendingVersion: "3.12.3-1ubuntu0.9"}})
	want := map[string]string{"nginx": "outdated", "php8.3-cli": "exploited", "php8.1-cli": "exploited", "python3.12": "outdated", "nodejs": ""}
	for _, rt := range host.Runtimes {
		if rt.Status != want[rt.Package] {
			t.Errorf("%s: %q (%s), want %q", rt.Package, rt.Status, rt.StatusNote, want[rt.Package])
		}
	}
	if n := host.Runtimes[1].StatusNote; !strings.Contains(n, "CISA KEV") {
		t.Errorf("KEV note = %q", n)
	}
	if n := host.Runtimes[3].StatusNote; !strings.Contains(n, "3.12.3-1ubuntu0.9") {
		t.Errorf("pending note = %q", n)
	}
}

func TestThirdPartyNginx(t *testing.T) {
	pkgs := []store.InventoryPackage{{Name: "nginx", Version: "1.18.0-6ubuntu14.4"}}
	if thirdPartyNginx(pkgs, "nginx", nil) {
		t.Error("Ubuntu's build is the distro's")
	}
	if !thirdPartyNginx(pkgs, "nginx", map[string]string{"nginx": "acme-repo"}) {
		t.Error("an origin makes it third-party")
	}
	if !thirdPartyNginx([]store.InventoryPackage{{Name: "nginx", Version: "1.30.6-1~jammy"}}, "nginx", nil) {
		t.Error("nginx.org's build is third-party")
	}
}
