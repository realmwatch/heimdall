// SPDX-License-Identifier: AGPL-3.0-or-later

package leftovers

import (
	"strings"
	"testing"
)

func TestSteps(t *testing.T) {
	f := &Finding{Codename: "jammy",
		Sources: []StaleSource{
			{File: "sources.list.d/ondrej-ubuntu-php-focal.list", URI: "http://ppa.launchpad.net/ondrej/php/ubuntu", Suite: "focal", Current: "jammy"},
			{File: "sources.list.d/pgdg.list", URI: "https://apt.postgresql.org/pub/repos/apt", Suite: "focal-pgdg", Current: "jammy-pgdg"},
		},
		OldBuilds: []Leftover{{Name: "libzip4", Version: "1.7.3-1+ubuntu20.04.1+deb.sury.org+2"}},
		Obsolete: []Leftover{
			{Name: "libpcre16-3", Version: "2:8.45-1+ubuntu20.04.1+deb.sury.org+1", Plan: PlanReplace},
			{Name: "libargon2-1", Version: "0~20190702-0.1+ubuntu20.04.1+deb.sury.org+1", Plan: PlanReview, Reason: "loaded by php8.1-fpm.service"},
			{Name: "libpq5", Version: "17.5-1.pgdg20.04+1", Plan: PlanReview, Reason: "loaded by php8.3-fpm.service"},
			{Name: "python2.7-minimal", Version: "2.7.18-1~20.04.4", Plan: PlanRemove},
			{Name: "oldthing", Version: "1.0-1"},
		},
		UsedBy: []Use{{PID: 10, Unit: "php8.1-fpm.service", Library: "/usr/lib/libargon2.so.1", Package: "libargon2-1"},
			{PID: 11, Unit: "php8.3-fpm.service", Library: "/usr/lib/libpq.so.5", Package: "libpq5"}},
	}
	steps := Steps(f)
	var titles []string
	for _, s := range steps {
		titles = append(titles, s.Title)
	}
	want := []string{"Fix the apt sources that name an older release", "Reinstall what's still built for an older release",
		"Replace these with jammy's build", "Restart what loads them", "Remove these: nothing needs them",
		"Decide on these once the rest is done", "Upgrade the collector to plan these"}
	if strings.Join(titles, "|") != strings.Join(want, "|") {
		t.Fatalf("steps:\n%s", strings.Join(titles, "\n"))
	}
	if got := strings.Join(steps[0].Packages, ","); got != "libpcre16-3,libargon2-1,libpq5,libzip4" {
		t.Errorf("source step packages = %s", got)
	}
	if !strings.Contains(steps[0].Detail, "pgdg.list (focal-pgdg → jammy-pgdg)") {
		t.Errorf("source step detail = %s", steps[0].Detail)
	}
	if d := steps[5].Detail; !steps[5].Waiting || !strings.Contains(d, "libpq5: loaded by php8.3-fpm.service (likely from sources.list.d/pgdg.list") ||
		!strings.Contains(d, "libargon2-1: loaded by php8.1-fpm.service (likely from sources.list.d/ondrej-ubuntu-php-focal.list") {
		t.Errorf("review step = %+v", steps[5])
	}
	if d := steps[3].Detail; !strings.Contains(d, "restart php8.1-fpm.service, php8.3-fpm.service") {
		t.Errorf("restart step = %s", d)
	}
	if Steps(nil) != nil || len(Steps(&Finding{Codename: "jammy"})) != 0 {
		t.Error("steps for nothing")
	}
}
