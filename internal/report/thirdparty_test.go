// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"reflect"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestThirdPartySources(t *testing.T) {
	pkgs := []store.InventoryPackage{
		{Name: "nginx", Version: "1.30.6-1~jammy", SourceName: "nginx"},
		{Name: "php8.3-fpm", Version: "8.3.14-1+deb.sury.org+1", SourceName: "php8.3"},
		{Name: "libgd3", Version: "2.3.3-9+deb.sury.org+1", Arch: "amd64", SourceName: "libgd2"},
		{Name: "libgd3", Version: "2.3.3-9+deb.sury.org+1", Arch: "i386", SourceName: "libgd2"},
		{Name: "curl", Version: "7.81.0-1ubuntu1.20"},
	}
	origins := map[string]string{"nginx": "nginx", "php8.3-fpm": "LP-PPA-ondrej-php", "libgd3": "LP-PPA-ondrej-php", "gone": "nginx"}
	got := thirdPartySources(origins, pkgs)
	want := []ThirdPartySource{
		{Origin: "LP-PPA-ondrej-php", Packages: []string{"libgd3", "php8.3-fpm"}},
		{Origin: "nginx", Packages: []string{"nginx"}, Checked: []string{"nginx"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if u := got[0].Unchecked(); !reflect.DeepEqual(u, []string{"libgd3", "php8.3-fpm"}) {
		t.Errorf("unchecked = %v", u)
	}
	if u := got[1].Unchecked(); u != nil {
		t.Errorf("nginx unchecked = %v", u)
	}
	if thirdPartySources(nil, pkgs) != nil || thirdPartySources(map[string]string{}, pkgs) != nil {
		t.Error("no origins should give nil")
	}
}

func TestNginxSuryBuild(t *testing.T) {
	v := "1.26.3-1+ubuntu22.04.1+deb.sury.org+1"
	if got := nginxSuryBuild([]store.InventoryPackage{{Name: "nginx-common", Version: v}, {Name: "nginx", Version: v}}); got != v {
		t.Errorf("got %q", got)
	}
	if got := nginxSuryBuild([]store.InventoryPackage{{Name: "nginx", Version: "1.30.6-1~jammy"}}); got != "" {
		t.Errorf("nginx.org's build: %q", got)
	}
}
