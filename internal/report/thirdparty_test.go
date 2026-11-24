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
		// PHP is checked against PHP's own advisories; libgd3 by nothing.
		{Origin: "LP-PPA-ondrej-php", Packages: []string{"libgd3", "php8.3-fpm"}, Checked: []string{"php8.3-fpm"}},
		{Origin: "nginx", Packages: []string{"nginx"}, Checked: []string{"nginx"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if u := got[0].Unchecked(); !reflect.DeepEqual(u, []string{"libgd3"}) {
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

func TestExposureLabel(t *testing.T) {
	on, off := true, false
	for f, want := range map[*Finding]string{
		{Feature: "http2", FeatureOn: &on}:  "HTTP/2 on",
		{Feature: "http3", FeatureOn: &off}: "HTTP/3 off",
		{Feature: "http2"}:                  "",
		{Feature: "", FeatureOn: &on}:       "",
	} {
		if got := f.ExposureLabel(); got != want {
			t.Errorf("%+v: %q, want %q", *f, got, want)
		}
	}
	if (Site{}).HTTP2Label() != "" || (Site{HTTP2: &on}).HTTP2Label() != "on" || (Site{HTTP2: &off}).HTTP2Label() != "off" {
		t.Error("site labels")
	}
	h := Host{Nginx: &store.NginxState{Resolver: true, Mail: true}}
	if got := h.NginxAlsoInUse(); len(got) != 2 || got[0] != "mail proxy" || got[1] != "resolver" {
		t.Errorf("also in use = %v", got)
	}
}
