// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestSystemPython(t *testing.T) {
	jammy := []store.InventoryPackage{
		{Name: "python3", Version: "3.10.6-1~22.04.1"},
		{Name: "python3.10", Version: "3.10.12-1~22.04.10"},
		{Name: "python3.12", Version: "3.12.9-1+jammy1"},
	}
	cases := []struct {
		name    string
		pm      string
		pkgs    []store.InventoryPackage
		pkg     string
		origins map[string]string
		want    bool
	}{
		{"jammy's default", "dpkg", jammy, "python3.10", nil, true},
		{"its -minimal", "dpkg", jammy, "python3.10-minimal", nil, true},
		{"another python3.X", "dpkg", jammy, "python3.12", nil, false},
		{"default from a third-party source", "dpkg", jammy, "python3.10", map[string]string{"python3.10": "LP-PPA-deadsnakes"}, false},
		{"python3 itself from a third-party source", "dpkg", jammy, "python3.10", map[string]string{"python3": "acme-repo"}, false},
		{"no python3 package", "dpkg", jammy[1:], "python3.10", nil, false},
		{"rpm's python3", "rpm", nil, "python3", nil, true},
		{"rpm's python3.11", "rpm", nil, "python3.11", nil, false},
		{"apk's python3", "apk", nil, "python3", nil, true},
		{"unknown package manager", "", jammy, "python3.10", nil, false},
	}
	for _, c := range cases {
		if got := systemPython(c.pm, c.pkgs, c.pkg, c.origins); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	for v, want := range map[string]string{"3.10.6-1~22.04.1": "3.10", "1:3.11.2-1": "3.11", "3.9": "3.9", "3": "", "": "", "3.x": ""} {
		if got := pythonMinor(v); got != want {
			t.Errorf("pythonMinor(%q) = %q, want %q", v, got, want)
		}
	}
}
