// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"slices"

	"github.com/realmwatch/heimdall/internal/feeds/nginx"
	"github.com/realmwatch/heimdall/internal/findings"
	"github.com/realmwatch/heimdall/internal/store"
)

// ThirdPartySource is one apt source other than the distro's, and the
// installed packages it supplied.
type ThirdPartySource struct {
	// Origin is the source's Release Origin ("nginx", "LP-PPA-ondrej-php").
	Origin   string   `json:"origin"`
	Packages []string `json:"packages"`
	// Checked are those an upstream project's own advisories cover
	// (nginx.org's for nginx); the rest aren't checked against any.
	Checked []string `json:"checked,omitempty"`
}

// Unchecked are the packages no advisories cover.
func (s ThirdPartySource) Unchecked() []string {
	var out []string
	for _, p := range s.Packages {
		if !slices.Contains(s.Checked, p) {
			out = append(out, p)
		}
	}
	return out
}

// thirdPartySources groups the host's installed third-party packages by
// source, sources sorted by name. Packages the collector named that
// aren't installed any more are left out.
func thirdPartySources(origins map[string]string, pkgs []store.InventoryPackage) []ThirdPartySource {
	if len(origins) == 0 {
		return nil
	}
	by := map[string]*ThirdPartySource{}
	for _, p := range pkgs {
		o := origins[p.Name]
		if o == "" {
			continue
		}
		src := by[o]
		if src == nil {
			src = &ThirdPartySource{Origin: o}
			by[o] = src
		}
		if slices.Contains(src.Packages, p.Name) {
			continue // one name, several architectures
		}
		src.Packages = append(src.Packages, p.Name)
		if findings.UpstreamChecked(p) {
			src.Checked = append(src.Checked, p.Name)
		}
	}
	var out []ThirdPartySource
	for _, src := range by {
		slices.Sort(src.Packages)
		slices.Sort(src.Checked)
		out = append(out, *src)
	}
	slices.SortFunc(out, func(a, b ThirdPartySource) int {
		switch {
		case a.Origin < b.Origin:
			return -1
		case a.Origin > b.Origin:
			return 1
		}
		return 0
	})
	return out
}

// nginxSuryBuild is the version of nginx installed from Ondřej Surý's
// builds, or "".
func nginxSuryBuild(pkgs []store.InventoryPackage) string {
	for _, p := range pkgs {
		if p.Name == "nginx" && nginx.IsSuryBuild(p.Version) {
			return p.Version
		}
	}
	return ""
}
