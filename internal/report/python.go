// SPDX-License-Identifier: AGPL-3.0-or-later

package report

import (
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// systemPython reports whether pkg is the distro's own Python: the
// interpreter its python3 points at, from the distro's archive. The
// distro patches that one for the OS release's life, whatever
// python.org's dates say (Ubuntu 22.04's 3.10 outlives python.org's
// October 2026), and it can't be swapped out: apt and the OS's tools run
// on it. Another python3.X (deadsnakes, or one in universe) ends with its
// branch, as does anything from a third-party source.
func systemPython(pm string, pkgs []store.InventoryPackage, pkg string, origins map[string]string) bool {
	if origins[pkg] != "" {
		return false
	}
	switch pm {
	case "rpm", "apk":
		return pkg == "python3"
	case "dpkg":
		// python3.10 or python3.10-minimal; python3 (a metapackage) is
		// 3.10.6-1~22.04.1 on Ubuntu 22.04.
		minor := strings.TrimSuffix(strings.TrimPrefix(pkg, "python"), "-minimal")
		for _, p := range pkgs {
			if p.Name == "python3" && origins["python3"] == "" {
				return minor != "3" && pythonMinor(p.Version) == minor
			}
		}
	}
	return false
}

// pythonMinor is a Debian package version's major.minor ("3.10" for
// "3.10.6-1~22.04.1"), or "".
func pythonMinor(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}
	if parts[0] == "" || minor == "" {
		return ""
	}
	return parts[0] + "." + minor
}
