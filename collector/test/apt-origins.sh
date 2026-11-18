#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/apt-origins.sh [SHELL]: unit tests for collect.sh's
# third-party package sources (--origins) from fixtures: apt's downloaded
# lists (InRelease with its signature, a flat repository's Release), the
# distro's own sources skipped (ESM too), and only installed packages at
# the version a third-party source offers. No root, no apt. Run by
# `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

l=$t/lists
mkdir -p "$l"
signed() { # signed ORIGIN: an InRelease's head
	printf -- '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: %s\nLabel: x\nSuite: jammy\n' "$1"
}
signed Ubuntu >"$l/archive.ubuntu.com_ubuntu_dists_jammy-updates_InRelease"
printf 'Package: nginx\nVersion: 1.18.0-6ubuntu14.4\n\nPackage: curl\nVersion: 7.81.0-1ubuntu1.20\n' \
	>"$l/archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages"
signed UbuntuESMApps >"$l/esm.ubuntu.com_apps_ubuntu_dists_jammy-apps-security_InRelease"
printf 'Package: redis\nVersion: 5:6.0.16-1ubuntu1+esm1\n' >"$l/esm.ubuntu.com_apps_ubuntu_dists_jammy-apps-security_main_binary-amd64_Packages"
signed nginx >"$l/nginx.org_packages_ubuntu_dists_jammy_InRelease"
printf 'Package: nginx\nVersion: 1.30.6-1~jammy\nArchitecture: amd64\n\nPackage: nginx\nVersion: 1.30.7-1~jammy\n\nPackage: nginx-module-njs\nVersion: 1.30.6+0.8.4-1~jammy\n' \
	>"$l/nginx.org_packages_ubuntu_dists_jammy_nginx_binary-amd64_Packages"
signed LP-PPA-ondrej-php >"$l/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_jammy_InRelease"
printf 'Package: php8.3-fpm\nVersion: 8.3.14-1+ubuntu22.04.1+deb.sury.org+1\n\nPackage: php8.3-cli\nVersion: 8.3.14-1+ubuntu22.04.1+deb.sury.org+1\n' \
	>"$l/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_jammy_main_binary-amd64_Packages"
# A flat repository: Release (unsigned), and an Origin with a space.
printf 'Origin: Acme Corp\nLabel: acme\n' >"$l/repo.example.com_apt_._Release"
printf 'Package: acme-agent\nVersion: 2.0.1\n' >"$l/repo.example.com_apt_._Packages"
cat >"$t/installed" <<'EOF'
ii  nginx 1.30.6-1~jammy
ii  nginx-module-njs 1.30.6+0.8.4-1~jammy
ii  php8.3-fpm 8.3.14-1+ubuntu22.04.1+deb.sury.org+1
rc  php8.3-cli 8.3.14-1+ubuntu22.04.1+deb.sury.org+1
ii  curl 7.81.0-1ubuntu1.20
ii  redis 5:6.0.16-1ubuntu1+esm1
ii  acme-agent 2.0.1
EOF

origins() { # origins LISTS INSTALLED
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	HEIMDALL_ALLOW_ROOT=1 HEIMDALL_APT_LISTS="$1" HEIMDALL_DPKG_INSTALLED="$2" $sh "$collect" --origins
}

run() {
	want='v1 Acme-Corp=acme-agent;LP-PPA-ondrej-php=php8.3-fpm;nginx=nginx,nginx-module-njs'
	got=$(origins "$l" "$t/installed")
	[ "$got" = "$want" ] || fail "got '$got', want '$want'"
	printf 'ok   origins (%s)\n' "$sh"

	# Only the distro's packages: "v1" alone, so the hub knows it's none.
	printf 'ii  curl 7.81.0-1ubuntu1.20\nii  nginx 1.18.0-6ubuntu14.4\n' >"$t/distro-only"
	got=$(origins "$l" "$t/distro-only")
	[ "$got" = v1 ] || fail "distro only: got '$got'"
	printf 'ok   origins, distro packages only (%s)\n' "$sh"

	# No apt lists: nothing.
	got=$(origins "$t/none" "$t/installed")
	[ -z "$got" ] || fail "no lists: got '$got'"
	printf 'ok   origins without apt (%s)\n' "$sh"

	# Many packages: cut between names, within 6000 characters.
	mkdir -p "$t/big"
	signed BigVendor >"$t/big/big.example.com_dists_x_InRelease"
	: >"$t/big/big.example.com_dists_x_main_binary-amd64_Packages"
	: >"$t/big-installed"
	i=0
	while [ $i -lt 600 ]; do
		printf 'Package: libbig-vendor-package%04d\nVersion: 1.0\n\n' $i >>"$t/big/big.example.com_dists_x_main_binary-amd64_Packages"
		printf 'ii  libbig-vendor-package%04d 1.0\n' $i >>"$t/big-installed"
		i=$((i + 1))
	done
	got=$(origins "$t/big" "$t/big-installed")
	n=$(printf '%s' "$got" | wc -c)
	if [ "$n" -gt 6000 ] || [ "$n" -le 5000 ]; then fail "big: $n characters"; fi
	case $got in *,libbig-vendor-package[0-9][0-9][0-9][0-9]) ;; *) fail "big: cut inside a name: ...$(printf '%s' "$got" | tail -c 40)" ;; esac
	printf 'ok   origins, cut at 6000 characters (%s)\n' "$sh"
}

if [ $# -gt 0 ]; then
	sh=$1
	run
	exit 0
fi
for sh in dash bash "busybox sh"; do
	command -v "${sh%% *}" >/dev/null 2>&1 || continue
	run
done
