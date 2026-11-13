#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/release-state.sh [SHELL]: unit tests for collect.sh's
# release leftovers (--release) from fixtures: apt sources (.list and
# deb822 .sources, disabled and commented ones skipped), files the release
# upgrader left, obsolete packages and ones only an older release's suites
# offer (from `apt list --installed` output), and processes mapping their
# libraries. No root, no apt. Run by `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

mkdir -p "$t/apt/sources.list.d" "$t/info" "$t/proc/812" "$t/proc/900" "$t/proc/77" "$t/etc"
printf 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n' >"$t/etc/os-release"
cat >"$t/apt/sources.list" <<'SRC'
deb http://archive.ubuntu.com/ubuntu jammy main universe
# deb http://archive.ubuntu.com/ubuntu focal main
deb-src http://archive.ubuntu.com/ubuntu jammy main
SRC
printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/pg.gpg] http://apt.postgresql.org/pub/repos/apt focal-pgdg main # re-enabled\n' >"$t/apt/sources.list.d/pgdg.list"
printf 'deb http://apt.postgresql.org/pub/repos/apt focal-pgdg main\n' >"$t/apt/sources.list.d/pgdg.list.distUpgrade"
cat >"$t/apt/sources.list.d/ondrej.sources" <<'SRC'
Types: deb
URIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu/
Suites: focal jammy
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mQINBGYo0vEBEAC0

Types: deb
URIs: https://example.com/off
Suites: focal
Components: main
Enabled: no
SRC
cat >"$t/apt.list" <<'LIST'
Listing...
curl/jammy-updates,jammy-security,now 7.81.0-1ubuntu1.20 amd64 [installed]
libssl1.1/now 1.1.1f-1ubuntu2.24+esm6 amd64 [installed,local]
libpq5/focal-pgdg,now 17.5-1.pgdg20.04+1 amd64 [installed,upgradable to: 17.6-1.pgdg20.04+1]
libzip4/focal,now 1.7.3-1+ubuntu20.04.1+deb.sury.org+2 amd64 [installed,automatic]
php8.3-fpm/focal,jammy,now 8.3.14-1+ubuntu22.04.1+deb.sury.org+1 amd64 [installed]
liblocale-gettext-perl/jammy,now 1.07-4build3 amd64 [installed,automatic]
linux-image-5.4.0-200-generic/now 5.4.0-200.220 amd64 [installed,local]
LIST
printf '/.\n/usr/lib/x86_64-linux-gnu/libssl.so.1.1\n/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1\n/usr/share/doc/libssl1.1\n' >"$t/info/libssl1.1:amd64.list"
printf '/usr/lib/x86_64-linux-gnu/libpq.so.5.17\n/usr/lib/x86_64-linux-gnu/libpq.so.5\n' >"$t/info/libpq5:amd64.list"
# php-fpm maps the leftover OpenSSL (through /lib, which is /usr/lib) and
# libpq; a shell maps only the current curl; one process isn't readable.
cat >"$t/proc/812/maps" <<'MAPS'
7f00 r-xp 00000000 08:01 1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
7f01 r-xp 00000000 08:01 2 /lib/x86_64-linux-gnu/libcrypto.so.1.1 (deleted)
7f02 r-xp 00000000 08:01 3 /usr/lib/x86_64-linux-gnu/libpq.so.5.17
7f03 r-xp 00000000 08:01 3 /usr/lib/x86_64-linux-gnu/libpq.so.5.17
MAPS
printf '0::/system.slice/php8.3-fpm.service\n' >"$t/proc/812/cgroup"
printf 'php-fpm8.3\n' >"$t/proc/812/comm"
printf '7f00 r-xp 00000000 08:01 9 /usr/lib/x86_64-linux-gnu/libcurl.so.4\n' >"$t/proc/900/maps"
printf '0::/user.slice/user-1000.slice/session-3.scope\n' >"$t/proc/900/cgroup"
printf 'bash\n' >"$t/proc/900/comm"
: >"$t/proc/77/maps"
chmod 000 "$t/proc/77/maps"

want='v1 cn=jammy maps=2/3
u=sources.list.d/pgdg.list.distUpgrade
p=812|php8.3-fpm.service|php-fpm8.3|libssl.so.1.1|libssl1.1
p=812|php8.3-fpm.service|php-fpm8.3|libcrypto.so.1.1|libssl1.1
p=812|php8.3-fpm.service|php-fpm8.3|libpq.so.5.17|libpq5
s=sources.list|http://archive.ubuntu.com/ubuntu|jammy|main,universe
s=sources.list.d/pgdg.list|http://apt.postgresql.org/pub/repos/apt|focal-pgdg|main
s=sources.list.d/ondrej.sources|https://ppa.launchpadcontent.net/ondrej/php/ubuntu/|focal|main
s=sources.list.d/ondrej.sources|https://ppa.launchpadcontent.net/ondrej/php/ubuntu/|jammy|main
o=libssl1.1|1.1.1f-1ubuntu2.24+esm6
b=libpq5|17.5-1.pgdg20.04+1|focal-pgdg
b=libzip4|1.7.3-1+ubuntu20.04.1+deb.sury.org+2|focal'

run() {
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	got=$(HEIMDALL_ALLOW_ROOT=1 HEIMDALL_OS_RELEASE="$t/etc/os-release" HEIMDALL_APT_DIR="$t/apt" HEIMDALL_APT_LIST="$t/apt.list" \
		HEIMDALL_DPKG_INFO="$t/info" HEIMDALL_PROC="$t/proc" $sh "$collect" --release)
	if [ "$(id -u)" -eq 0 ]; then # root reads the unreadable one anyway
		got=$(printf '%s\n' "$got" | sed 's/^v1 cn=jammy maps=3\/3$/v1 cn=jammy maps=2\/3/')
	fi
	[ "$got" = "$want" ] || fail "got:
$got
want:
$want"
	printf 'ok   release state (%s)\n' "$sh"
	# Not apt: nothing at all.
	printf 'ID=alpine\n' >"$t/etc/alpine-release"
	# shellcheck disable=SC2086
	got=$(HEIMDALL_ALLOW_ROOT=1 HEIMDALL_OS_RELEASE="$t/etc/alpine-release" HEIMDALL_APT_DIR="$t/apt" HEIMDALL_APT_LIST="$t/apt.list" $sh "$collect" --release)
	[ -z "$got" ] || fail "no codename: got '$got'"
	printf 'ok   release state without a codename (%s)\n' "$sh"
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
