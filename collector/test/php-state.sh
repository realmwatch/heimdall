#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/php-state.sh [SHELL]: unit tests for collect.sh's
# X-Heimdall-PHP (--php) and X-Heimdall-Apt (--apt) values from fixtures:
# running PHP-FPMs found by master process, pool socket and pid file, each
# version once; the apt lists' refresh stamp. No root. Run by
# `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
sh=${1:-sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

mkdir -p "$t/proc/101" "$t/proc/202" "$t/proc/303" "$t/proc/404" "$t/run"
# 8.1's master, retitled; a pool worker; something else; 8.3's pid file.
printf 'php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)\000\000' >"$t/proc/101/cmdline"
printf 'php-fpm: pool www\000' >"$t/proc/202/cmdline"
printf 'nginx: master process /usr/sbin/nginx\000' >"$t/proc/303/cmdline"
printf '404\n' >"$t/run/php8.3-fpm.pid"
# A stale pid file: its process is gone.
printf '999\n' >"$t/run/php7.4-fpm.pid"
# 8.1 again, by a pool socket (where a real socket can be made).
if command -v python3 >/dev/null 2>&1; then
	python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$t/run/php8.1-fpm-acme.sock"
	python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$t/run/php8.2-fpm.sock"
	sockets=1
else
	sockets=
fi

php() {
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	HEIMDALL_ALLOW_ROOT=1 HEIMDALL_PROC="$t/proc" HEIMDALL_RUN_PHP="$t/run" $sh "$collect" --php
}
got=$(php)
case $got in v2\ cli=*\ fpm=*) ;; *) fail "php: got '$got'" ;; esac
fpm=${got##*fpm=}
if [ -n "$sockets" ]; then want=8.3,8.1,8.2; else want=8.3,8.1; fi
[ "$fpm" = "$want" ] || fail "fpm: got '$fpm', want '$want'"
printf 'ok   php fpm by process, socket and pid file (%s)\n' "$sh"

# Nothing running: "-".
rm -rf "$t/proc"/* "$t/run"/*
got=$(php)
[ "${got##*fpm=}" = "-" ] || fail "nothing running: got '$got'"
printf 'ok   php fpm, none running (%s)\n' "$sh"

apt() {
	# shellcheck disable=SC2086
	HEIMDALL_ALLOW_ROOT=1 HEIMDALL_APT_STAMP="$1" $sh "$collect" --apt
}
: >"$t/stamp"
touch -d '@1764000000' "$t/stamp" 2>/dev/null || touch -t 202511241600.00 "$t/stamp"
got=$(apt "$t/stamp")
case $got in "v1 refreshed="[0-9]*) ;; *) fail "apt: got '$got'" ;; esac
[ "$(apt "$t/missing")" = "v1 refreshed=-" ] || fail "apt without a stamp"
printf 'ok   apt lists refresh stamp (%s)\n' "$sh"
