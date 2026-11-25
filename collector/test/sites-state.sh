#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/sites-state.sh [SHELL]: unit tests for collect.sh's
# X-Heimdall-Sites value (--sites) from a fixture nginx tree: each enabled
# site's vhost file, and sites whose vhost is available but not enabled or
# set aside in a *-disabled/ folder. No root. Run by `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
sh=${1:-sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

n=$t/nginx
mkdir -p "$n/sites-available" "$n/sites-enabled" "$n/conf.d" "$n/acme-disabled" "$t/www/app/public" "$t/www/old" "$t/www/gone"
: >"$t/www/app/composer.json"
vhost() { printf 'server {\n  server_name %s;\n  root %s;\n}\n' "$2" "$3" >"$1"; }
# Enabled through a link; enabled as a regular conf.d file; available
# only; set aside by the change tool; the stock default, never listed.
vhost "$n/sites-available/app" 'example.com www.example.com' "$t/www/app/public"
ln -s "$n/sites-available/app" "$n/sites-enabled/app"
vhost "$n/conf.d/blog.conf" 'blog.example.com' "$t/www/blog"
vhost "$n/sites-available/old" 'old.example.com' "$t/www/old"
vhost "$n/acme-disabled/gone.2" 'gone.example.com' "$t/www/gone"
vhost "$n/sites-available/default" '_' /var/www/html
# An available copy of an enabled site isn't a disabled one.
vhost "$n/sites-available/app-copy" 'example.com' "$t/www/app/public"

sites() {
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	HEIMDALL_ALLOW_ROOT=1 HEIMDALL_NGINX_DIR="$n" $sh "$collect" --sites
}
got=$(sites)
want="v1 on $t/www/app $n/sites-enabled/app;on $t/www/blog $n/conf.d/blog.conf;off $t/www/gone $n/acme-disabled/gone.2 gone.example.com;off $t/www/old $n/sites-available/old old.example.com"
# The order of the off entries follows the glob order: available, then set aside.
want2="v1 on $t/www/app $n/sites-enabled/app;on $t/www/blog $n/conf.d/blog.conf;off $t/www/old $n/sites-available/old old.example.com;off $t/www/gone $n/acme-disabled/gone.2 gone.example.com"
[ "$got" = "$want" ] || [ "$got" = "$want2" ] || fail "sites: got '$got'"
printf 'ok   sites: enabled files, available-only and set-aside sites (%s)\n' "$sh"

# Turning discovery off sends no sites.
# shellcheck disable=SC2086
got=$(HEIMDALL_ALLOW_ROOT=1 HEIMDALL_NGINX_DIR="$n" HEIMDALL_DISCOVER_SITES=0 $sh "$collect" --sites)
[ "$got" = v1 ] || fail "discovery off: got '$got'"
printf 'ok   sites: discovery off (%s)\n' "$sh"

# Nothing at all.
rm -rf "$n"
[ "$(sites)" = v1 ] || fail "no nginx"
printf 'ok   sites: no nginx (%s)\n' "$sh"
