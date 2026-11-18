#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/nginx-state.sh [SHELL]: unit tests for collect.sh's nginx
# settings (--nginx) from fixtures: includes followed in place (globs,
# relative paths, a file including itself), HTTP/2 from a listen flag
# (which covers every server on that port), http2 on in a server or
# inherited from http{}, QUIC listens, the PROXY protocol, mail{},
# resolver and mp4, and whether nginx needs a restart. No root, no nginx.
# Run by `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

n=$t/nginx
mkdir -p "$n/conf.d" "$n/sites-enabled" "$n/snippets" "$t/run" "$t/proc/123"
cat >"$n/nginx.conf" <<EOF
user www-data;
pid $t/run/nginx.pid;
events { worker_connections 768; }
http {
	include mime.types; # not there: skipped
	# http2 on;
	resolver 192.0.2.53 valid=30s;
	include conf.d/*.conf;
	include $n/sites-enabled/*;
}
mail {
	server { listen 25; protocol smtp; }
}
EOF
cat >"$n/sites-enabled/a" <<'EOF'
server {
	listen 443 ssl http2;
	server_name a.example.com;
	root /srv/a/public;
	location /x { root /srv/a/other; }
}
EOF
# No http2 of its own, but on port 443, where a's listen turned it on.
printf 'server { listen [::]:443 ssl; server_name b.example.com; root /srv/b/public; }\n' >"$n/sites-enabled/b"
printf 'server {\n  listen 8080;\n  http2 on;\n  root "/srv/c/public/";\n  include snippets/quic.conf;\n}\n' >"$n/sites-enabled/c"
printf 'listen 8443 quic reuseport;\n' >"$n/snippets/quic.conf"
printf 'server { listen 8081; http2 off; location / { proxy_pass http://127.0.0.1:9; } }\n' >"$n/sites-enabled/d"
printf 'server { listen 9000 proxy_protocol; root /srv/e; location ~ \\.mp4$ { mp4; } }\ninclude conf.d/e.conf;\n' >"$n/conf.d/e.conf"
printf '123 (nginx) S 1 123 123 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n' >"$t/proc/123/stat"
printf '123\n' >"$t/run/nginx.pid"
: >"$t/nginx-bin"

state() { # state CONF BTIME
	printf 'cpu 0\nbtime %s\n' "$2" >"$t/proc/stat"
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	HEIMDALL_ALLOW_ROOT=1 HEIMDALL_NGINX_CONF="$1" HEIMDALL_NGINX_BIN="$t/nginx-bin" HEIMDALL_PROC="$t/proc" $sh "$collect" --nginx
}

run() {
	# Booted long ago, so nginx started (1s after boot) before its binary
	# was installed (now): it needs a restart.
	want='v1 servers=5 h2=3 h3=1 pp=1 mail=1 resolver=1 mp4=1 restart=1;r=/srv/e|-;r=/srv/a/public|h2;r=/srv/b/public|h2;r=/srv/c/public|h2'
	got=$(state "$n/nginx.conf" 1000)
	[ "$got" = "$want" ] || fail "got:
$got
want:
$want"
	printf 'ok   nginx settings (%s)\n' "$sh"

	# Started after the binary was installed.
	got=$(state "$n/nginx.conf" "$(($(date +%s) + 60))")
	case $got in *' restart=0;'*) ;; *) fail "fresh start: $got" ;; esac
	printf 'ok   nginx running its installed binary (%s)\n' "$sh"

	# http2 on in http{}: every server inherits it. Not running: restart=-.
	printf 'pid %s/run/none.pid;\nhttp {\n  http2 on;\n  server { listen 80; root /srv/x; }\n  server { listen 81; http2 off; }\n}\n' "$t" >"$t/inherit.conf"
	got=$(state "$t/inherit.conf" 1000)
	[ "$got" = 'v1 servers=2 h2=1 h3=0 pp=0 mail=0 resolver=0 mp4=0 restart=-;r=/srv/x|h2' ] || fail "inherited: $got"
	printf 'ok   nginx http2 inherited from http{} (%s)\n' "$sh"

	# No nginx: "none", so the hub forgets what it had.
	got=$(state "$t/missing.conf" 1000)
	[ "$got" = none ] || fail "no nginx: got '$got'"
	printf 'ok   nginx absent (%s)\n' "$sh"

	# An include naming shell syntax is skipped, never run.
	# shellcheck disable=SC2016 # the command substitutions are the point
	printf 'http { include "$(touch %s/pwned)"; include `touch %s/pwned2`; server { listen 80; } }\n' "$t" "$t" >"$t/evil.conf"
	got=$(state "$t/evil.conf" 1000)
	if [ -e "$t/pwned" ] || [ -e "$t/pwned2" ]; then fail "an include ran a command"; fi
	case $got in 'v1 servers=1 h2=0 '*) ;; *) fail "evil: $got" ;; esac
	printf 'ok   nginx include patterns never reach the shell unchecked (%s)\n' "$sh"
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
