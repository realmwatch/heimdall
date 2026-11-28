#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/node-state.sh [SHELL]: unit tests for collect.sh's
# X-Heimdall-Node value (--node) from fixtures: /opt/node installs and
# /usr/bin/node with their node_version.h, running node binaries (an nvm
# one by its path), a site's bin by a process argument inside it, and
# requirements from .nvmrc, .node-version and package.json engines.node.
# No root. Run by `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
sh=${1:-sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
t=$(cd -P "$t" && pwd -P)
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

vh() { # vh PREFIX MAJOR MINOR PATCH
	mkdir -p "$1/bin" "$1/include/node"
	: >"$1/bin/node"
	printf '#define NODE_MAJOR_VERSION %s\n#define NODE_MINOR_VERSION %s\n#define NODE_PATCH_VERSION %s\n' "$2" "$3" "$4" >"$1/include/node/node_version.h"
}
vh "$t/opt/22" 22 11 0
vh "$t/opt/20" 20 18 1
mkdir -p "$t/opt/.22.new/bin" && : >"$t/opt/.22.new/bin/node" # mid-install: skipped
vh "$t/usr" 24 4 1
nvm=$t/home/acme/.nvm/versions/node/v18.20.4/bin/node

mkdir -p "$t/proc/1" "$t/proc/2" "$t/proc/3" "$t/proc/4" "$t/proc/5"
printf '%s\000%s\000' "$t/opt/22/bin/node" "$t/sites/app/server.js" >"$t/proc/1/cmdline"
printf '%s\000--max-old-space-size=512\000%s\000' "$nvm" "$t/sites/legacy/current/worker.js" >"$t/proc/2/cmdline"
printf 'node\000%s\000' "$t/sites/rel/x.js" >"$t/proc/3/cmdline"                # relative argv0: unknown
printf 'php\000artisan\000queue:work\000node\000' >"$t/proc/4/cmdline"           # not node
printf '/usr/local/bin/node worker\000' >"$t/proc/5/cmdline"                      # a space: not a path

mkdir -p "$t/sites/app" "$t/sites/legacy/releases/3" "$t/sites/build" "$t/sites/pkg" "$t/sites/none" "$t/sites/rel"
ln -s "$t/sites/legacy/releases/3" "$t/sites/legacy/current"
printf 'v22\n' >"$t/sites/app/.nvmrc"
printf '20.18\n' >"$t/sites/build/.node-version"
printf '{\n  "name": "x",\n  "engines": {\n    "npm": ">=9",\n    "node": ">=18 <21 || ^22"\n  },\n  "dependencies": {}\n}\n' >"$t/sites/pkg/package.json"

got=$(HEIMDALL_ALLOW_ROOT=1 HEIMDALL_ENV_FILE="$t/missing.env" HEIMDALL_DISCOVER_SITES=0 \
	HEIMDALL_SITES="$t/sites/app $t/sites/legacy/current $t/sites/build $t/sites/pkg $t/sites/none $t/sites/rel" \
	HEIMDALL_PROC="$t/proc" HEIMDALL_NODE_OPT="$t/opt" HEIMDALL_NODE_USR="$t/usr" $sh "$collect" --node)
want="v1 bin=$t/opt/20/bin/node@20.18.1@0 bin=$t/opt/22/bin/node@22.11.0@1 bin=$t/usr/bin/node@24.4.1@0 bin=$nvm@18.20.4@1 site=$t/sites/app|$t/opt/22/bin/node|v22 site=$t/sites/legacy/current|$nvm|- site=$t/sites/build|-|20.18 site=$t/sites/pkg|-|>=18+<21+||+^22"
[ "$got" = "$want" ] || fail "node:
got  $got
want $want"
printf 'ok   node binaries, running, sites and requirements (%s)\n' "$sh"

# Nothing at all: just v1.
got=$(HEIMDALL_ALLOW_ROOT=1 HEIMDALL_ENV_FILE="$t/missing.env" HEIMDALL_DISCOVER_SITES=0 HEIMDALL_SITES= \
	HEIMDALL_PROC="$t/empty" HEIMDALL_NODE_OPT="$t/none" HEIMDALL_NODE_USR="$t/none" $sh "$collect" --node)
[ "$got" = v1 ] || fail "none: got '$got'"
printf 'ok   node, none (%s)\n' "$sh"
