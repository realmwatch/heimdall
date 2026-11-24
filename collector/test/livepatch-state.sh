#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# collector/test/livepatch-state.sh [SHELL]: unit tests for collect.sh's
# X-Heimdall-Livepatch value (--livepatch) from fixtures: a patch applied
# or mid-transition, Canonical's client status (the running kernel's
# entry, CVE ids by pattern, bad JSON), and what a pending reboot is for.
# No root. Run by `make test-collector`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
collect=$here/collect.sh
sh=${1:-sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { printf 'FAIL (%s): %s\n' "$sh" "$*" >&2; exit 1; }

lp() { # lp SYS STATUS PKGS
	# shellcheck disable=SC2086 # $sh may be "busybox sh"
	HEIMDALL_ALLOW_ROOT=1 HEIMDALL_LIVEPATCH_SYS="$1" HEIMDALL_LIVEPATCH_STATUS="$2" HEIMDALL_REBOOT_PKGS="$3" $sh "$collect" --livepatch
}
mkdir -p "$t/sys/lkp_Ubuntu_6_8_0_1073_azure_108"
printf '1\n' >"$t/sys/lkp_Ubuntu_6_8_0_1073_azure_108/enabled"
printf '0\n' >"$t/sys/lkp_Ubuntu_6_8_0_1073_azure_108/transition"
# Two kernels listed; only the running one's fixes count.
cat >"$t/status.json" <<'JSON'
{"client-version":"10.11.2","status":[
 {"kernel":"6.8.0-1070.77-azure","running":false,"livepatch":{"patchState":"nothing-to-apply","fixes":"* cve-2020-0001"}},
 {"kernel":"6.8.0-1073.80-azure","running":true,"livepatch":{"checkState":"checked","patchState":"applied","version":"108.1",
  "fixes":"* cve-2026-1234 nf_tables\n* CVE-2026-2345 bluetooth\n* cve-2026-1234 again"},"supported":"supported","upgradeRequiredDate":"2027-01-31"}]}
JSON
printf 'linux-image-6.8.0-1074-azure\nlinux-base\n' >"$t/pkgs-kernel"
printf 'linux-image-6.8.0-1074-azure\nlibc6\n' >"$t/pkgs-other"

got=$(lp "$t/sys" "$t/status.json" "$t/pkgs-kernel")
case $got in
"v1 applied=1 state=applied version=108.1 support=supported checked="[0-9]*" reboot=kernel fixes=CVE-2026-1234,CVE-2026-2345") ;;
*) fail "applied: got '$got'" ;;
esac
printf 'ok   livepatch applied, the running kernel'"'"'s fixes (%s)\n' "$sh"

got=$(lp "$t/sys" "$t/status.json" "$t/pkgs-other")
case $got in *" reboot=other "*) ;; *) fail "other reboot: got '$got'" ;; esac
got=$(lp "$t/sys" "$t/status.json" "$t/none")
case $got in *" reboot=- "*) ;; *) fail "no reboot: got '$got'" ;; esac
printf 'ok   livepatch, what a reboot is for (%s)\n' "$sh"

# Mid-transition: not applied yet.
printf '1\n' >"$t/sys/lkp_Ubuntu_6_8_0_1073_azure_108/transition"
got=$(lp "$t/sys" "$t/status.json" "$t/none")
case $got in "v1 applied=0 "*) ;; *) fail "transition: got '$got'" ;; esac
printf 'ok   livepatch mid-transition (%s)\n' "$sh"

# No client status, or not JSON: applied from the kernel, the rest "-".
printf '0\n' >"$t/sys/lkp_Ubuntu_6_8_0_1073_azure_108/transition"
got=$(lp "$t/sys" "$t/missing.json" "$t/none")
[ "$got" = "v1 applied=1 state=- version=- support=- checked=- reboot=- fixes=-" ] || fail "no client: got '$got'"
printf 'not json at all\n' >"$t/bad.json"
got=$(lp "$t/sys" "$t/bad.json" "$t/none")
case $got in "v1 applied=1 state=- version=- support=- checked="[0-9]*" reboot=- fixes=-") ;; *) fail "bad json: got '$got'" ;; esac
printf 'ok   livepatch without the client, or bad JSON (%s)\n' "$sh"

# A kernel that can't take live patches: nothing at all.
[ -z "$(lp "$t/nosys" "$t/status.json" "$t/none")" ] || fail "no livepatch support should print nothing"
printf 'ok   livepatch unsupported (%s)\n' "$sh"
