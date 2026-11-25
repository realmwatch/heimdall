#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# scripts/release.sh vX.Y.Z: tag origin/main as vX.Y.Z, wait for the release
# workflow, and check what it published. Run it after the PR that bumps the
# versions (RELEASING.md) is merged. It works in a temporary worktree, so
# the current checkout is never touched. Needs git, gh (signed in with the
# right to create v* tags) and sha256sum.
set -eu
V=${1:?usage: scripts/release.sh vX.Y.Z}
case $V in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "not a release tag: $V" >&2; exit 1 ;; esac
repo=realmwatch/heimdall
R=$(git rev-parse --show-toplevel)
W=$(mktemp -d)
trap 'cd "$R"; git worktree remove --force "$W" >/dev/null 2>&1 || rm -rf "$W"' EXIT
git -C "$R" fetch -q origin
git -C "$R" worktree add -q --detach "$W" origin/main
cd "$W"
want=${V#v}
got=$(sed -n 's/^VERSION=//p' collector/collect.sh)
[ "$got" = "$want" ] || { echo "collector/collect.sh VERSION=$got, not $want: merge the version bump first" >&2; exit 1; }
grep -q "CollectorVersion = '$want'" collector/collect.ps1 || { echo "collector/collect.ps1 isn't at $want" >&2; exit 1; }
if git ls-remote --exit-code --tags origin "refs/tags/$V" >/dev/null 2>&1; then
	echo "$V is already tagged" >&2
	exit 1
fi
git tag -a "$V" -m "Heimdall $V"
git push -q origin "$V"
# Wait for the run for THIS tag (GitHub can be slow to start it, or drop
# the event); never fall back to an older release's run.
run=
for _ in $(seq 60); do
	run=$(gh run list --repo "$repo" --workflow release --event push --branch "$V" --limit 1 --json databaseId --jq '.[0].databaseId // empty')
	[ -n "$run" ] && break
	sleep 5
done
[ -n "$run" ] || { echo "no release run started for $V after 5 minutes; re-push the tag: git push origin :refs/tags/$V && git push origin $V" >&2; exit 1; }
gh run watch "$run" --repo "$repo" --exit-status --interval 10 >/dev/null
# What it published: every file matches SHA256SUMS, the binary has a build
# attestation from this repository, and it says it's $V.
D=$W/.release
mkdir "$D"
gh release download "$V" --repo "$repo" --dir "$D" >/dev/null
(cd "$D" && sha256sum --quiet -c SHA256SUMS) || { echo "$V: a file doesn't match SHA256SUMS" >&2; exit 1; }
gh attestation verify "$D/heimdall-linux-amd64" --repo "$repo" >/dev/null || { echo "$V: no valid build attestation" >&2; exit 1; }
chmod +x "$D/heimdall-linux-amd64"
[ "$("$D/heimdall-linux-amd64" version 2>/dev/null | head -n 1)" = "$V" ] || { echo "$V: the binary reports another version" >&2; exit 1; }
echo "released $V"
