# Releasing Heimdall

A release is a `vX.Y.Z` tag on `main`. Pushing the tag runs the release workflow, which builds the files, writes `SHA256SUMS`, signs it with Sigstore and attests the binaries. Hubs then find it: each one checks GitHub every hour and, with `[updates] auto_install` (the default), installs a release once it has been out for `soak` (2h by default). An admin can also install it at once from **Admin > Updates**. So merging and tagging is the whole job: nobody needs to sign in to a hub.

The tag is the gate: everything on `main` at that point ships to every hub that installs on its own. Tag only what passed CI.

## 1. Bump the versions, in the PR that ships

Every release:
- `collector/collect.sh`: `VERSION=X.Y.Z`
- `collector/collect.ps1`: `$script:CollectorVersion = 'X.Y.Z'`

Only when something under `collector/` changed (other than those two lines):
- `internal/updates/collector.go`: `CollectorChanged = "vX.Y.Z"`
- `internal/updates/collector_test.go`: `collectorSum`. Run `go test ./internal/updates/`; the failing test prints the new value.

Put the version in the PR title, e.g. `Something useful (0.5.47)`.

## 2. Before you push

```sh
gofmt -l cmd internal deploy      # prints nothing
make check                        # tests, vet, lint
go test -tags dev ./internal/web/
make shellcheck
make test-collector               # when collector/ changed (needs Docker)
```

**Never put real names in anything that reaches GitHub**: code, tests, fixtures, docs, commit messages, PR text, release notes. No organization, company, server, domain, tailnet or cloud-resource names, no chat or bot IDs, no IP addresses, no personal email addresses. Use placeholders: `web-01`, `web-02`, `acme`, `example.com`.

## 3. Merge, then tag

Squash-merge the PR once CI passes, then:

```sh
scripts/release.sh vX.Y.Z
```

It refuses unless `main`'s `collect.sh` is at that version, tags `origin/main`, waits for the release workflow, then downloads the release and checks every file against `SHA256SUMS`, the binary's build attestation and its version. It needs `gh` signed in as someone allowed to create `v*` tags.

## If something goes wrong

- **The release workflow failed:** fix it on `main` in a new PR and release the next patch version. Don't move or reuse a tag that was pushed.
- **A hub's upgrade failed:** the installer put the previous version and database back, and **Admin > Updates** shows why with the installer's output. Automatic install won't retry that release; the next release, or **Install** on that page, tries again.
- **A release is bad:** release a fixed patch version. Hubs only ever move forward.
