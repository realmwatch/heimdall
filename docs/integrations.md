# Change-management integrations

Heimdall finds what needs patching and never changes a server itself. If you use a separate tool that does make changes (a deploy or patch-management tool, a runbook system, your own scripts), Heimdall can work with it without gaining any power of its own:

- **Fix links** take you from a finding to a draft of its fix in that tool.
- **The report webhook** tells the tool when a host has reported again, so it can check whether the fix worked.
- **MCP** lets the tool read findings by id, and find a host by its machine ID.

None of these lets anyone change anything through Heimdall. The hub still never connects to a server, and holds no credential for the other tool.

## Fix links

```toml
# /etc/heimdall/heimdall.toml
[change_link]
url   = "https://changes.example.com/new?org={org}&host={host}&package={package}&findings={finding}"
label = "Fix"
updates_url = "https://changes.example.com/updates?org={org}&host={host}"
collector_url = "https://changes.example.com/collector?org={org}&host={host}"
action_url = "https://changes.example.com/propose?action={action}&org={org}&host={host}&{params}"
```

With `url` set, a host page gets links next to its findings:

- **Install security updates**, under the patch command and in Pending updates: every finding shown with a fix released, after the severity and fixable filters.
- **Fix \<package\>**, in each package's row: that package's fixable findings.

With `updates_url` set, a host with pending updates also gets **Install all updates**, in the same two places. It names the host and no findings: the tool asks the server what's pending and drafts that. Each link is independent, so either can be on alone. `updates_url` takes only `{org}` and `{host}`. On a hub set up earlier, add the line under `[change_link]` yourself; `heimdall config update` only adds whole sections.

With `collector_url` set, a host whose collector is behind gets an **update ↗** link in place of its "update available" pill, and its "behind" pill on the host list links to the same address. It takes `{org}` and `{host}`. Without it, or with a current collector, nothing changes.

`action_url` is one link for every other change a host page can propose, so a new action doesn't need a new setting. With it set, each version in a host's **Unused PHP** section gets **Propose removal**, with `{action}` as `php.remove` and `{params}` as `php=8.2`. With two or more, the section's header also gets **Propose removing all N**: one `php.remove` link listing them in version order, `php=8.1%2C8.2` (8.1,8.2). The tool must accept a comma-separated list before you upgrade to a Heimdall release that shows it, and should make one proposal per version so each keeps its own checks and rollback. A host that needs a reboot (one is required, or a newer kernel is installed but not running) gets **Propose reboot** beside its Reboot status and its reboot command, with `{action}` as `system.reboot` and no `{params}`; the tool asks why and checks that the host's agent can reboot. Add support for it in the tool before upgrading to a release that shows it. Old kernels that aren't running get **Propose removal** beside their command, with `{action}` as `kernel.remove` and `{params}` as `kernels=6.8.0-45-generic%2C6.8.0-49-generic` (comma-separated, as `uname -r` prints them, at most 50; the tool must accept as many as Heimdall sends before you upgrade); the tool's agent should decide again when it runs, removing only kernels still installed and older than the running one. A host with [release leftovers](collector.md#release-leftovers) (apt sources, packages or libraries left from an older release by an in-place upgrade) gets **Propose cleanup** on its Release leftovers card, with `{action}` as `release.cleanup`. Its `{params}` are Heimdall's plan for the packages, as comma-separated names (see [Release leftovers](collector.md#release-leftovers)): `keep` (a vendor's `.deb` or one an operator marked to keep, not a leftover: never remove it), `replace` (install the host's release's build in its place) and `remove` (nothing installed needs it), for example `keep=acme-edr%2Cacme-scanner&remove=libwebp6&replace=libpq5`. An obsolete package in none of them is for the tool to judge. Without the plan (an older collector, or a list too long for a link), the link ends in `&`. Either way the tool should ask the host's agent for the current state itself and decide what to change when it runs: retarget or disable stale sources, reinstall old-release builds, restart what loads them, then follow the plan. It should still check the plan on the server, running as root: `apt-get -s` should show a removal taking nothing else, and nothing running should load a library being removed. Heimdall can't see cron, supervisor or systemd, so the tool should repeat those checks on the server when the change runs. The version the command line's `php` points at gets no button, because `php` has to be repointed first; its manual commands stay on the page. A host whose nginx speaks HTTP/2 while an [nginx.org advisory](collector.md#third-party-packages) about HTTP/2 applies gets **Propose turning off HTTP/2** on its nginx card, with `{action}` as `nginx.http2_off` and no `{params}`: the tool's agent should turn HTTP/2 off everywhere (`http2 off;` in `http{}` and each server, and the `http2` flag removed from every `listen`, since that flag turns it on for the whole address and port), run `nginx -t`, reload, and keep a backup so it can be turned back on once nginx is updated. A host whose running nginx started before its binary was installed (an upgrade with no restart, so the old code still runs) gets **Propose restart**, with `{action}` as `service.restart` and `{params}` as `unit=nginx.service`. A host whose nginx is Ondřej Surý's build, from the `ondrej/nginx` PPA Launchpad removed (Laravel Forge's source before about April 2026), gets **Propose switching to nginx.org**, with `{action}` as `nginx.source.nginx_org` and no `{params}`: the tool's agent should remove the PPA's sources file (`add-apt-repository --remove` fails now), add nginx.org's signing key and repository and pin it, drop `load_module` lines for modules nginx.org doesn't ship (brotli, geoip, image-filter, xslt, ssl-ct), upgrade nginx keeping its configuration, run `nginx -t` and restart. Add support for both in the tool before upgrading to a release that shows them.

A site served by nginx whose PHP-FPM version is known, and older than the newest supported PHP (from the [endoflife.date](https://endoflife.date/php) data the hub syncs), gets **Propose PHP upgrade** beside its PHP-FPM version on the site page, for operators. Its `{action}` is `php.upgrade` and its `{params}` are `from=8.1&site=%2Fvar%2Fwww%2Fapp`: the version the site runs now, and the site's root as the collector reports it. It names no target version: the tool should offer the versions the host's OS can install. Heimdall can't see the OS's package sources, so the button's tooltip names the newest supported release only as a hint. An upgrade is a change in stages, each with its own checks and rollback, and the order matters:

1. **The new PHP beside the old.** Install its PHP-FPM with the same extensions as the old version, port the pool and `php.ini` settings, and start it. Nothing the site uses changes, so this can run first, and having it on the server lets you test the code there. On Debian and Ubuntu, installing `phpX.Y-cli` repoints the host-wide `php` at the new version: put it back while other sites use the old one.
2. **The code runs on both versions** (a pull request). What usually blocks a newer PHP is the locked packages' own PHP requirements, not `require.php` (`^8.1` already allows 8.4): update only the packages that block it, keep `config.platform.php` at the old version so the lock still installs there, and widen `require.php` only if it doesn't already allow the new version. Check with `composer check-platform-reqs --lock` and the tests under the new PHP, then merge and deploy. The site still runs the old PHP.
3. **The switch**, once that's deployed. Point only this site's `fastcgi_pass` at the new socket (`nginx -t`, then reload), along with what runs the site's PHP from the command line: its cron entries, queue workers and the deploy's `php` and `composer`. Leave the host-wide `php` alone while other sites use the old version. On a server managed by a hosting panel (Laravel Forge, for example), the panel owns the site's PHP version, nginx config and deploy script: switch it there too, or the panel's next change puts the old version back. Rolling back restores the old socket.
4. **Raise the floor** (a pull request: `require.php` `^8.4`, `config.platform.php` 8.4) only once every host that deploys the repository has switched; before that, `composer install` fails the platform check on the hosts that haven't. This is the point of no return: once it's deployed, switching back to the old PHP breaks the site.

Heimdall can start the two pull requests as Amp threads: see [PHP upgrades](deployment.md#php-upgrades). A tool can link its code steps there: `https://heimdall.example.com/hosts/{org}/{host}/handoff/php?root=<site root>&stage=compat&to=8.4` for step 2, and `stage=floor` for step 4. Heimdall shows the confirm page with that stage and target chosen; nothing starts without an operator's click, and a target that isn't a supported PHP newer than the site's, or a floor above a site's current PHP, is refused there.

Removing the old PHP isn't part of it: once nothing uses it, the host page offers **Propose removal** (`php.remove`). The next report shows each stage: the site's **Requires PHP** after the code changes, and its **PHP-FPM** after the switch. Add support for `php.upgrade` in the tool before upgrading to a Heimdall release that shows it.

With `action_url` set, an open patch plan also gets **Batch N: install updates on N hosts** above its table, one link per batch, for the hosts not yet marked done, so you can work through a maintenance window batch by batch, canaries first. Its `{action}` is `updates.install`, `{host}` is empty, and `{params}` is `hosts=` and the host names, comma-separated: an action on several hosts names them there, and the tool should read `hosts` and ignore `host`. The tool asks each server what's pending and drafts that. A link names at most 100 hosts; a bigger batch gets several links. The tool links one org at a time, so a fleet-wide plan gets one link per batch and org. Only operators see the links. Marking a host done still works as before, and a clean check-in verifies it.

| Placeholder | Becomes |
| --- | --- |
| `{org}` | The org's slug |
| `{host}` | The host's name; empty on an action for several hosts, which names them in `{params}` as `hosts` |
| `{package}` | The package, on a package's link; empty on the "Install security updates" link |
| `{action}` | What to propose, such as `php.remove`, on `action_url` only |
| `{params}` | That action's own query parameters, already escaped, on `action_url` only |
| `{finding}` | Finding ids, comma-separated, most important first (at most 200) |

Each value is URL-escaped. The link opens in a new tab, with no referrer.

- **The link carries pointers, not data.** Heimdall sends the tool nothing. The tool should look the findings up itself (see [Reading findings](#reading-findings)), and should treat the link's parameters as untrusted, as it would any URL someone could send its users.
- **OS packages only, for now.** Site (Composer and npm) findings don't get Fix links yet.
- `url`, `updates_url`, `collector_url` and `action_url` must be `https`, or plain `http` for loopback. Unknown placeholders are refused when the config loads.
- `collector_upgrade_action`, once your tool supports the `collector.upgrade` action, makes the host list offer **Propose collector upgrade (N)**: one `action_url` link per org naming every listed host whose collector is behind (`{params}` `hosts=web-01,web-02`, `{host}` empty, at most 100 hosts per link). It follows the list's filters. Leave it `false` (the default) until the tool has the action, or the link leads nowhere. Each host's own **update** link (`collector_url`) works either way.
- `agent_service`, if set, is the systemd service your tool runs on servers (ending in `-agent`, without `.service`). The host list then gets a column showing where it's installed. It reads the `X-Heimdall-Agents` header from collector 0.5.5 or later, and shows `?` for older collectors and hosts without systemd.
- `label` is a package link's text: at most 24 characters, "Fix" by default.

## Report webhook

```sh
sudo heimdall report-webhook set https://changes.example.com/hooks/heimdall
sudo heimdall restart
sudo heimdall report-webhook test
```

`set` generates a signing secret and prints it once: give it to the receiver. It stores the secret in `/etc/heimdall/report-webhook-secret` (owner-only), and adds `LoadCredential=heimdall-report-webhook:…` to the hub's unit. It also writes `url` under `[report_webhook]`. To use a secret you already have, pipe it in with `--secret-stdin`; it must be at least 32 characters.

Each time the hub accepts a host's report, it POSTs:

```json
{
  "event": "report.received",
  "delivery": "5f0c1e…",
  "org": "acme",
  "host": "web-01",
  "snapshot_id": 4182,
  "changed": true,
  "received_at": "2026-11-02T15:04:05Z"
}
```

- **`changed`:** `true` when the inventory differed from the host's last report. The hub recomputes the host's findings first, then sends this, so the receiver reads the new ones. `false` is an unchanged report (a heartbeat): its findings are as they were.
- **No inventory, no findings.** The event names the report and nothing in it.
- **`delivery`** is random and unique per event. Receivers should refuse one they've seen before.
- `test` sends `"event": "test"` with the same headers.

### Checking the signature

| Header | Value |
| --- | --- |
| `X-Heimdall-Event` | `report.received` or `test` |
| `X-Heimdall-Delivery` | The body's `delivery` |
| `X-Heimdall-Timestamp` | Unix seconds when this attempt was sent |
| `X-Heimdall-Signature` | `sha256=` and the hex HMAC-SHA256 of the timestamp, a `.`, and the raw body, keyed with the secret |

The receiver should:

1. Recompute the signature over the raw body, and compare it in constant time.
2. Refuse a timestamp more than five minutes from its own clock.
3. Refuse a `delivery` it has already handled.

To check your code against a known value: `printf '1700000000.{}' | openssl dgst -sha256 -hmac secret` gives `b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163`.

### Delivery

- Events are sent one at a time, separately from ingest, so a slow receiver never holds up a report. Failures are retried like the notify webhooks: four attempts with backoff, honouring `Retry-After`. Each retry is signed with a fresh timestamp.
- Events can be lost: a receiver that's down for longer than the retries, a full queue (256 events), or a hub restart. **Receivers should poll as well**, for example every 15 minutes, and treat the webhook as "check now".
- The hub may reach only the webhook URL's host, over HTTPS.

## Reading findings

A tool reads Heimdall through [MCP](mcp.md), like any assistant: it uses a token belonging to a Heimdall user with the **viewer** role on the orgs it works with. MCP is read-only for every user.

- **`finding`** takes up to 200 finding ids, the `id` field on the findings from `host` and `patch_priorities`. For each it returns whether the finding is open or resolved, when it was last seen and resolved, the package, and the installed and fixed versions. `package` is the source package that advisories name (`openssl`, `linux`); `binaries` lists the installed binary packages built from it (`libssl3`, `openssl`), which are what a package manager upgrades. A finding keeps its id from report to report while it's open, and again if it comes back. Ids in orgs the user can't see are listed under `not_found`.
- **`host`** takes `machine` instead of `host`: the hex SHA-256 of `heimdall-machine:` followed by the contents of `/etc/machine-id`, which the collector reports. On Windows it's the `MachineGuid` registry value instead of the machine ID. A tool with its own agent on the server can compute the same hash and find the host without matching hostnames. `host` also returns the hash it has for a host.

A typical loop:

1. Someone follows a Fix link.
2. The tool reads those findings with `finding`, and drafts and runs the fix in its own way.
3. The tool waits for a `report.received` with `changed: true` for that host, or polls.
4. It calls `finding` again. Resolved means the fix worked; still open after the next report means it didn't.

## Security notes

- Heimdall stays a sink: none of these features makes the hub call a server or run anything. The webhook is an outbound notice with no data, and Fix links are plain links.
- A forged or replayed webhook can at most make a receiver read sooner, as long as it checks the signature, timestamp and delivery id.
- The signing secret is a systemd credential, never in `heimdall.toml`. Rotate it by running `report-webhook set` again, then updating the receiver.
- A stolen viewer token exposes what that user can see in Heimdall's UI, read-only. Use one user per tool, with access to only the orgs it needs, and revoke its token from the Users page.
