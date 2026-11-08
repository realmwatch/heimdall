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
```

With `url` set, a host page gets links next to its findings:

- **Install security updates**, under the patch command and in Pending updates: every finding shown with a fix released, after the severity and fixable filters.
- **Fix \<package\>**, in each package's row: that package's fixable findings.

With `updates_url` set, a host with pending updates also gets **Install all updates**, in the same two places. It names the host and no findings: the tool asks the server what's pending and drafts that. Each link is independent, so either can be on alone. `updates_url` takes only `{org}` and `{host}`. On a hub set up earlier, add the line under `[change_link]` yourself; `heimdall config update` only adds whole sections.

| Placeholder | Becomes |
| --- | --- |
| `{org}` | The org's slug |
| `{host}` | The host's name |
| `{package}` | The package, on a package's link; empty on the "Install security updates" link |
| `{finding}` | Finding ids, comma-separated, most important first (at most 200) |

Each value is URL-escaped. The link opens in a new tab, with no referrer.

- **The link carries pointers, not data.** Heimdall sends the tool nothing. The tool should look the findings up itself (see [Reading findings](#reading-findings)), and should treat the link's parameters as untrusted, as it would any URL someone could send its users.
- **OS packages only, for now.** Site (Composer and npm) findings don't get Fix links yet.
- `url` and `updates_url` must be `https`, or plain `http` for loopback. Unknown placeholders are refused when the config loads.
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
