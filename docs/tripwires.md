# Tripwires (opt-in)

Apps can plant tripwires of their own: decoy paths scanners probe, breadcrumbs only someone reading the source would find, and honey users, tokens and records. Legitimate users never touch them, so every trip is worth knowing about. Heimdall collects the trips from every server and alerts on the ones that matter.

For Laravel apps, [laravel-viti](https://github.com/realmwatch/laravel-viti) plants them. Any app can write trips in the same format.

## Turn it on

On each server that runs such an app:

```sh
sudo heimdall-collect upgrade --tripwires      # on
sudo heimdall-collect upgrade --no-tripwires   # off, and the waiting trips deleted
```

The same options work with `install.sh`. Re-running the installer or `upgrade` keeps the current choice (`HEIMDALL_TRIPWIRES` in `collect.env`).

This creates the spool directory, `/var/lib/heimdall-viti`, with mode `1733`, owned by `heimdall`. Any local user can add a file there, such as each site's PHP-FPM user, but only the collector can list, read or delete the files. The app needs no Heimdall token or secret.

## How a trip travels

1. The app writes the trip to `/var/lib/heimdall-viti/<id>.json`. It writes under a dot name first and then renames it, so the collector never sees half a file.
2. The change watch sees the new file and starts a report about a minute later. The usual [cap on event reports](collector.md#the-cap-on-event-reports) applies: at most 12 an hour. Without systemd, trips go with the hourly report.
3. After the report, the collector sends up to 200 waiting trips (256 KB) in a request of their own. It uses the same URL and token as the report, so a proxy that passes only `/api/v1/ingest` still works.
4. Once the hub has stored them (HTTP 200), the collector deletes them. Otherwise they wait for the next report.

Deleting sent trips changes the directory, so one more report follows a minute later. It's usually unchanged, and the cap applies to it as well.

The collector treats the directory as hostile, because anyone on the server can write to it. It reads only regular files, never a symlink, that:

- have a trip's name (a 26-character ULID plus `.json`);
- are at most 16 KiB;
- hold one line that starts as a `viti.trip.v1` object does.

It deletes anything else it finds there, and unfinished writes (dot names) older than an hour. If more than 5,000 trips pile up, the oldest are deleted.

## On the hub

The hub checks every field, strips control characters and keeps only:

- the request headers on the allowlist: `accept`, `accept-language`, `referer`, `user-agent`, `cf-connecting-ip`, `cf-ray`, `cf-ipcountry` and `cf-visitor`;
- the names of query parameters;
- the tripwire's scalar context;
- a user ID.

It never stores a request body, a cookie, a credential or a query value, because the app never sends them. Trips older than 30 days, or more than 15 minutes in the future, are dropped. Repeats of a trip ID are ignored.

What happens next depends on the trip's severity:

| Trip severity | What happens |
|---|---|
| `noise` (scanners probing decoy paths) | Stored only. |
| `low` (for example `php artisan viti:test`) | A low `tripwire` anomaly, shown on Anomalies, with no alert. |
| `high`, `critical` | A high `tripwire` anomaly, alerted at once. A signed-in user tripping one is always `critical`. |

Only one anomaly stays open per tripwire, trap, address and day until it's acknowledged. Alerts name the rule only ("an app's tripwire was tripped"). The trip's details, such as the path, address and site, stay on the hub.

Trips are kept for 90 days, and requests carrying trips are limited to 60 per host per hour.

The `site` and `root` a trip names are the app's own claims. What the hub knows for certain is which server sent it, because the collector authenticated that.

## The trip format: `viti.trip.v1`

One JSON object per file and per line. The [package's contract](https://github.com/realmwatch/laravel-viti/blob/main/docs/heimdall-contract.md) describes every field. These ones are required:

- `schema`: `viti.trip.v1`;
- `id`: a ULID;
- `tripwire`: snake_case, at most 64 characters;
- `severity`: `noise`, `low`, `high` or `critical`;
- `occurred_at`: RFC 3339.

## Check it

```sh
php artisan viti:test                       # in the app: writes a low trip
sudo -u heimdall heimdall-collect --trips   # on the server: what the next report sends
sudo systemctl start heimdall-collect       # send it now
```

A low "Tripwire test tripped" anomaly then appears on the host's Anomalies.
