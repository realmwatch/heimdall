#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install a Heimdall hub on a fresh Debian/Ubuntu VM, in one step.
#
#   curl -fsSLO https://github.com/realmwatch/heimdall/releases/download/vX.Y.Z/install-hub.sh &&
#     sudo sh install-hub.sh --org acme --ingest-host ingest.acme.example.com --admin you@example.com
#
# Modes:
#   --ingest-host NAME   servers anywhere: Caddy serves ONLY the ingest path
#                        on NAME with an automatic certificate (ports 80/443)
#   --tailnet-only       every server is on your tailnet: ingest is published
#                        with `tailscale serve`, nothing is public
# The UI (and MCP with --mcp) is always tailnet-only via `tailscale serve`.
# Beside it, Caddy binds only this box's non-tailnet addresses (or
# --public-bind ADDR): both use port 443, on different addresses.
#
# Upgrading an existing hub: run the new release's script with just
#   sudo sh install-hub.sh
# (or --version vX.Y.Z). It stops the hub, keeps the previous binary and a
# pre-upgrade copy of the database, migrates, starts it again and rolls
# back automatically if the hub doesn't come up.
#
# Requires Tailscale to be installed and logged in first:
#   curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up --ssh
set -eu
umask 022
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin

HEIMDALL_VERSION=dev # set by `make dist`
RELEASES=${HEIMDALL_RELEASES:-https://github.com/realmwatch/heimdall/releases/download}

die() { printf 'heimdall install-hub: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── Release signature ── (keep this block the same in collect.sh, install.sh
# and install-hub.sh; the pins are also in cmd/heimdall/signature.go and
# install-windows.ps1, and TestSignaturePinsMatch checks they agree.)
# A release's SHA256SUMS must carry a Sigstore signature made by this repo's
# release workflow for a v* tag. cosign checks it: a pinned build, fetched
# once into /usr/local/lib/heimdall and checked against its hash each use.
COSIGN_VERSION=v3.1.4
RELEASE_SIGNER='^https://github.com/realmwatch/heimdall/\.github/workflows/release\.yml@refs/tags/v'

# cosign_bin: print the path of the cosign to check signatures with,
# fetching the pinned build first if it's missing or doesn't match.
cosign_bin() {
	case $(uname -m) in
	x86_64 | amd64) c=amd64 s=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa ;;
	aarch64 | arm64) c=arm64 s=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2 ;;
	armv7l) c=arm s=09e77a313910cf5c4774508d85d017d9c60983f41bf657f83ecbd3892f7952cb ;;
	*) command -v cosign; return ;; # no pinned build: an installed cosign, if any
	esac
	b=/usr/local/lib/heimdall/cosign-$COSIGN_VERSION-$c
	if [ ! -x "$b" ] || ! printf '%s  %s\n' "$s" "$b" | sha256sum -c - >/dev/null 2>&1; then
		printf '==> Fetching cosign %s (once) to check the release signature\n' "$COSIGN_VERSION" >&2
		u=https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$c
		install -d -m 0755 /usr/local/lib/heimdall
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL --proto '=https' --tlsv1.2 -o "$b.tmp" "$u" || return 1
		else
			wget -q -O "$b.tmp" "$u" || return 1
		fi
		if ! printf '%s  %s\n' "$s" "$b.tmp" | sha256sum -c - >/dev/null 2>&1; then
			rm -f "$b.tmp"
			echo "the cosign download doesn't match its pinned hash" >&2
			return 1
		fi
		chmod 0755 "$b.tmp" && mv "$b.tmp" "$b"
	fi
	echo "$b"
}

# verify_release DIR: check DIR/SHA256SUMS against its Sigstore signature
# (DIR/SHA256SUMS.sigstore.json), or exit.
verify_release() {
	[ -s "$1/SHA256SUMS.sigstore.json" ] || die "the release has no signature (SHA256SUMS.sigstore.json); not installing it"
	cosign=$(cosign_bin) || cosign=''
	[ -n "$cosign" ] || die "can't check the release signature: no cosign for $(uname -m); install cosign, or pass --skip-signature-check"
	HOME=$1 "$cosign" verify-blob "$1/SHA256SUMS" --bundle "$1/SHA256SUMS.sigstore.json" \
		--certificate-identity-regexp "$RELEASE_SIGNER" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >"$1/cosign.log" 2>&1 ||
		die "SHA256SUMS signature verification FAILED; not installing it: $(tail -n 1 "$1/cosign.log")"
	printf '==> Sigstore signature verified\n' >&2
}

usage() {
	cat >&2 <<'EOF'
usage: install-hub.sh --org SLUG (--ingest-host NAME | --tailnet-only)
                      [--org-name "Acme Corp"] [--admin EMAIL] [--mcp]
                      [--version vX.Y.Z] [--from-dir DIR] [--no-tailscale]
                      [--skip-signature-check] [--public-bind ADDR|auto]
       install-hub.sh --org SLUG --no-tailscale --ui-url URL --ingest-url URL ...

  --no-tailscale   skip tailscale (UI stays on 127.0.0.1:8080; for testing or
                   if you'll put your own HTTPS proxy in front)
  --ui-url URL, --ingest-url URL
                   with --no-tailscale: your own proxy on this box (e.g.
                   Cloudflare Tunnel with Access) forwards URL to the UI on
                   127.0.0.1:8080 and the ingest URL to 127.0.0.1:8443. No
                   Caddy is installed; both trust the proxy's client address
  --public-bind ADDR|auto
                   the addresses Caddy listens on (repeat it, or separate
                   them with commas). By default, beside `tailscale serve`
                   on 443, Caddy binds every global address except the
                   tailnet's ("auto"); otherwise every address
  --skip-signature-check
                   don't check the release's Sigstore signature, only its
                   checksums (where cosign can't run; not advised)
EOF
	exit 2
}

org='' org_name='' ingest_host='' tailnet_only=0 admin='' mcp=0 version=$HEIMDALL_VERSION from_dir='' use_ts=1 sigcheck=1
proxy_ui='' proxy_ingest='' public_bind=''
while [ $# -gt 0 ]; do
	case $1 in
	--org) org=${2:-}; shift ;;
	--org-name) org_name=${2:-}; shift ;;
	--ingest-host) ingest_host=${2:-}; shift ;;
	--tailnet-only) tailnet_only=1 ;;
	--admin) admin=${2:-}; shift ;;
	--mcp) mcp=1 ;;
	--version) version=${2:-}; shift ;;
	--from-dir) from_dir=${2:-}; shift ;;
	--no-tailscale) use_ts=0 ;;
	--ui-url) proxy_ui=${2:-}; shift ;;
	--ingest-url) proxy_ingest=${2:-}; shift ;;
	--skip-signature-check) sigcheck=0 ;;
	--public-bind) public_bind="$public_bind ${2:-}"; shift ;;
	*) usage ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
upgrade=0
[ ! -e /etc/heimdall/heimdall.toml ] || upgrade=1
if [ "$upgrade" = 1 ]; then
	# Existing hub: networking (tailscale serve, Caddy) and the org stay as
	# they are; only the software is upgraded.
	# --ingest-host and --admin still finish those steps if given.
	org=${org:-existing} use_ts=0
fi
[ -n "$org" ] || usage
case $org in *[!a-z0-9-]* | -* | *-) die "--org must be lowercase letters, digits and '-'" ;; esac
if [ -n "$ingest_host" ]; then
	[ "$tailnet_only" = 0 ] || die "choose --ingest-host or --tailnet-only, not both"
	case $ingest_host in *[!a-z0-9.-]* | .* | *.) die "--ingest-host must be a DNS name" ;; esac
elif [ "$tailnet_only" = 0 ] && [ "$use_ts" = 1 ]; then
	die "choose --ingest-host NAME (servers anywhere) or --tailnet-only"
fi
if [ -n "$proxy_ui$proxy_ingest" ]; then
	if [ "$use_ts" = 1 ] || [ -n "$ingest_host" ] || [ "$tailnet_only" = 1 ]; then
		die "--ui-url and --ingest-url go with --no-tailscale, without --ingest-host or --tailnet-only"
	fi
	for u in "$proxy_ui" "$proxy_ingest"; do
		case $u in https://*/* | *[!A-Za-z0-9:/.-]*) die "--ui-url and --ingest-url must be https://name, with no path" ;; https://?*) ;; *) die "--ui-url and --ingest-url must both be given, as https://name" ;; esac
	done
fi
public_bind=$(printf '%s' "$public_bind" | tr ',' ' ' | xargs)
for a in $public_bind; do
	case $a in
	auto) [ "$public_bind" = auto ] || die "--public-bind auto can't be combined with addresses" ;;
	*[!0-9A-Fa-f:.]* | '') die "--public-bind takes IP addresses (or auto), not $a" ;;
	*[.:]*) ;;
	*) die "--public-bind takes IP addresses (or auto), not $a" ;;
	esac
done
[ -z "$public_bind" ] || [ -n "$ingest_host" ] || [ "$upgrade" = 1 ] || die "--public-bind goes with --ingest-host"
case $version in v[0-9]*.[0-9]*.[0-9]* | dev) ;; *) die "bad --version $version" ;; esac
[ -n "$from_dir" ] || [ "$version" != dev ] || die "this script isn't from a release; pass --version vX.Y.Z or --from-dir"
[ -d /run/systemd/system ] || die "systemd is required"

case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

# Tailscale gives the UI its private HTTPS address.
ts_name=''
if [ "$use_ts" = 1 ]; then
	have tailscale || die "install and log in to Tailscale first: curl -fsSL https://tailscale.com/install.sh | sh && tailscale up --ssh"
	ts_name=$(tailscale status --json 2>/dev/null | sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p' | head -n 1)
	[ -n "$ts_name" ] || die "tailscale isn't logged in (run: tailscale up --ssh)"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() {
	if [ -n "$from_dir" ]; then
		cp "$from_dir/$1" "$work/$1" || die "missing $from_dir/$1"
	else
		curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$1" "$RELEASES/$version/$1" || die "download failed: $1"
	fi
}
say "Fetching Heimdall $version ($arch)"
for f in SHA256SUMS "heimdall-linux-$arch" heimdall.service collect.sh splash.html; do fetch "$f"; done
if [ "$sigcheck" = 1 ]; then
	fetch SHA256SUMS.sigstore.json
	verify_release "$work"
else
	say "WARNING: not checking the release's signature (--skip-signature-check); only its checksums"
fi
(cd "$work" && grep -E " (heimdall-linux-$arch|heimdall\.service|collect\.sh|splash\.html)\$" SHA256SUMS | sha256sum -c - >/dev/null) ||
	die "checksum verification FAILED; not installing"
say "Checksums verified"

hd() { (cd /var/lib/heimdall && runuser -u heimdall-hub -- /usr/local/bin/heimdall -c /etc/heimdall/heimdall.toml "$@"); }

# secrets_key UNIT: the hub's secrets key, which encrypts what it keeps in
# its database for a user (their own Amp API key): 32 random bytes in
# /etc/heimdall/secrets-key, root-only, made once and never printed or
# replaced (a new one would make the saved keys unreadable). UNIT gets
# its LoadCredential line when it hasn't one.
secrets_key() {
	if [ ! -s /etc/heimdall/secrets-key ]; then
		(umask 077 && head -c 32 /dev/urandom >/etc/heimdall/secrets-key.new) ||
			die "couldn't create /etc/heimdall/secrets-key"
		mv /etc/heimdall/secrets-key.new /etc/heimdall/secrets-key
	fi
	chown root:root /etc/heimdall/secrets-key
	chmod 0600 /etc/heimdall/secrets-key
	if ! grep -q '^LoadCredential=heimdall-secrets:' "$1"; then
		awk '{ print } /^\[Service\]$/ { print "LoadCredential=heimdall-secrets:/etc/heimdall/secrets-key" }' "$1" >"$1.new" &&
			mv "$1.new" "$1"
	fi
}

# healthy waits for the service to stay up and the UI to answer.
healthy() {
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
		sleep 1
		systemctl is-active --quiet heimdall || continue
		if have curl; then
			curl -fs -o /dev/null --max-time 2 http://127.0.0.1:8080/login && return 0
		else
			return 0
		fi
	done
	return 1
}

id heimdall-hub >/dev/null 2>&1 || useradd --system --home-dir /var/lib/heimdall --shell /usr/sbin/nologin heimdall-hub
install -d -m 0700 -o heimdall-hub -g heimdall-hub /etc/heimdall /var/lib/heimdall

if [ "$upgrade" = 1 ]; then
	old=$(/usr/local/bin/heimdall version 2>/dev/null || echo unknown)
	say "Upgrading the hub: $old -> $version"
	db=$(sed -n 's/^database *= *"\(.*\)"/\1/p' /etc/heimdall/heimdall.toml | head -n 1)
	case $db in /*) ;; *) db=/etc/heimdall/${db:-heimdall.db} ;; esac
	systemctl stop heimdall
	cp -p /usr/local/bin/heimdall /usr/local/bin/heimdall.previous
	cp -p /etc/systemd/system/heimdall.service "$work/heimdall.service.previous"
	# A consistent pre-upgrade copy, owner-only, next to the database.
	rm -f "$db.pre-upgrade"
	runuser -u heimdall-hub -- sh -c "umask 077 && cp -p '$db' '$db.pre-upgrade'"
	install -m 0755 "$work/heimdall-linux-$arch" /usr/local/bin/heimdall
	# migrate appends config sections for new features (off); keep the old
	# file for a rollback, since older binaries reject keys they don't know.
	cp -p /etc/heimdall/heimdall.toml "$work/heimdall.toml.previous"
	# Keep local additions to the unit (e.g. SSO's LoadCredential line).
	grep -E '^LoadCredential=' "$work/heimdall.service.previous" >"$work/creds" || true
	if [ -s "$work/creds" ]; then
		awk -v f="$work/creds" '{ if ($0 ~ /^#?LoadCredential=/) next; print } /^\[Service\]$/ { while ((getline l < f) > 0) print l }' \
			"$work/heimdall.service" >"$work/heimdall.service.new" && mv "$work/heimdall.service.new" "$work/heimdall.service"
	fi
	secrets_key "$work/heimdall.service"
	install -m 0644 "$work/heimdall.service" /etc/systemd/system/heimdall.service
	systemctl daemon-reload
	if ! hd migrate || ! systemctl start heimdall || ! healthy; then
		say "Upgrade failed; the new version's log:"
		journalctl -u heimdall -n 15 --no-pager -o cat >&2 2>/dev/null || true
		say "Rolling back to $old"
		systemctl stop heimdall 2>/dev/null || true
		install -m 0755 /usr/local/bin/heimdall.previous /usr/local/bin/heimdall
		install -m 0644 "$work/heimdall.service.previous" /etc/systemd/system/heimdall.service
		cp -p "$work/heimdall.toml.previous" /etc/heimdall/heimdall.toml
		systemctl daemon-reload
		runuser -u heimdall-hub -- cp -p "$db.pre-upgrade" "$db"
		rm -f "$db-wal" "$db-shm"
		systemctl start heimdall
		die "upgrade to $version failed and was rolled back; see journalctl -u heimdall"
	fi
	say "Upgraded to $(/usr/local/bin/heimdall version)"
else
	say "Installing the hub"
	install -m 0755 "$work/heimdall-linux-$arch" /usr/local/bin/heimdall
	base=${proxy_ui:-http://127.0.0.1:8080}
	[ -z "$ts_name" ] || base=https://$ts_name
	set -- --database /var/lib/heimdall/heimdall.db --ui-base-url "$base" --behind-proxy
	[ -z "$proxy_ui" ] || set -- "$@" --ui-behind-proxy
	if [ -n "$proxy_ingest" ]; then
		set -- "$@" --ingest-public-url "$proxy_ingest"
	elif [ -n "$ingest_host" ]; then
		set -- "$@" --ingest-public-url "https://$ingest_host"
	elif [ -n "$ts_name" ]; then
		set -- "$@" --ingest-public-url "https://$ts_name:8443"
	fi
	[ "$mcp" = 0 ] || [ -z "$ts_name" ] || set -- "$@" --mcp-base-url "https://$ts_name:8444"
	hd init "$@" 2>/dev/null
	hd org create "$org" --name "${org_name:-$org}" 2>/dev/null
	hd env create prod 2>/dev/null
	secrets_key "$work/heimdall.service"
	install -m 0644 "$work/heimdall.service" /etc/systemd/system/heimdall.service
	systemctl daemon-reload
	systemctl enable --now heimdall >/dev/null 2>&1
	healthy || die "heimdall didn't start; see journalctl -u heimdall"
fi

# Trust this release's collector, so servers upgrading to it don't raise
# "collector changed" anomalies.
collector_version=$(sed -n 's/^VERSION=//p' "$work/collect.sh" | head -n 1)
collector_sha=$(sha256sum "$work/collect.sh" | cut -d ' ' -f 1)
hd collector trust --version "$collector_version" --note "release $version" "$collector_sha" >/dev/null 2>&1 || true

# Caddy and `tailscale serve` share port 443 on this box: serve listens on
# the tailnet addresses only (the UI, and 8443/8444), Caddy on the others.
# A Caddy site with no bind line listens on every address, so whichever of
# the two starts first holds 443 and the other fails; a reboot, or
# needrestart restarting both after a libc update, flips which one. So
# beside a tailnet listener on 443, Caddy's sites bind the box's other
# global addresses.
caddy_marker="# Written by Heimdall's install-hub.sh"

# public_addrs: this box's global addresses, minus Tailscale's
# (100.64.0.0/10, fd7a:115c:a1e0::/48) and container bridges' (which come
# and go), one per line.
public_addrs() {
	ip -o addr show scope global 2>/dev/null | awk '
		$2 ~ /^(tailscale|docker|br-|veth|virbr|lxc|lxd|cni|flannel|cali|podman)/ { next }
		/ (temporary|deprecated|tentative|dadfailed)( |$)/ { next }
		{
			split($4, a, "/"); ip = tolower(a[1])
			if ($3 == "inet") { split(ip, o, "."); if (o[1] == 100 && o[2] >= 64 && o[2] < 128) next }
			else if (ip ~ /^fd7a:115c:a1e0:/) next
			print ip
		}'
}

# tailnet_443: whether the tailnet has port 443 here: `tailscale serve`
# publishes on it, or something listens on a tailnet address's 443.
tailnet_443() {
	if have tailscale && tailscale serve status --json 2>/dev/null | grep -qE '"443"|:443"'; then
		return 0
	fi
	have ss && ss -Hltn 'sport = :443' 2>/dev/null | awk '{ print $4 }' |
		grep -qE '^(\[?fd7a:115c:a1e0:|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'
}

# caddy_binds: the addresses Caddy's sites bind, space-separated, or
# nothing for every address (no tailnet listener to keep clear of, and no
# --public-bind). Exits when there's none to bind.
caddy_binds() {
	case $public_bind in
	'') tailnet_443 || return 0; b=$(public_addrs) ;;
	auto) b=$(public_addrs) ;;
	*) b=$public_bind ;;
	esac
	# shellcheck disable=SC2086 # one address per word
	b=$(printf '%s\n' $b | sort -u | xargs)
	[ -n "$b" ] || die "found no address outside the tailnet for Caddy to listen on; pass --public-bind ADDR"
	echo "$b"
}

# install_caddyfile NEW: check NEW, keep a copy of a different Caddyfile,
# put NEW in place and (re)start Caddy. check_ports reports a Caddy that
# doesn't come up.
install_caddyfile() {
	caddy validate --adapter caddyfile --config "$1" >"$work/caddy-validate.log" 2>&1 ||
		die "the new Caddyfile doesn't validate (the old one is untouched): $(tail -n 1 "$work/caddy-validate.log")"
	if [ -e /etc/caddy/Caddyfile ]; then
		if cmp -s "$1" /etc/caddy/Caddyfile; then
			systemctl is-active --quiet caddy || systemctl restart caddy || true
			return 0
		fi
		bak=/etc/caddy/Caddyfile.bak-$(date -u +%Y%m%d%H%M%S)
		cp -p /etc/caddy/Caddyfile "$bak"
		say "Previous Caddyfile kept as $bak"
	fi
	install -m 0644 "$1" /etc/caddy/Caddyfile
	systemctl reload caddy 2>/dev/null || systemctl restart caddy || true
}

# fix_caddy_bind: on an upgrade, an older install-hub.sh's Caddyfile has no
# bind line. Beside a tailnet listener on 443 (or with --public-bind), bind
# its sites now.
fix_caddy_bind() {
	f=/etc/caddy/Caddyfile
	[ -e "$f" ] && have caddy || return 0
	has_bind=0
	! grep -qE '^[[:space:]]*bind[[:space:]]' "$f" || has_bind=1
	if ! grep -qF "$caddy_marker" "$f"; then
		[ "$has_bind" = 1 ] || ! tailnet_443 ||
			say "WARNING: $f has no bind line, and tailscale serve uses port 443 too: add 'bind ADDR' (this box's non-tailnet addresses) to each site block, or Caddy and the UI will take turns failing"
		return 0
	fi
	[ "$has_bind" = 0 ] || [ -n "$public_bind" ] || return 0
	binds=$(caddy_binds) || exit 1
	[ -n "$binds" ] || return 0
	say "Binding Caddy to $binds, clear of the tailnet's port 443"
	awk -v b="	bind $binds" '
		/^[[:space:]]*bind[[:space:]]/ { next }
		{ print }
		/^[^#[:space:]{(][^{]*[[:space:]]\{[[:space:]]*$/ { print b }' "$f" >"$work/Caddyfile"
	install_caddyfile "$work/Caddyfile"
}

# check_ports: Caddy and the tailnet's listener on 443 must both be up, on
# their own addresses; fail loudly otherwise.
check_ports() {
	have ss || return 0
	f=/etc/caddy/Caddyfile ours=0 tsip=''
	[ ! -e "$f" ] || ! grep -qF "$caddy_marker" "$f" || ours=1
	if have tailscale && tailscale serve status --json 2>/dev/null | grep -qE '"443"|:443"'; then
		tsip=$(tailscale ip -4 2>/dev/null | head -n 1)
	fi
	[ "$ours" = 1 ] || [ -n "$tsip" ] || return 0
	binds=''
	[ "$ours" = 0 ] || binds=$(sed -n 's/^[[:space:]]*bind[[:space:]]\{1,\}//p' "$f" | head -n 1)
	# tailscaled retries a busy port, backing off up to 30s.
	for _ in $(seq 45); do
		problem=''
		on=$(ss -Hltn 'sport = :443' 2>/dev/null | awk '{ print $4 }')
		if [ "$ours" = 1 ]; then
			systemctl is-active --quiet caddy || problem="caddy.service isn't running"
			for a in $binds; do
				printf '%s\n' "$on" | grep -qF -e "$a:443" -e "[$a]:443" || problem="${problem:+$problem; }Caddy isn't listening on $a:443"
			done
		fi
		if [ -n "$tsip" ] && ! printf '%s\n' "$on" | grep -qF -e "$tsip%" -e "$tsip:443"; then
			problem="${problem:+$problem; }tailscale serve isn't listening on $tsip:443"
		fi
		[ -n "$problem" ] || return 0
		sleep 1
	done
	[ "$ours" = 0 ] || journalctl -u caddy -n 5 --no-pager -o cat >&2 2>/dev/null || true
	die "port check FAILED: $problem. Public ingest (Caddy) and the UI (tailscale serve) both need port 443, each on its own addresses; see docs/deployment.md"
}

# setup_caddy publishes only the ingest path, plus a blank splash page at
# GET / (with --ingest-host). Everything else is an empty 404.
#
# splash_csp pins splash.html's <style> block by hash. After editing it,
# recompute with:
#   sed -n 's/.*<style>\(.*\)<\/style>.*/\1/p' deploy/splash.html | tr -d '\n' | openssl dgst -sha256 -binary | base64
# (go test ./deploy fails until this matches.)
splash_csp="default-src 'none'; style-src 'sha256-lyQ49lXrXIDrdL6U7TEpK1gTs3k1ZzyWzGf2QjuBM34='; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
setup_caddy() {
	if [ -n "$ingest_host" ]; then
		say "Installing Caddy for public ingest on $ingest_host"
		have caddy || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null; }
		install -d -m 0755 /etc/caddy/heimdall-splash
		install -m 0644 "$work/splash.html" /etc/caddy/heimdall-splash/index.html
		# Keep a certificate installed with `heimdall ingest cert` (e.g. a
		# Cloudflare Origin certificate).
		binds=$(caddy_binds) || exit 1
		bind_line=''
		[ -z "$binds" ] || bind_line="	bind $binds"
		tls_line=''
		[ ! -e /etc/caddy/heimdall-origin.pem ] || [ ! -e /etc/caddy/heimdall-origin.key ] ||
			tls_line="	tls /etc/caddy/heimdall-origin.pem /etc/caddy/heimdall-origin.key"
		cat >"$work/Caddyfile" <<EOF
$caddy_marker: only the ingest path and a blank
# splash page at / are public. Nothing names the software or its version.
$ingest_host {
$bind_line
$tls_line
	header {
		-Server
		-Via
		defer
	}
	@ingest path /api/v1/ingest
	request_body @ingest {
		max_size 6MB
	}
	handle @ingest {
		reverse_proxy 127.0.0.1:8443
	}
	@root {
		method GET HEAD
		path /
	}
	handle @root {
		root * /etc/caddy/heimdall-splash
		header {
			Content-Security-Policy "$splash_csp"
			X-Content-Type-Options nosniff
			Referrer-Policy no-referrer
			X-Frame-Options DENY
			Cache-Control no-store
			Permissions-Policy "camera=(), microphone=(), geolocation=()"
			-ETag
			-Last-Modified
			defer
		}
		file_server
	}
	handle {
		respond 404
	}
}

# Plain HTTP only redirects (ACME challenges are answered before this), and
# without the Server header Caddy's automatic redirect would send.
http:// {
$bind_line
	header {
		-Server
		defer
	}
	@ingest_host host $ingest_host
	redir @ingest_host https://{host}{uri} 308
	respond 404
}
EOF
		install_caddyfile "$work/Caddyfile"
	fi
}

# setup_admin creates the first admin (with --admin) if missing.
setup_admin() {
	if [ -n "$admin" ] && ! hd user list 2>/dev/null | awk -v e="$admin" '$2 == e && $3 == "local" { f = 1 } END { exit !f }'; then
		if [ -t 0 ]; then
			say "Creating admin $admin (choose a password, then add the TOTP secret to your authenticator)"
			hd user create --admin "$admin"
		else
			say "No terminal: create the admin later with: sudo heimdall user create --admin $admin"
		fi
	fi
}

if [ "$upgrade" = 1 ]; then
	setup_caddy
	[ -n "$ingest_host" ] || fix_caddy_bind
	setup_admin
	check_ports
	say "Done. Previous binary: /usr/local/bin/heimdall.previous; pre-upgrade database: $db.pre-upgrade"
	say "Servers: re-run install.sh from $version to update their collectors."
	exit 0
fi

if [ -n "$ts_name" ]; then
	say "Publishing the UI on your tailnet"
	tailscale serve --bg 8080 >/dev/null
	[ "$mcp" = 0 ] || tailscale serve --bg --https 8444 http://127.0.0.1:8090 >/dev/null
	[ -n "$ingest_host" ] || tailscale serve --bg --https 8443 http://127.0.0.1:8443 >/dev/null
fi

setup_caddy
setup_admin
check_ports

ui_shown="http://127.0.0.1:8080 (put HTTPS in front)"
[ -z "$proxy_ui" ] || ui_shown="$proxy_ui (through your proxy to 127.0.0.1:8080)"
[ -z "$ts_name" ] || ui_shown=https://$ts_name
if [ -n "$proxy_ingest" ]; then
	ingest_url="$proxy_ingest/api/v1/ingest (through your proxy to 127.0.0.1:8443)"
elif [ -n "$ingest_host" ]; then
	ingest_url="https://$ingest_host/api/v1/ingest"
elif [ -n "$ts_name" ]; then
	ingest_url="https://$ts_name:8443/api/v1/ingest (tailnet only)"
else
	ingest_url="http://127.0.0.1:8443/api/v1/ingest (loopback; put HTTPS in front)"
fi
cat >&2 <<EOF

Heimdall hub is running.
  UI:      $ui_shown
  Ingest:  $ingest_url
EOF
[ "$mcp" = 0 ] || [ -z "$ts_name" ] || printf '  MCP:     https://%s:8444/mcp\n' "$ts_name" >&2
cat >&2 <<EOF

Next:
  sudo heimdall user create --admin you@example.com   (if not done)
  Sign in to the UI, then Hosts → Add a host for each server.
EOF
[ -z "$ingest_host" ] || printf '  Point DNS for %s at this machine and allow inbound 80/443.\n' "$ingest_host" >&2
