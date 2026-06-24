#!/bin/sh
set -eu

REPO=${REPO:-/home/ubuntu/honeymcp}
CADDYFILE_SRC=${CADDYFILE_SRC:-$REPO/deploy/Caddyfile}
DASHBOARD_AUTH_FILE=${DASHBOARD_AUTH_FILE:-/etc/honeymcp/dashboard-basic-auth}

if [ "$(id -u)" -eq 0 ]; then
	SUDO=
else
	SUDO=sudo
fi

require_file() {
	if [ ! -s "$1" ]; then
		echo "missing required file: $1" >&2
		exit 1
	fi
}

install_caddyfile() {
	require_file "$CADDYFILE_SRC"
	require_file "$DASHBOARD_AUTH_FILE"

	tmp=$($SUDO mktemp /tmp/honeymcp-caddy.XXXXXX)
	$SUDO install -m 0644 "$CADDYFILE_SRC" "$tmp"
	$SUDO caddy fmt --overwrite "$tmp" >/dev/null
	$SUDO caddy validate --adapter caddyfile --config "$tmp" >/dev/null
	$SUDO install -m 0644 "$tmp" /etc/caddy/Caddyfile
	$SUDO rm -f "$tmp"
	$SUDO systemctl reload caddy
}

install_imds_block() {
	$SUDO install -m 0755 "$REPO/deploy/honeymcp-imds-block.sh" \
		/usr/local/sbin/honeymcp-imds-block.sh
	$SUDO install -m 0644 "$REPO/deploy/honeymcp-imds-block.service" \
		/etc/systemd/system/honeymcp-imds-block.service
	$SUDO systemctl daemon-reload
	$SUDO systemctl enable --now honeymcp-imds-block.service >/dev/null
}

lock_down_ufw() {
	if command -v ufw >/dev/null 2>&1; then
		printf 'y\n' | $SUDO ufw delete allow 8080/tcp >/dev/null 2>&1 || true
	fi
}

install_caddyfile
install_imds_block
lock_down_ufw
