#!/usr/bin/env bash
# ArkTunnel server upgrade script
#
# Downloads the latest ark-server binary, replaces the installed one,
# and restarts the service.
#
# Usage:
#   curl -fsSL https://github.com/arktunnel/arktunnel/releases/latest/download/upgrade.sh | bash

set -euo pipefail

GITHUB_REPO="arktunnel/arktunnel"
BIN_DIR="/usr/local/bin"

log()  { echo "[arktunnel] $*"; }
die()  { echo "[arktunnel] ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64"  ;;
  aarch64) ARCH="arm64"  ;;
  *) die "Unsupported arch: $ARCH" ;;
esac

OLD_VERSION=$(ark-server --version 2>/dev/null | awk '{print $2}' || echo "unknown")
log "Current version: $OLD_VERSION"

ARK_VERSION=$(curl -fsSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": *"\(.*\)".*/\1/')

if [[ "$ARK_VERSION" == "$OLD_VERSION" ]]; then
  log "Already on latest version ($ARK_VERSION). Nothing to do."
  exit 0
fi

log "Upgrading to $ARK_VERSION..."

ARK_BINARY="ark-server-linux-$ARCH"
ARK_URL="https://github.com/$GITHUB_REPO/releases/download/$ARK_VERSION/$ARK_BINARY"
ARK_SHA_URL="https://github.com/$GITHUB_REPO/releases/download/$ARK_VERSION/SHA256SUMS"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL --retry 3 -o "$TMP/$ARK_BINARY" "$ARK_URL"
curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$ARK_SHA_URL"
(cd "$TMP" && grep "$ARK_BINARY" SHA256SUMS | sha256sum -c -)

install -m 755 "$TMP/$ARK_BINARY" "$BIN_DIR/ark-server"

log "Restarting arktunnel service..."
systemctl restart arktunnel

log "Upgrade complete: $OLD_VERSION → $ARK_VERSION"
log "Changelog: https://github.com/$GITHUB_REPO/releases/tag/$ARK_VERSION"
