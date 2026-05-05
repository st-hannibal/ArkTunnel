#!/usr/bin/env bash
# ArkTunnel client — Linux one-liner installer.
#
# Usage:
#   curl -fsSL https://github.com/arktunnel/arktunnel/releases/latest/download/install-client-linux.sh | bash
#
# Supports x86_64 and aarch64. Downloads the latest static musl binary,
# verifies SHA256, and installs to /usr/local/bin/ark-client.

set -euo pipefail

REPO="arktunnel/arktunnel"
INSTALL_DIR="/usr/local/bin"
BINARY="ark-client"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[ark-client] $*"; }
error() { echo "[ark-client] ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" &>/dev/null || error "required command not found: $1"; }

# ── preflight checks ─────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]] || error "This script is for Linux only."
need_cmd curl
need_cmd sha256sum
need_cmd install

# ── detect architecture ───────────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)          ARTIFACT="ark-client-linux-amd64" ;;
  aarch64|arm64)   ARTIFACT="ark-client-linux-arm64" ;;
  *)               error "Unsupported architecture: ${ARCH}. Only x86_64 and aarch64 are supported." ;;
esac

# ── fetch latest release tag ─────────────────────────────────────────────────
info "Fetching latest release from GitHub..."
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
[[ -n "$LATEST_TAG" ]] || error "Could not determine latest release tag."
info "Latest release: ${LATEST_TAG}"

BASE_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}"

# ── download binary and checksums ────────────────────────────────────────────
TMPDIR_LOCAL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

info "Downloading ${ARTIFACT} (${ARCH})..."
curl -fsSL -o "${TMPDIR_LOCAL}/${ARTIFACT}" "${BASE_URL}/${ARTIFACT}"

info "Downloading SHA256SUMS..."
curl -fsSL -o "${TMPDIR_LOCAL}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"

# ── verify SHA256 ─────────────────────────────────────────────────────────────
info "Verifying checksum..."
(
  cd "${TMPDIR_LOCAL}"
  grep "${ARTIFACT}" SHA256SUMS | sha256sum -c -
)
info "Checksum OK."

# ── install ───────────────────────────────────────────────────────────────────
# Use sudo only if the install directory is not writable by the current user.
if [[ -w "${INSTALL_DIR}" ]]; then
  INSTALL_CMD="install"
else
  need_cmd sudo
  INSTALL_CMD="sudo install"
fi

info "Installing to ${INSTALL_DIR}/${BINARY}..."
$INSTALL_CMD -m 755 "${TMPDIR_LOCAL}/${ARTIFACT}" "${INSTALL_DIR}/${BINARY}"

info ""
info "ark-client ${LATEST_TAG} installed successfully."
info ""
info "Usage:"
info "  ark-client run --uri 'arktunnel://<uuid>@<server>:<port>?transport=bip324'"
info ""
info "Point your app's proxy settings to:"
info "  SOCKS5    127.0.0.1:1080"
info "  HTTP      127.0.0.1:8118"
