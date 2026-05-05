#!/usr/bin/env bash
# ArkTunnel client — macOS one-liner installer.
#
# Usage:
#   curl -fsSL https://github.com/arktunnel/arktunnel/releases/latest/download/install-client-mac.sh | bash
#
# Downloads the latest macOS universal binary (x86_64 + aarch64), verifies
# SHA256, installs to /usr/local/bin/ark-client, and prints usage.

set -euo pipefail

REPO="arktunnel/arktunnel"
INSTALL_DIR="/usr/local/bin"
BINARY="ark-client"
ARTIFACT="ark-client-macos-universal"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[ark-client] $*"; }
error() { echo "[ark-client] ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" &>/dev/null || error "required command not found: $1"; }

# ── preflight checks ─────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Darwin" ]] || error "This script is for macOS only."
need_cmd curl
need_cmd shasum
need_cmd install

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

info "Downloading ${ARTIFACT}..."
curl -fsSL -o "${TMPDIR_LOCAL}/${ARTIFACT}" "${BASE_URL}/${ARTIFACT}"

info "Downloading SHA256SUMS..."
curl -fsSL -o "${TMPDIR_LOCAL}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"

# ── verify SHA256 ─────────────────────────────────────────────────────────────
info "Verifying checksum..."
(
  cd "${TMPDIR_LOCAL}"
  grep "${ARTIFACT}" SHA256SUMS | shasum -a 256 -c -
)
info "Checksum OK."

# ── install ───────────────────────────────────────────────────────────────────
info "Installing to ${INSTALL_DIR}/${BINARY}..."
install -m 755 "${TMPDIR_LOCAL}/${ARTIFACT}" "${INSTALL_DIR}/${BINARY}"

info ""
info "ark-client ${LATEST_TAG} installed successfully."
info ""
info "Usage:"
info "  ark-client run --uri 'arktunnel://<uuid>@<server>:<port>?transport=bip324'"
info ""
info "Point your app's proxy settings to:"
info "  SOCKS5    127.0.0.1:1080"
info "  HTTP      127.0.0.1:8118"
