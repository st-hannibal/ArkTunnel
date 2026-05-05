#!/usr/bin/env bash
# ArkTunnel server installer
#
# Usage:
#   curl -fsSL https://github.com/arktunnel/arktunnel/releases/latest/download/install.sh | bash
#   curl -fsSL ... | bash -s -- --transport rlpx
#
# Idempotent: safe to re-run for upgrades. Skips init if config already exists.
#
# Supported platforms:
#   OS:   Ubuntu 20/22/24, Debian 11/12
#   Arch: x86_64, aarch64

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TRANSPORT="${ARKTUNNEL_TRANSPORT:-bip324}"
GITHUB_REPO="arktunnel/arktunnel"
BITCOIN_VERSION="27.0"
RETH_VERSION="v1.3.12"

ARKTUNNEL_USER="arktunnel"
CONFIG_DIR="/etc/arktunnel"
BIN_DIR="/usr/local/bin"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[arktunnel] $*"; }
warn() { echo "[arktunnel] WARNING: $*" >&2; }
die()  { echo "[arktunnel] ERROR: $*" >&2; exit 1; }

require_root() {
  [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."
}

detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "$ID"
  else
    die "Cannot detect OS (/etc/os-release not found)"
  fi
}

sha256_verify() {
  local file="$1" expected="$2"
  local actual
  actual=$(sha256sum "$file" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || die "SHA256 mismatch for $file\n  expected: $expected\n  actual:   $actual"
}

download() {
  local url="$1" dest="$2"
  log "Downloading $url"
  curl -fsSL --retry 3 -o "$dest" "$url"
}

# ---------------------------------------------------------------------------
# GPG verification for Bitcoin Core
#
# Bitcoin Core releases are signed by multiple builder keys from the
# bitcoin-core/guix.sigs repository.  We download a curated set of known
# builder public-key files and import them, then verify SHA256SUMS.asc.
# If gpg is not installed, we skip GPG and warn (SHA256 is still verified).
# ---------------------------------------------------------------------------
gpg_verify_bitcoin() {
  local tmp="$1" archive="$2"

  if ! command -v gpg &>/dev/null; then
    warn "gpg not found — skipping GPG signature check for Bitcoin Core (SHA256 still verified)"
    return 0
  fi

  log "Downloading Bitcoin Core SHA256SUMS.asc for GPG verification..."
  download \
    "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc" \
    "$tmp/SHA256SUMS.asc"

  # Import a curated set of Bitcoin Core builder keys from the guix.sigs repository.
  # These keys are the current active signers listed in the guix.sigs README.
  local GUIX_KEYS_BASE="https://raw.githubusercontent.com/bitcoin-core/guix.sigs/main/builder-keys"
  local BUILDER_KEYS=(
    "fanquake.gpg"
    "achow101.gpg"
    "hebasto.gpg"
    "laanwj.gpg"
    "theStack.gpg"
    "pinheadmz.gpg"
  )
  local imported=0
  for key_file in "${BUILDER_KEYS[@]}"; do
    if curl -fsSL --retry 2 "${GUIX_KEYS_BASE}/${key_file}" \
         | gpg --batch --import 2>/dev/null; then
      imported=$((imported + 1))
    fi
  done

  if [[ $imported -eq 0 ]]; then
    warn "Could not import any Bitcoin Core builder keys — skipping GPG check"
    return 0
  fi

  log "Imported $imported Bitcoin Core builder key(s). Verifying signature..."
  if gpg --batch --verify "$tmp/SHA256SUMS.asc" "$tmp/SHA256SUMS" 2>&1 \
       | grep -q "Good signature"; then
    log "GPG signature OK for Bitcoin Core $BITCOIN_VERSION SHA256SUMS"
  else
    die "GPG signature verification FAILED for Bitcoin Core SHA256SUMS.  Aborting."
  fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --transport=*) TRANSPORT="${arg#*=}" ;;
    --transport)   shift; TRANSPORT="$1" ;;
  esac
done

[[ "$TRANSPORT" == "bip324" || "$TRANSPORT" == "rlpx" ]] \
  || die "Invalid transport '$TRANSPORT'. Use 'bip324' or 'rlpx'."

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
require_root

ARCH=$(detect_arch)
OS=$(detect_os)
log "Platform: $OS / $ARCH"
log "Transport: $TRANSPORT"

# --- System user ---
if ! id -u "$ARKTUNNEL_USER" &>/dev/null; then
  log "Creating system user '$ARKTUNNEL_USER'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$ARKTUNNEL_USER"
fi

# --- sing-box ---
# As of v0.1.7 ArkTunnel speaks its own ARK-frame protocol natively;
# sing-box is no longer required.

# --- crypto node ---
if [[ "$TRANSPORT" == "bip324" ]]; then
  if ! command -v bitcoind &>/dev/null; then
    log "Installing bitcoind $BITCOIN_VERSION..."
    BTC_ARCH_MAP_amd64="x86_64-linux-gnu"
    BTC_ARCH_MAP_arm64="aarch64-linux-gnu"
    BTC_ARCH_VAR="BTC_ARCH_MAP_$ARCH"
    BTC_TRIPLE="${!BTC_ARCH_VAR}"
    BTC_ARCHIVE="bitcoin-${BITCOIN_VERSION}-${BTC_TRIPLE}.tar.gz"
    BTC_URL="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/$BTC_ARCHIVE"
    TMP=$(mktemp -d)
    download "$BTC_URL" "$TMP/$BTC_ARCHIVE"
    # Verify SHA256 from bitcoin.org checksums file
    SHA_FILE="SHA256SUMS"
    download "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/$SHA_FILE" "$TMP/$SHA_FILE"
    (cd "$TMP" && grep "$BTC_ARCHIVE" "$SHA_FILE" | sha256sum -c -)
    # Verify GPG signature on the checksums file
    gpg_verify_bitcoin "$TMP" "$BTC_ARCHIVE"
    tar -xzf "$TMP/$BTC_ARCHIVE" -C "$TMP"
    install -m 755 "$TMP/bitcoin-${BITCOIN_VERSION}/bin/bitcoind" "$BIN_DIR/bitcoind"
    rm -rf "$TMP"
    log "bitcoind $BITCOIN_VERSION installed"

    # Write bitcoind config (regtest-free, listen on non-standard port)
    mkdir -p /etc/bitcoin
    cat > /etc/bitcoin/bitcoin.conf <<'BTCEOF'
server=1
listen=1
bind=127.0.0.1:18444
rpcbind=127.0.0.1
rpcport=18443
rpcuser=arktunnel
rpcpassword=arktunnel_rpc
datadir=/var/lib/bitcoin
BTCEOF
    mkdir -p /var/lib/bitcoin
    chown -R "$ARKTUNNEL_USER:$ARKTUNNEL_USER" /var/lib/bitcoin /etc/bitcoin
  fi

elif [[ "$TRANSPORT" == "rlpx" ]]; then
  if ! command -v reth &>/dev/null; then
    log "Installing reth $RETH_VERSION..."
    RETH_ARCHIVE="reth-${RETH_VERSION}-${ARCH}-unknown-linux-gnu.tar.gz"
    RETH_URL="https://github.com/paradigmxyz/reth/releases/download/$RETH_VERSION/$RETH_ARCHIVE"
    TMP=$(mktemp -d)
    download "$RETH_URL" "$TMP/$RETH_ARCHIVE"
    # Verify SHA256
    download "${RETH_URL}.sha256" "$TMP/reth.sha256"
    (cd "$TMP" && sha256sum -c reth.sha256)
    tar -xzf "$TMP/$RETH_ARCHIVE" -C "$TMP"
    install -m 755 "$TMP/reth" "$BIN_DIR/reth"
    rm -rf "$TMP"
    log "reth $RETH_VERSION installed"
  fi
fi

# --- ark-server ---
log "Installing ark-server..."
ARK_VERSION=$(curl -fsSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
ARK_BINARY="ark-server-linux-$ARCH"
ARK_URL="https://github.com/$GITHUB_REPO/releases/download/$ARK_VERSION/$ARK_BINARY"
ARK_SHA_URL="https://github.com/$GITHUB_REPO/releases/download/$ARK_VERSION/SHA256SUMS"
TMP=$(mktemp -d)
download "$ARK_URL" "$TMP/$ARK_BINARY"
download "$ARK_SHA_URL" "$TMP/SHA256SUMS"
(cd "$TMP" && grep "$ARK_BINARY" SHA256SUMS | sha256sum -c -)
install -m 755 "$TMP/$ARK_BINARY" "$BIN_DIR/ark-server"
rm -rf "$TMP"
log "ark-server $ARK_VERSION installed"

# --- firewall ---
if command -v ufw &>/dev/null; then
  OPEN_PORT=8333
  [[ "$TRANSPORT" == "rlpx" ]] && OPEN_PORT=30303
  log "Opening port $OPEN_PORT/tcp in ufw"
  ufw allow "$OPEN_PORT/tcp" || true
fi

# --- init (skip if already initialized) ---
if [[ ! -f "$CONFIG_DIR/server.toml" ]]; then
  log "Initializing ark-server (transport: $TRANSPORT)"
  ark-server init --transport "$TRANSPORT" > /tmp/arktunnel_init.txt 2>&1
  cat /tmp/arktunnel_init.txt
  URI=$(grep "arktunnel://" /tmp/arktunnel_init.txt | sed 's/^ *//')
else
  log "Config already exists — skipping init (this is an upgrade)"
  URI="(see existing URI or run: ark-server add-user)"
fi

# --- systemd units ---
log "Writing systemd unit files"

cat > /etc/systemd/system/arktunnel.service <<UNIT
[Unit]
Description=ArkTunnel server
After=network.target

[Service]
Type=simple
User=$ARKTUNNEL_USER
ExecStart=$BIN_DIR/ark-server run
Restart=on-failure
RestartSec=5
# No sensitive data in logs
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

if [[ "$TRANSPORT" == "bip324" ]] && command -v bitcoind &>/dev/null; then
  cat > /etc/systemd/system/bitcoind.service <<UNIT
[Unit]
Description=Bitcoin Core daemon
After=network.target

[Service]
Type=forking
User=$ARKTUNNEL_USER
ExecStart=$BIN_DIR/bitcoind -conf=/etc/bitcoin/bitcoin.conf -daemon
ExecStop=$BIN_DIR/bitcoin-cli -conf=/etc/bitcoin/bitcoin.conf stop
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT
fi

if [[ "$TRANSPORT" == "rlpx" ]] && command -v reth &>/dev/null; then
  cat > /etc/systemd/system/reth.service <<UNIT
[Unit]
Description=Reth Ethereum node
After=network.target

[Service]
Type=simple
User=$ARKTUNNEL_USER
ExecStart=$BIN_DIR/reth node --port 30304 --datadir /var/lib/reth
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT
  mkdir -p /var/lib/reth
  chown -R "$ARKTUNNEL_USER:$ARKTUNNEL_USER" /var/lib/reth
fi

systemctl daemon-reload
systemctl enable arktunnel
systemctl start arktunnel || true

[[ "$TRANSPORT" == "bip324" ]] && systemctl enable bitcoind && systemctl start bitcoind || true
[[ "$TRANSPORT" == "rlpx"   ]] && systemctl enable reth    && systemctl start reth    || true

# ---------------------------------------------------------------------------
log ""
log "=== ArkTunnel installation complete ==="
log ""
log "  Transport:  $TRANSPORT"
log "  URI:        $URI"
log ""
log "Check status:  systemctl status arktunnel"
log "View logs:     journalctl -u arktunnel -f"
