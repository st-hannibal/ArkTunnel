# ArkTunnel

Censorship-resistant transport proxy that masks traffic as Bitcoin or Ethereum peer-to-peer
protocol, making it indistinguishable from the cryptocurrency traffic that censors cannot block
without devastating their own economy.

---

## How it works

A government cannot block ports 8333 (Bitcoin) or 30303 (Ethereum) without cutting
their own crypto mining sector off the network.  ArkTunnel exploits this: an operator runs a
**real** Bitcoin or Ethereum node, obtaining a publicly-listed IP.  The same port simultaneously
serves ArkTunnel clients.

The server performs the full cryptographic handshake (BIP 324 or RLPx) with every inbound
connection, exactly as a real node would.  After decryption, the first plaintext packet determines
routing:

- Starts with `ARK1 || UUID` → ArkTunnel client → forwarded to sing-box (VLESS) on localhost
- Standard `version` / `Hello` message → real crypto peer → forwarded to bitcoind / geth

Clients connect through a local SOCKS5 proxy (`ark-client`), so existing apps (v2rayNG, NekoBox,
Clash) require zero modification.

---

## Architecture

```
ark-core      — Transport trait + BIP 324 (port 8333) + RLPx (port 30303) implementations
ark-server    — Accept loop, multiplexing, sing-box subprocess management
ark-client    — Local SOCKS5 bridge → outbound ArkTunnel connection
```

### Cryptographic details

| Transport | Handshake | Encryption |
|-----------|-----------|------------|
| BIP 324 | X25519 ECDH + HKDF-SHA256 | FSChaCha20-Poly1305 |
| RLPx (EIP-8) | secp256k1 ECDH, ECIES (AES-128-CTR + HMAC-SHA256) | AES-256-CTR + SHA-3 MAC |

---

## Quick start (server)

**Prerequisites:** a publicly-routable server with ports 8333 or 30303 open, and sing-box
installed.

```sh
# Install (Linux, amd64)
curl -Lo ark-server https://github.com/YOUR_ORG/ArkTunnel/releases/latest/download/ark-server-linux-amd64
chmod +x ark-server

# Create config
cat > /etc/ark-server.toml <<'EOF'
transport    = "bip324"           # or "rlpx"
listen_addr  = "0.0.0.0:8333"
crypto_node_addr = "127.0.0.1:8334"  # your bitcoind p2p port

[[uuids]]
value = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
EOF

ark-server run
```

Live-reload config without dropping connections:

```sh
kill -HUP $(pidof ark-server)
```

Drop privileges after bind — the server automatically calls `setuid(nobody)` when started as
root.  Override with `ARK_USER=myuser ark-server run`.

---

## Quick start (client)

```sh
# macOS/Linux universal binary
curl -Lo ark-client https://github.com/YOUR_ORG/ArkTunnel/releases/latest/download/ark-client-macos-universal
chmod +x ark-client

ark-client \
  --server 1.2.3.4:8333 \
  --transport bip324 \
  --uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --socks5 127.0.0.1:1080
```

Configure v2rayNG / NekoBox / Clash to use `socks5://127.0.0.1:1080`.

---

## Building from source

```sh
git clone https://github.com/YOUR_ORG/ArkTunnel
cd ArkTunnel
cargo build --release --workspace
```

Rust 1.87+ required (pinned in `rust-toolchain.toml`).

### Cross-compile static binaries (musl)

```sh
rustup target add x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
```

---

## Running tests

```sh
cargo test --workspace
```

---

## Security notes

- No credentials are stored in binaries or config in plaintext — UUIDs are the only secret on the
  client side.
- The server drops root after binding the privileged port.
- Session keys are derived fresh per connection; no long-term symmetric keys are persisted.
- EIP-8 forward compatibility: both old-format and EIP-8 RLPx auth messages are accepted.

---

## License

MIT
