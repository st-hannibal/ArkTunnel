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

**Prerequisites:** a Linux VPS (Ubuntu 20/22/24 or Debian 11/12, x86_64 or aarch64) with
ports 8333 or 30303 open. The installer handles bitcoind/geth, sing-box, and systemd setup.

```sh
# Run as root on the VPS
curl -fsSL https://github.com/st-hannibal/ArkTunnel/releases/latest/download/install.sh | bash
```

The installer prints an `arktunnel://` URI at the end — copy it, you need it for the client.

Live-reload config without dropping connections:

```sh
kill -HUP $(pidof ark-server)
```

Add a new user (generates a new URI):

```sh
sudo ark-server add-user
```

The server automatically drops to a dedicated `arktunnel` system user after binding the port.

### Server runbook (validated on Amazon Linux 2023)

For manual deployments (instead of `install.sh`), this sequence is known-good:

1. Install `ark-server` and `sing-box` binaries under `/usr/local/bin`.
2. Create `/etc/arktunnel/server.toml`:

```toml
transport = "bip324"
listen_addr = "0.0.0.0:8333"
uuids = ["<uuid>"]
singbox_api = "127.0.0.1:9090"
```

3. Run `ark-server` as a systemd service.
4. Verify sing-box local inbound is reachable:

```sh
sudo systemctl status arktunnel
sudo journalctl -u arktunnel -n 100 --no-pager
```

Important sing-box compatibility notes (1.13.x):

- Do not include `"transport": { "type": "tcp" }` in VLESS inbound blocks.
- Do not include `experimental.v2ray_api` unless the binary is built with that feature.

Current generated sing-box config shape is:

```json
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "vless",
    "tag": "vless-in",
    "listen": "127.0.0.1",
    "listen_port": 10800,
    "users": [{ "uuid": "<uuid>", "flow": "" }]
  }],
  "outbounds": [{ "type": "direct", "tag": "direct-out" }]
}
```

Note: `ark-server` rewrites sing-box config on startup, so source/template fixes are required for persistent changes.

---

## Quick start (client)

**macOS:**
```sh
curl -fsSL https://github.com/st-hannibal/ArkTunnel/releases/latest/download/install-client-mac.sh | bash
```

**Linux:**
```sh
curl -fsSL https://github.com/st-hannibal/ArkTunnel/releases/latest/download/install-client-linux.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://github.com/st-hannibal/ArkTunnel/releases/latest/download/install-client-windows.ps1 | iex
```

Then start the proxy using the URI printed by the server `init` step:

```sh
ark-client run --uri 'arktunnel://<uuid>@<server-ip>:<port>?transport=bip324'
```

Test it:

```sh
curl --socks5 127.0.0.1:1080 https://api.ipify.org
# should print your server's IP, not yours
```

Configure v2rayNG / NekoBox / Clash to use `socks5://127.0.0.1:1080` or `http://127.0.0.1:8118`.

### Client smoke test flow

Use this sequence when validating a freshly deployed server:

```sh
ark-client test --uri 'arktunnel://<uuid>@<server-ip>:8333?transport=bip324'
ark-client run --uri 'arktunnel://<uuid>@<server-ip>:8333?transport=bip324'
curl --socks5 127.0.0.1:1080 https://api.ipify.org
```

Expected result: `api.ipify.org` returns the server public IP.

If `ark-client test` hangs over real internet but works locally, ensure you are running version `v0.1.4+` where BIP324 read cancel-safety is fixed.

### Known networking bug fixed in v0.1.4

`Bip324Stream::poll_read` previously constructed a fresh `recv_packet` future on every poll. If polling returned `Pending`, that future was dropped and any partially-consumed TCP bytes were lost, desynchronizing packet framing and causing hangs over fragmented real-world TCP.

Fix in `v0.1.4`: persistent `RecvState` state machine (`Idle`, `ReadingLength`, `ReadingBody`) stored on `Bip324Stream`, so partial reads survive across polls.

---

## Building from source

```sh
git clone https://github.com/st-hannibal/ArkTunnel
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

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
