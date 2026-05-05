# ArkTunnel

Censorship-resistant transport proxy that masks traffic as Bitcoin or Ethereum peer-to-peer
protocol, making it indistinguishable from cryptocurrency traffic that censors cannot block
without devastating their own economy.

No TLS. No HTTPS. No SSL certificates. End-to-end encryption is provided entirely by the
Bitcoin/Ethereum wire protocols — protocols that any censor must allow or lose their own
crypto-mining sector.

---

## How it works

A government cannot block port 8333 (Bitcoin) or 30303 (Ethereum) without cutting their own
crypto-mining sector off the network. ArkTunnel exploits this asymmetry: an operator runs a
**real** Bitcoin or Ethereum node, obtaining a publicly-listed IP. The same port simultaneously
serves ArkTunnel clients.

Every inbound connection receives the full cryptographic handshake (BIP 324 or RLPx), exactly
as a real peer node would. After the handshake, the first decrypted payload determines routing:

- Starts with `ARK1 || UUID` → ArkTunnel client → ARK-frame request handled natively
- Standard Bitcoin `version` or Ethereum `Hello` message → real crypto peer → forwarded to
  `bitcoind` / `geth` running on the same machine

Clients connect through a local SOCKS5 (`127.0.0.1:1080`) or HTTP CONNECT
(`127.0.0.1:8118`) proxy, so any existing app requires zero modification.

---

## Architecture

```
ark-core      — Transport trait, BIP 324, RLPx, ARK-frame protocol
ark-server    — Accept loop, peer/client multiplexing, upstream relay
ark-client    — Local SOCKS5 + HTTP CONNECT bridge → outbound ArkTunnel connection
```

```
 Browser / app
      │  SOCKS5 / HTTP CONNECT
      ▼
 ark-client (local)
      │  TCP  →  BIP 324 handshake (X25519 + FSChaCha20)
      ▼
 ark-server (VPS, port 8333)
      │  ARK1 detected → ARK-frame request
      ├──→ TcpStream::connect(target)   ← direct, no subprocess
      │        tokio::io::copy_bidirectional
      │
      └──→ Real Bitcoin peer? → forward raw stream to bitcoind
```

### Cryptographic transports

| Transport | Handshake | Packet encryption |
|-----------|-----------|-------------------|
| BIP 324 (port 8333) | X25519 EllSwift ECDH + HKDF-SHA256 | FSChaCha20-Poly1305 (AEAD) |
| RLPx / EIP-8 (port 30303) | secp256k1 ECDH, ECIES (AES-128-CTR + HMAC-SHA256) | AES-256-CTR + SHA-3 MAC |

---

## Quick start (server)

**Prerequisites:** a Linux VPS (Ubuntu 20/22/24, Debian 11/12, or Amazon Linux 2023,
x86_64 or aarch64) with port 8333 open inbound.

```sh
# Run as root on the VPS
curl -fsSL https://github.com/st-hannibal/ArkTunnel/releases/latest/download/install.sh | bash
```

The installer prints an `arktunnel://` URI at the end — copy it for the client.

Live-reload config without dropping connections:

```sh
kill -HUP $(pidof ark-server)
```

Add a new user (generates a new URI):

```sh
sudo ark-server add-user
```

The server drops to a dedicated `arktunnel` system user after binding the port.

### Manual deployment (validated on Amazon Linux 2023)

1. Install `ark-server` under `/usr/local/bin`.
2. Create `/etc/arktunnel/server.toml`:

```toml
transport   = "bip324"
listen_addr = "0.0.0.0:8333"
uuids       = ["<uuid>"]
```

3. Run `ark-server` as a systemd service (see `install.sh` for the unit file template).
4. Verify:

```sh
sudo systemctl status arktunnel
sudo journalctl -u arktunnel -n 50 --no-pager
```

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

Start the proxy:

```sh
ark-client run --uri 'arktunnel://<uuid>@<server-ip>:8333?transport=bip324'
```

Test it:

```sh
ark-client test --uri 'arktunnel://<uuid>@<server-ip>:8333?transport=bip324'
# → OK  104ms

curl --socks5 127.0.0.1:1080 https://api.ipify.org
# → <server public IP>
```

Point any app at `socks5://127.0.0.1:1080` or `http://127.0.0.1:8118`.

### URI grammar

```
arktunnel://<uuid>@<host>:<port>[,<host>:<port>…]?transport=<name>[&backup=<host>:<port>…][&nodekey=<hex>]
```

- **Single endpoint** (v0.1.x compatible):
  `arktunnel://<uuid>@server.example:8333?transport=bip324`
- **Multiple endpoints** (v0.2.0+) — comma-separated in the host list:
  `arktunnel://<uuid>@h1.example:8333,h2.example:8333,h3.example:8333?transport=bip324`
- **Or** with repeated `&backup=` query params:
  `arktunnel://<uuid>@h1.example:8333?transport=bip324&backup=h2.example:8333&backup=h3.example:8333`
- IPv6 endpoints must be bracketed: `[2001:db8::1]:8333`.
- Order is preserved; the first entry is the primary. Duplicate
  `host:port` entries are silently deduped.
- `transport=rlpx` requires `&nodekey=<hex128>` and supports a single
  endpoint only.

The client tries endpoints in order on each connect attempt with a
3-second deadline per endpoint (TCP connect + transport handshake). After
3 consecutive failures an endpoint is demoted for 60 seconds and dropped
to the back of the candidate list. Once an endpoint succeeds it becomes
the *sticky* preferred entry for subsequent connections in the same
process — this avoids scattering load across the pool. State is in-memory
only; nothing is written to disk.

### Signed pool registry (optional)

Operators that run multiple servers can publish a tiny signed JSON
document the client fetches at start. The verified server list replaces
the URI's static endpoint list, so URIs stay short and the pool can
rotate without re-issuing them.

```sh
ark-client run \
  --uri 'arktunnel://<uuid>@fallback.example:8333?transport=bip324' \
  --pool-url https://pool.example/arktunnel/pool.json \
  --pool-pubkey <hex64-ed25519-public-key>
```

Document schema (sig is detached Ed25519 over the canonical JSON of the
other top-level fields):

```json
{
  "version": 1,
  "updated": "2026-05-05T09:00:00Z",
  "servers": [
    {"host": "h1.example", "port": 8333, "weight": 1, "transport": "bip324"},
    {"host": "h2.example", "port": 8333, "weight": 1, "transport": "bip324"}
  ],
  "sig": "<hex-encoded 64-byte Ed25519 signature>"
}
```

The verified document is cached under the platform cache directory
(`~/Library/Caches/arktunnel/pool.json` on macOS, `~/.cache/arktunnel/`
on Linux, `%LOCALAPPDATA%\arktunnel\` on Windows). If the next start-up
fetch fails (block or outage) the client falls back to the cached copy
as long as its signature still verifies. Out of scope: gossip, DHT, and
push updates — it's a static signed file fetched over HTTPS.

A reference signer ships as `cargo run --example sign-pool -p ark-client`.
Generate a key with `openssl rand -hex 32`; the signer prints the matching
public key on stderr.

### Traffic shaping (`--shape`)

`ark-client {run,test,tun} --shape off|light|heavy` selects the
traffic-shaping policy (Phase 12 / WP4):

| Policy | Length quantization | Cover packets | Wire compat |
|---|---|---|---|
| `off` (default) | none | none | v0.1.x and newer |
| `light` | round to `{256,512,1024,1280,1500}` B buckets | Poisson, mean 2 s when idle > 500 ms | requires v0.2.x server (WP5) |
| `heavy` | same buckets | Poisson, mean 500 ms when idle > 500 ms | requires v0.2.x server (WP5) |

Padding bytes are zeroed at the ARK-frame layer and then encrypted by
the surrounding BIP 324 channel, so on-wire entropy is unaffected.
Indicative bandwidth overhead measured against a quiet idle link:
`light` ≈ 4 KB/s of cover, `heavy` ≈ 16 KB/s. Real-traffic overhead is
dominated by per-packet padding, typically < 10 % for browsing-shaped
flows.

The wire-level activation is gated on ARK-frame v2 capability bits
(WP5). When the client is started with `--shape light` or `heavy` it
appends a 6-byte v2 hello (`ARKV || ver || caps`) to the encrypted
ARK1+UUID packet and waits up to 2 s for the server's matching ack.
A v0.2.x server replies with the AND-merge of supported capabilities
(`bit0 = COVER`, `bit1 = PAD_QUANTIZE`); a v0.1.x server is silent and
the client logs `server did not ack ARK-frame v2; falling back to v1`
and proceeds without padding or cover frames. The actual emission of
`CMD_COVER` frames + length quantization on top of the negotiated bits
is wired in a follow-up commit; this WP only ships the negotiation
plumbing.

---

## Full-device mode (route everything)

The default `ark-client run` exposes a SOCKS5 + HTTP-CONNECT listener and only
carries traffic from apps that explicitly use those proxies. If you want
*every* TCP connection on the machine — system updates, App Store, native
apps, etc. — to be tunneled through ArkTunnel, use **TUN mode**:

```sh
sudo ark-client tun --uri 'arktunnel://<uuid>@<server-ip>:8333?transport=bip324'
```

What happens:

1. `ark-client` starts an in-process SOCKS5 listener on `127.0.0.1:1080`.
2. It launches the upstream [`tun2socks`](https://github.com/xjasonlyu/tun2socks)
   binary, which creates a virtual network device (`utun8` / `tun8` / `wintun`)
   and forwards every packet it receives to that SOCKS5 endpoint.
3. `ark-client` installs OS routes that send the system default route through
   the TUN device, while keeping a `/32` host bypass to the ark-server itself
   (otherwise the encrypted session would loop through itself).
4. On `Ctrl-C` (or `SIGTERM`) every route is reverted in LIFO order and the
   TUN device is torn down. Routes are restored even if `tun2socks` crashes.

### Verifying

After starting TUN mode, with **no proxy environment variables set**:

```sh
curl https://api.ipify.org
# → <server public IP>
```

Your SSH session to the server keeps working because of the `/32` bypass.

### Prerequisites

- **Privileges:** `sudo` on macOS/Linux, an Administrator terminal on Windows.
- **`tun2socks` binary:** the install scripts download a pinned version into
  `/usr/local/libexec/arktunnel/tun2socks` (Unix) or alongside `ark-client.exe`
  (Windows). To skip auto-download set `NO_TUN2SOCKS=1`.
- **Windows only:** the [Wintun](https://www.wintun.net/) driver must be
  installed system-wide.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--uri` | required | `arktunnel://` URI |
| `--socks5` | `127.0.0.1:1080` | upstream SOCKS5 listen address |
| `--tun-name` | `utun8` / `tun8` / `wintun` | TUN device name |
| `--mtu` | `1500` | MTU for the TUN device |
| `--tun2socks` | auto-detect | explicit path to the `tun2socks` binary |
| `--ipv6` | `false` | allow IPv6 traffic to flow through the tunnel (default blackholes v6 to prevent leaks) |

### Caveats

- **UDP is now tunneled (v0.1.9).** QUIC/HTTP-3, DNS over UDP/53, WebRTC,
  native VoIP and games go through the SOCKS5 UDP_ASSOCIATE path and out the
  server's egress. The previous `-udp-timeout 0` workaround is gone.
- **DNS in TUN mode goes through the tunnel automatically.** Because the OS
  resolver's UDP/53 queries are captured by the TUN device and relayed via
  the server, your ISP / LAN no longer sees plaintext DNS metadata while
  TUN is active. The **server operator** still sees the queries unless you
  also configure DoH/DoT — see [DNS privacy](#dns-privacy) below.
- **SOCKS5-only mode (no TUN) still leaks DNS.** Apps that resolve hostnames
  themselves before handing the IP to the SOCKS proxy will leak. Configure
  the app to send hostnames to the SOCKS proxy ("remote DNS" / SOCKS5h).
- **IPv6 is blackholed by default while TUN is active.** ArkTunnel’s
  ARK-frame already carries v6 (`atype = 0x04`) and the server egress
  resolves v6 destinations, but to stay safe-by-default we still install
  blackhole routes for `::/0` so v6-capable apps don’t silently bypass the
  tunnel and leak the user’s real IPv6 address. Pass `--ipv6` to lift the
  blackhole when you have verified that the URI / server actually carry v6
  egress (WP10). Apps fall back to IPv4 transparently when v6 is
  blackholed.
- **System default route is altered transiently.** ArkTunnel uses the
  split-default trick (`0.0.0.0/1` + `128.0.0.0/1`) so the original default
  route is left untouched and is restored on shutdown. If `ark-client` is
  killed with `SIGKILL` you may need to manually restore the default route
  (`route add default <gw>` on macOS, `ip route add default via <gw> dev <dev>`
  on Linux).
- **One TUN session per machine.** Don't run `ark-client tun` and a second
  VPN at the same time — the routes will conflict.

### DNS privacy

With TUN mode active in v0.1.9, DNS queries no longer leak to your ISP — they
are carried inside the encrypted tunnel and resolved by the **server's**
upstream resolver. The trust boundary moves from your ISP to whoever runs
the ArkTunnel server.

If you do not fully trust the server operator, layer DNS-over-HTTPS (DoH) or
DNS-over-TLS (DoT) on top:

- **macOS / iOS:** install a configuration profile pointing at
  `https://cloudflare-dns.com/dns-query` (Cloudflare) or
  `https://dns.google/dns-query` (Google).
- **Linux:** `systemd-resolved` with `DNSOverTLS=yes` and
  `DNS=1.1.1.1#cloudflare-dns.com`.
- **Windows 11:** Settings → Network → DNS server assignment → Manual →
  enable "DNS over HTTPS".
- **Browser-only:** Firefox and Chrome both expose a built-in DoH toggle.

These resolvers ride inside the ArkTunnel UDP relay (DoH=TCP/443, DoT=TCP/853,
standard DNS=UDP/53), so they are end-to-end encrypted and only the chosen
resolver — not the server operator — sees your queries.

### Threat model — current limitations (v0.2.0)

The cryptography is sound (BIP 324 / RLPx are real Bitcoin/Eth wire
protocols, indistinguishable from random bytes), and the v0.2.x line
closes the operational gaps that previously kept us from recommending
ArkTunnel to higher-risk users. Read this before relying on it in
adversarial environments:

| Limitation | Why it matters | Status |
|---|---|---|
| Server operator sees plaintext DNS unless you layer DoH/DoT | They can log every hostname you visit | mitigated by DoH/DoT (above) |
| Single static server IP | Once identified, blocked permanently | **fixed in 0.2.0** — multi-server URI grammar (WP1) + sticky/demote failover (WP2) + signed pool registry with auto-fetch (WP3) |
| No traffic shaping / padding | ML-based flow analysis can flag "Bitcoin-handshake but YouTube-volume" | **fixed in 0.2.0** — `--shape light\|heavy` ships length quantization + Poisson cover frames (WP4) gated on a 2-byte ARK-frame v2 capability negotiation (WP5) |
| No active-probe resistance audit | A prober that connects to the server may receive distinguishable responses | **fixed in 0.2.0** — every malformed-input failure path holds the connection silently for a uniformly random `[10s, 60s]` then drops (no error byte ever sent); per-IP tarpit after 10 fails / 60 s (WP6); independent simulator + envelope assertion in `ark-probe` (WP7) |
| No multi-hop / bridging | Server operator can correlate source ↔ destination | 0.2.1 (WP11) |
| IPv6 fully blocked in TUN mode | Apps fall back to v4; not a leak, but a feature gap | 0.2.1 (WP10) |

**Who can reasonably use it today (v0.2.0):**

* Users in moderately- and heavily-restricted networks (commercial DPI,
  national filters that aren't running ML-based flow analysis on every
  flow). The BIP 324 framing defeats today's signature-based DPI; the
  WP6 tarpit makes naive active probing produce the same "stalled real
  peer" signature it would get from a random Bitcoin node; and the
  WP1–WP3 multi-server pool means a single blocked IP no longer kills
  the deployment.
* Users with a higher-risk profile **provided** they (a) run with
  `--shape light` or `--shape heavy` against a v0.2.x server (the
  shaping is gated on capability negotiation, so an old server still
  works but quietly downgrades and logs a warning), (b) point the
  client at a multi-endpoint URI or a signed pool registry rather than
  a single hard-coded IP, and (c) understand that ArkTunnel still
  trusts a single server operator with the source ↔ destination
  correlation until multi-hop ships in 0.2.1 (WP11).

**Who should still NOT use this:** anyone whose adversary is plausibly
running full nation-state ML flow analysis (timing/volume correlation
against a known-good corpus), or anyone who needs to assume the server
operator is hostile. For the first case the v0.2.0 shaping policies
are a *speed bump*, not a defeat — they were sized to fool standard
DPI and unsupervised flow clustering, not a dedicated lab. For the
second case wait for v0.2.1 multi-hop, or use Tor with bridges.

---

## Security model

### Why no TLS / SSL / HTTPS

TLS certificates require a CA-signed domain name, which is visible in the TLS ClientHello
SNI field and trivially blocked or fingerprinted by a DPI firewall. Self-signed certificates
produce distinct TLS patterns that are equally easy to detect.

ArkTunnel replaces the TLS layer entirely with real Bitcoin / Ethereum wire-protocol
cryptography. These protocols were specifically designed to be indistinguishable from
random bytes on the wire (BIP 324 §8 "Traffic analysis resistance"). There is no SNI,
no certificate, no plaintext header — only random-looking bytes from the very first byte of
the TCP stream.

### BIP 324 security properties

BIP 324 is Bitcoin's encrypted peer-to-peer transport, defined in
[BIP-324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki).

**Key exchange:**

1. Each side generates an ephemeral X25519 key pair, encoded in EllSwift format (64 bytes).
   EllSwift encoding ensures the public key is indistinguishable from 64 random bytes
   — there is no "this is a public key" structure visible in the stream.
2. The shared secret is derived with `ECDH(our_priv, their_ellswift)` + HKDF-SHA256
   over a protocol-specific salt. Session keys are unique per connection and are never
   reused or stored.
3. Both sides send random-length garbage (up to 4 KB) before any meaningful data.
   A garbage terminator (a MAC derived from the session key) lets each side know when
   garbage ends, without being visible to an observer who lacks the session key.

**Packet encryption:**

Each plaintext message is wrapped in an AEAD packet:

```
| 3-byte encrypted length | 16-byte length MAC | ciphertext | 16-byte content MAC |
```

The cipher is FSChaCha20-Poly1305 — a forward-secret variant of ChaCha20-Poly1305 that
rekeyes automatically every 224 packets, so compromise of any single key does not expose
prior or subsequent traffic.

**Authentication:**

Session identity is carried inside the encrypted channel as `ARK1 || UUID` — the UUID is
the client's secret credential and is never transmitted in plaintext. A passive observer
cannot distinguish an ArkTunnel session from a Bitcoin node handshake.

**No PKI dependency:**

There are no certificates, no CAs, and no revocation infrastructure. The server has no
long-term identity key exposed to clients; every connection is authenticated purely by the
UUID secret shared out-of-band via the `arktunnel://` URI.

### RLPx security properties

RLPx (used on Ethereum port 30303) uses secp256k1 ECDH with ECIES for the auth handshake
(AES-128-CTR + HMAC-SHA256), then AES-256-CTR + SHA-3 MAC for the session. EIP-8 framing
is supported for forward compatibility. The security level is equivalent to ~128-bit
symmetric security.

### ARK-frame protocol (application layer)

After the transport handshake, ArkTunnel speaks its own minimal framing protocol on top of
the encrypted channel. There is no additional authentication or encryption at this layer —
the transport layer provides both.

```
Client → Server (inside encrypted channel):

  Packet 1: ARK1 magic (8 bytes) || UUID (16 bytes raw)
  Packet 2: ARK-frame request

  ARK-frame request wire format:
  +-----+-------+----------+--------+
  | cmd |  at   |   addr   |  port  |
  | u8  |  u8   | variable | u16 BE |
  +-----+-------+----------+--------+

  cmd  = 0x01  TCP connect (only command in v0)
  at   = 0x01  IPv4 (4 bytes follow)
         0x03  Domain (1-byte length, then UTF-8 bytes, max 253)
         0x04  IPv6 (16 bytes follow)

Server → Client (single byte):

  0x00  OK — bidirectional raw data copy begins immediately
  0x01  Connection refused
  0x02  Host unreachable / DNS failure
  0xFF  Generic error
```

This is deliberately minimal: "SOCKS5 after the negotiation phase, over an already-encrypted
channel". The small size (6–261 bytes) minimises the metadata available to timing attacks.

### Threat model summary

| Threat | Mitigation |
|--------|------------|
| Passive DPI (traffic classification) | BIP 324 / RLPx: wire bytes are computationally indistinguishable from random; no SNI, no cert, no plaintext header |
| Active probing (server fingerprinting) | The server completes a valid Bitcoin / Ethereum handshake with every connection — including real probes. Every malformed-input failure path holds the connection silently for a uniformly random `[10s, 60s]` then drops with no error byte (WP6); per-IP tarpit after 10 fails / 60 s short-circuits floods. The `ark-probe` crate (WP7) asserts this envelope holds end-to-end. |
| Flow-shape analysis (volume/timing) | `--shape light\|heavy` quantizes outbound payload lengths to fixed buckets and emits Poisson-distributed cover frames during idle (WP4), gated on the ARK-frame v2 capability negotiation (WP5). v0.1.x servers are silently treated as v1 (no shaping) so the client always tunnels. |
| Single-IP block | Multi-endpoint URI grammar (WP1) + sticky-with-demote failover (WP2) + signed pool registry with auto-fetch (WP3); rotating to a fresh node is one client restart away |
| Credential leak | UUID is only transmitted inside the encrypted channel |
| Session replay | Per-session ephemeral keys; nonce counter in FSChaCha20 prevents replay within a session |
| Man-in-the-middle | EllSwift ECDH binds the session to the ephemeral key pair; a MITM would produce a different session key and the UUID packet would fail to decrypt |
| Long-term key compromise | No long-term server key is exposed to clients; session keys are ephemeral and not persisted |

---

## Building from source

```sh
git clone https://github.com/st-hannibal/ArkTunnel
cd ArkTunnel
cargo build --release --workspace
```

Rust 1.87+ required (pinned in `rust-toolchain.toml`).

Binaries are placed in `target/release/`:

```
target/release/ark-server
target/release/ark-client
```

### Cross-compile static Linux binaries (musl)

```sh
rustup target add x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --workspace --target x86_64-unknown-linux-musl
```

---

## Running tests

```sh
cargo test --workspace
```

The test suite covers BIP 324 vector tests (session keys + ciphertext from the BIP spec),
ellswift encoding round-trips, ECIES round-trips, RLPx handshake, ARK1 detection, and the
full ARK-frame protocol (encode/decode round-trips for IPv4/6/domain, status codes, error
cases).

---

## Developer guide

### Crate layout

```
ark-core/
  src/
    lib.rs          — re-exports Transport, ARK1 helpers, arkframe, bip324, rlpx
    transport.rs    — Transport trait, BoxedAsyncReadWrite, Multiplexed enum
    arkframe.rs     — ARK-frame v0 protocol encoder/decoder
    bip324/
      mod.rs        — Bip324Transport (connect + accept), Bip324Stream AsyncRead/Write
      handshake.rs  — EllSwift ECDH, HKDF key derivation, garbage exchange
      ellswift.rs   — EllSwift encode/decode, x-only ECDH
      cipher.rs     — FSChaCha20-Poly1305 packet framing
    rlpx/
      mod.rs        — RlpxTransport (connect + accept), session relay helpers
      handshake.rs  — ECIES auth/ack, EIP-8 framing, Hello detection
      ecies.rs      — AES-128-CTR + HMAC-SHA256 encrypt/decrypt

ark-server/
  src/
    main.rs         — CLI (init / run / add-user / upgrade)
    run.rs          — accept loop, handle_connection, serve_arkframe
    config.rs       — ServerConfig (server.toml)
    init.rs         — first-run setup, UUID generation, config write
    add_user.rs     — append UUID, print new arktunnel:// URI

ark-client/
  src/
    main.rs         — CLI (run / test / tun)
    proxy.rs        — open_transport_only, activate_proxied_stream, Target enum
    socks5.rs       — SOCKS5 server (RFC 1928 CONNECT)
    http_proxy.rs   — HTTP CONNECT proxy
    tun.rs          — TUN-mode subprocess + per-OS route install/teardown
    uri.rs          — ArkUri parser (arktunnel:// scheme)
    pool.rs         — connection pool (pre-established transport channels)
```

### Adding a new transport

1. Implement `ark_core::transport::Transport` for your type:
   - `connect(TcpStream, SocketAddr) -> BoxedAsyncReadWrite` — client handshake
   - `accept(TcpStream) -> Multiplexed` — server handshake + ARK1 vs. real-peer detection
2. Add a variant to `TransportKind` in `ark-server/src/config.rs` and
   `ark-client/src/uri.rs`.
3. Wire the new variant into the `match cfg.transport` arms in `ark-server/src/run.rs`
   and the equivalent match in `ark-client/src/proxy.rs`.

No changes to `ark-core::arkframe` or the ARK1/UUID handling are needed — those operate
entirely above the transport layer.

### Adding a new ARK-frame command

ARK-frame v0 defines only `cmd = 0x01` (TCP connect). To add a new command:

1. Add a constant `CMD_*` in `ark-core/src/arkframe.rs`.
2. Extend `read_request` to parse the new wire format and return a new `FrameTarget`
   variant (or a separate type if the semantics differ).
3. Add a corresponding `build_request_*` encoder.
4. Handle the new command in `ark-server/src/run.rs::serve_arkframe`.
5. Add unit tests — see the existing `#[cfg(test)]` block in `arkframe.rs` for the pattern.

### Extending TUN mode to a new platform

`ark-client/src/tun.rs` keeps every OS-specific bit behind
`#[cfg(target_os = "...")]` arms inside three functions:

- `install_routes()` — the actual `route` / `ip` invocations.
- `read_default_route_*()` — parses the original gateway/interface so it
  can be restored on shutdown.
- `require_privileges()` — refuses to run unprivileged.

To add a new platform:

1. Add a `#[cfg(target_os = "<your-os>")]` arm to each of the three functions.
2. Every route added must be paired with a `janitor.record_undo(...)` entry so
   shutdown reverses it. The `RouteJanitor` runs entries LIFO and never
   propagates errors — cleanup is best-effort by design.
3. Pick a sensible default `--tun-name` in `ark-client/src/main.rs`
   (`DEFAULT_TUN_NAME` const, gated on `target_os`).
4. Add the platform's `tun2socks` asset name + checksum logic to the matching
   `install-client-*` script.

No changes to the wire protocol, server, or `ark-core` are needed — TUN mode
is a pure client-side feature on top of the existing SOCKS5 listener.

### Connection flow (reference)

```
                  CLIENT                              SERVER
                    │                                   │
  SOCKS5 accept ───▶│                                   │
  Target::Domain    │  TCP connect :8333                │
                    │──────────────────────────────────▶│
                    │  BIP 324 EllSwift (64B)           │
                    │──────────────────────────────────▶│
                    │◀─────────────────── EllSwift (64B)│
                    │  garbage + terminator             │
                    │──────────────────────────────────▶│
                    │◀──────────────── garbage+terminator│
                    │  version packet (encrypted, 20B)  │
                    │──────────────────────────────────▶│
                    │◀──────────────── version packet   │
                    │  [handshake complete]             │
                    │                                   │
                    │  ARK1 (8B magic + 16B UUID raw)   │  ← Multiplexed::ArkClient
                    │──────────────────────────────────▶│    validate_uuid()
                    │  ARK-frame request (6–261B)       │
                    │──────────────────────────────────▶│    serve_arkframe()
                    │                                   │    TcpStream::connect(target)
                    │◀──────────────────── 0x00 (OK)    │
                    │  bidirectional raw data           │◀──▶ upstream TCP
                    │◀─────────────────────────────────▶│
```

### Workspace conventions

- All async code uses Tokio. No `async-std` or `smol`.
- Error handling: `anyhow::Result` in binaries and integration paths; typed errors only
  where callers need to match on them (currently none).
- Logging: `tracing` with `INFO` for lifecycle events, `DEBUG` for per-connection details,
  `TRACE` for crypto internals. Set `RUST_LOG=ark_server=debug,ark_core=trace` for deep
  inspection.
- Clippy: CI runs `cargo clippy --workspace -- -D warnings`. No warnings allowed on `main`.
- Tests: `cargo test --workspace`. All tests must pass before merging to `main`.

---

## Security notes

- UUIDs are the only secret on the client side — treat them like passwords.
- The server drops root after binding the privileged port (`ARK_USER` env var, default
  `nobody`).
- Session keys are ephemeral; no long-term symmetric keys are persisted anywhere.
- All key material lives only in process memory for the duration of a single connection.
- EIP-8 forward compatibility: both legacy and EIP-8 RLPx auth messages are accepted.

---

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
