# ArkTunnel Protocol Specification

**Version:** 0.1  
**Status:** Draft  
**Reference Implementation:** https://github.com/arktunnel/arktunnel

---

## 1. Overview

ArkTunnel is a transport-layer protocol. It disguises proxy traffic as Bitcoin P2P (BIP 324) or Ethereum P2P (RLPx) so that deep packet inspection (DPI) sees a connection that is indistinguishable from traffic to a cryptocurrency node.

ArkTunnel is a *transport*, not a full VPN or proxy protocol. It occupies the same layer as WebSocket or gRPC transports in the V2Ray/sing-box ecosystem. The payload carried over an ArkTunnel session is a VLESS v0 stream, which in turn proxies arbitrary TCP traffic.

```
Client application
    │  SOCKS5 / HTTP CONNECT  (to ark-client, local loopback)
    ▼
ark-client
    │  ArkTunnel transport (BIP 324 or RLPx)
    │  + ARK1 session marker
    │  + VLESS v0 framing
    ▼
ark-server  ──► sing-box (VLESS inbound)  ──► Internet
    │
    └─►  bitcoind / geth  (real crypto peer traffic)
```

---

## 2. URI Format

Operators distribute connection parameters as an `arktunnel://` URI. This is analogous to a VLESS or Shadowsocks share link.

```
arktunnel://<uuid>@<host>:<port>?transport=<name>[&nodekey=<hex>]
```

### 2.1 Components

| Component | Description |
|-----------|-------------|
| `uuid` | RFC 4122 UUID (hyphenated, case-insensitive). Identifies the user on the server. Used as both the ArkTunnel session credential and the VLESS user identity. |
| `host` | Server hostname or IP address. IPv6 addresses MUST be enclosed in square brackets: `[::1]`. |
| `port` | TCP port. Conventional values: `8333` for `bip324`, `30303` for `rlpx`. |
| `transport` | Transport name (see Section 5). Default if absent: `bip324`. |
| `nodekey` | (RLPx only, required) Hex-encoded 64-byte uncompressed secp256k1 public key (`x‖y`, no `04` prefix). The client uses this to encrypt the ECIES auth message. |

### 2.2 Examples

**BIP 324 transport:**
```
arktunnel://550e8400-e29b-41d4-a716-446655440000@203.0.113.5:8333?transport=bip324
```

**RLPx transport:**
```
arktunnel://550e8400-e29b-41d4-a716-446655440000@203.0.113.5:30303?transport=rlpx&nodekey=04ab...ef
```

### 2.3 Forward Compatibility

Clients MUST ignore unknown query parameters. This allows future protocol extensions (e.g. `fingerprint=`, `mtu=`) without breaking older clients.

---

## 3. Session Establishment

Establishing an ArkTunnel session has three stages:

1. **Transport handshake** — the underlying P2P crypto handshake (BIP 324 or RLPx). No ArkTunnel-specific bytes appear on the wire during this stage.
2. **ARK1 session marker** — the first application-layer payload after the handshake identifies the connection as ArkTunnel.
3. **VLESS request** — the client sends a VLESS v0 header to instruct the server where to connect.

### 3.1 ARK1 Session Marker

After the transport handshake completes, the client sends a single encrypted payload:

```
ARK1 (4 bytes, ASCII) ‖ UUID (16 bytes, binary, RFC 4122 big-endian)
```

Total: **20 bytes**.

This payload is transmitted inside the transport's encrypted channel, so it is never visible to DPI. The server reads the first decrypted payload and checks the leading 4 bytes:

- If bytes 0–3 equal `ARK1` (0x41 0x52 0x4B 0x31): this is an ArkTunnel client connection. The UUID in bytes 4–19 is validated against the server's user list. If the UUID is not found, the connection is dropped immediately.
- Otherwise: this is a real crypto peer. The connection is forwarded to the local crypto daemon (bitcoind or geth).

The ARK1 check is the **only** place server-side UUID validation occurs. After the check passes, the server pipes the encrypted channel to sing-box VLESS and does not inspect further.

### 3.2 VLESS v0 Request

Immediately after sending the ARK1 marker (in the same or the next write), the client sends a VLESS v0 TCP CONNECT header:

```
 Offset  Size  Field
 ------  ----  -----
  0       1    Version (always 0x00)
  1      16    UUID (same UUID as ARK1, binary big-endian)
 17       1    Addon length (0x00 for no addons)
 18       1    Command (0x01 = TCP CONNECT)
 19       2    Destination port (big-endian)
 21       1    Address type: 0x01=IPv4, 0x02=domain, 0x03=IPv6
 22       *    Destination address:
                 IPv4:   4 bytes
                 domain: 1-byte length prefix + N bytes (max 255)
                 IPv6:  16 bytes
```

The server-side sing-box inbound reads this header and establishes an outbound connection to the specified destination.

### 3.3 VLESS v0 Response

sing-box responds with:

```
 Offset  Size  Field
 ------  ----  -----
  0       1    Version (always 0x00)
  1       1    Addon length N
  2       N    Addons (ignored; N is typically 0)
```

After the response header, raw bidirectional application data flows over the encrypted channel.

---

## 4. Transport Specifications

### 4.1 BIP 324 Transport (`bip324`)

**Reference:** [BIP 324 — Version 2 P2P Encrypted Transport Protocol](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)  
**Default port:** 8333  
**DPI resistance:** Fully pseudorandom bytestream from the first byte. No plaintext patterns, no TLS handshake, no length-prefixed headers. Gold standard for DPI evasion.

#### Handshake

The BIP 324 handshake is performed as specified in BIP 324 with no modifications. ArkTunnel does not extend or alter the handshake.

Wire format summary (for reference):

```
Initiator → Responder:  EllSwift-encoded pubkey (64B) ‖ random garbage (0–4095B)
Responder → Initiator:  EllSwift-encoded pubkey (64B) ‖ random garbage (0–4095B)
Both:                   garbage terminator (16B) ‖ encrypted version packet
```

Session keys are derived via HKDF-SHA256 with salt `"bitcoin_v2_shared_secret"‖NETWORK_MAGIC`:

| Key label | Usage |
|-----------|-------|
| `session_id` | 32-byte session identifier |
| `initiator_L` | Initiator → Responder length-field cipher (FSChaCha20) |
| `initiator_P` | Initiator → Responder packet cipher (FSChaCha20Poly1305) |
| `responder_L` | Responder → Initiator length-field cipher (FSChaCha20) |
| `responder_P` | Responder → Initiator packet cipher (FSChaCha20Poly1305) |
| `garbage_terminators` | First 16B = initiator garbage terminator; last 16B = responder garbage terminator |

#### Packet Cipher

**Length field:** FSChaCha20 (rekeying ChaCha20 stream cipher, rekeyed every 2^24 chunks, 3-byte chunks).  
**Packet content:** FSChaCha20Poly1305 (rekeying ChaCha20-Poly1305 AEAD, rekeyed every 2^24 messages).  
**Rekey trigger:** After every `REKEY_INTERVAL` (2^24) operations, consume the next 32 bytes of the keystream as the new key. Rekey nonce = `0x00*4 ‖ 0xFF*4 ‖ LE64(n_rekeyings)`.

#### ArkTunnel Integration

The ARK1 session marker (Section 3.1) is sent as the first application-layer BIP 324 packet, immediately after the version packet exchange. From BIP 324's perspective it is an ordinary encrypted packet with the ignore bit unset.

The server's v1-peer detection check (examining the first 16 bytes for Bitcoin mainnet magic `\xf9\xbe\xb4\xd9version\x00\x00\x00\x00\x00`) happens before the BIP 324 crypto handshake begins. This allows real Bitcoin v1 peers to be forwarded to bitcoind without ever entering the BIP 324 state machine.

#### Real-Peer Forwarding

When a real Bitcoin v1 peer connects, the 16-byte v1 prefix consumed during detection is prepended to the forwarded stream so bitcoind receives a complete message.

---

### 4.2 RLPx Transport (`rlpx`)

**Reference:** [RLPx Transport Protocol (devp2p)](https://github.com/ethereum/devp2p/blob/master/rlpx.md)  
**Default port:** 30303  
**DPI resistance:** Partial. The auth message has a 2-byte cleartext size prefix followed by ECIES ciphertext; the ECIES payload is opaque. Less ideal than BIP 324's fully pseudorandom stream, but the server's IP appearing in the Ethereum peer discovery network provides operational cover.

#### Static Key Requirement

Unlike BIP 324 (ephemeral only), RLPx auth is ECIES-encrypted to the responder's *static* secp256k1 public key. The initiator must know this key before connecting. Consequently:

- `arktunnel://` URIs for `rlpx` transport MUST include `nodekey=<hex64>`.
- `<hex64>` is the 64-byte uncompressed secp256k1 public key (x‖y coordinates, no `04` prefix, 128 hex characters).
- The server generates its static keypair once at `ark-server init` time and embeds the public key in all distributed URIs.

#### Handshake (Old Format / Pre-EIP-8)

The current implementation uses the pre-EIP-8 old format. EIP-8 (forward compatibility via RLP + size prefix) is deferred to a future version.

**Auth message** (initiator → responder):

```
ECIES.encrypt(responder_static_pub,
    sig(65B)                  // ECDSA-recoverable signature
  ‖ initiator_static_pub(64B) // x‖y, no prefix
  ‖ nonce(32B)                // random
  ‖ vsn(1B=4)                 // version
)
```

The signature covers `keccak256(eph_shared_secret ⊕ nonce_I)`.

**Ack message** (responder → initiator):

```
ECIES.encrypt(initiator_static_pub,
    eph_pub(64B)  // responder's ephemeral pubkey, x‖y
  ‖ nonce(32B)   // random
  ‖ vsn(1B=4)
)
```

ECIES wire format used in both messages:

```
04 ‖ ephemeral_pub_x(32B) ‖ ephemeral_pub_y(32B)  // 65B
‖ IV(16B)
‖ AES-128-CTR ciphertext
‖ HMAC-SHA256(SHA256(kM), IV ‖ ciphertext)          // 32B
```

Key derivation uses ConcatKDF(SHA-256): `kE ‖ kM = ConcatKDF(eph_shared_x, 32B)` where the first 16 bytes are the AES key and the next 16 bytes are the MAC key (hashed to 32 bytes for HMAC use).

#### Session Key Derivation

```
eph_shared  = ECDH(initiator_eph_priv, responder_eph_pub).x
shared      = keccak256(eph_shared ‖ keccak256(nonce_R ‖ nonce_I))
aes_secret  = keccak256(eph_shared ‖ shared)
mac_secret  = keccak256(eph_shared ‖ aes_secret)
```

Egress/ingress MACs are Keccak256 states seeded with:

```
egress_mac.update(mac_secret ⊕ nonce_R ‖ auth_ciphertext)    // for initiator
ingress_mac.update(mac_secret ⊕ nonce_I ‖ ack_ciphertext)    // for initiator
(swapped for responder)
```

#### Frame Encryption

Each RLPx frame:

```
header_ct(16B) ‖ header_mac(16B) ‖ frame_ct(padded to 16B) ‖ frame_mac(16B)
```

- **Cipher:** AES-256-CTR, stateful across frames (IV = 0x00*16, no seek between frames).
- **Header MAC:** `AES-ECB(mac_secret, running_mac_digest[:16]) ⊕ header_ct`
- **Frame MAC:** `running_mac_digest[:16] ⊕ AES-ECB(mac_secret, running_mac_digest[:16])`

The header encodes the 3-byte big-endian frame length in the first 3 bytes, padded to 16 bytes with zeros.

#### ArkTunnel Integration via Hello Capabilities

The RLPx p2p Hello message (sent by both sides after auth/ack) carries a capabilities list. ArkTunnel clients MUST include `["ARK1", 0]` as one of the capabilities.

```
Hello capabilities list (RLP):
  [["ARK1", 0], ["p2p", 5], ...]
```

The server inspects the capabilities in the client's Hello. If `ARK1` is present:

1. The server sends its own Hello (without ARK1 — a real node would not advertise it).
2. The server reads the next RLPx data frame, which MUST be the 20-byte ARK1+UUID payload.
3. UUID validation is performed as in Section 3.1.

If `ARK1` is absent, the connection is a real Ethereum peer. Full p2p proxying to geth is a future hardening item; currently the connection is logged and dropped.

---

## 5. Transport Registry

| Transport Name | Default Port | Underlying Protocol | DPI Resistance |
|---------------|-------------|---------------------|----------------|
| `bip324`      | 8333        | Bitcoin P2P v2 (BIP 324) | Fully pseudorandom |
| `rlpx`        | 30303       | Ethereum RLPx (devp2p) | ECIES payload opaque; 2B cleartext size prefix |

---

## 6. Extensibility

### 6.1 Adding a New Transport

1. Implement the `Transport` trait from `ark-core/src/transport.rs`:

```rust
pub trait Transport: Send + Sync {
    fn name() -> &'static str;
    fn default_port() -> u16;
    async fn connect(stream: TcpStream) -> Result<BoxedAsyncReadWrite>;
    async fn accept(stream: TcpStream) -> Result<Multiplexed>;
}
```

2. After the transport's own handshake completes, `connect()` MUST send the ARK1+UUID payload (Section 3.1) followed by the VLESS request header (Section 3.2).

3. `accept()` MUST read the first decrypted payload and return `Multiplexed::ArkClient` if it begins with `ARK1`, or `Multiplexed::RealPeer` if it is a standard crypto peer message.

4. Register the transport name in the URI parser (`ark-client/src/uri.rs`) and the server dispatch (`ark-server/src/run.rs`).

5. Add the transport name and port to Section 5 of this document.

### 6.2 URI Parameter Extensions

Future transports may need additional URI parameters (analogous to `nodekey=` for RLPx). All parameters are `key=value` pairs in the query string. Parameters defined for one transport are ignored by all others. Unrecognised parameters are ignored by clients for forward compatibility.

---

## 7. Security Considerations

### 7.1 What ArkTunnel Protects Against

- **DPI traffic classification:** Both transports produce ciphertext that does not match any known proxy protocol signature (no TLS ClientHello, no HTTP CONNECT, no Shadowsocks magic bytes, no VLESS frame headers on the wire).
- **Port-based blocking:** The server listens on the same port as the crypto node it mimics (8333/30303). Blocking this port would break connectivity to a significant fraction of Bitcoin or Ethereum nodes globally.
- **IP-based blocking:** The server's IP legitimately participates in Bitcoin or Ethereum P2P node discovery, making it harder to distinguish from real crypto nodes by IP reputation alone.

### 7.2 What ArkTunnel Does Not Protect Against

- **Traffic analysis (timing/volume):** ArkTunnel does not pad packets or add timing jitter. An adversary with access to both ends of the connection can correlate flows.
- **Destination concealment:** The exit server (ark-server) knows what IP/domain the client is connecting to, as it appears in the VLESS request header.
- **Client anonymity:** The UUID in the ARK1 marker identifies the user to the server. Multi-user deployments should issue one UUID per user.
- **Application-layer inspection by server:** The server decrypts the VLESS header before forwarding. A compromised server can read destination addresses.
- **Zero-day DPI beyond protocol signatures:** A sufficiently advanced adversary with behavioural traffic analysis capability may still identify ArkTunnel sessions based on flow characteristics.

### 7.3 UUID Security

The UUID is a shared secret between the client and server. It is transmitted only inside the encrypted transport channel and is never visible on the wire. However:

- If the URI is leaked (e.g. shared over unencrypted channels), an attacker who knows the UUID can impersonate a legitimate user.
- UUIDs SHOULD be generated with a cryptographically secure random number generator.
- Revoked UUIDs MUST be removed from `server.toml` and sing-box reloaded; there is no mechanism for the server to signal revocation to the client.

### 7.4 LAN Deployment (ark-client)

When `ark-client` is started with `--socks5 0.0.0.0:1080`, the SOCKS5 port is reachable from any host on the same network. On untrusted networks (hotel, office, public WiFi), this exposes the proxy port to other users on the network. Users SHOULD restrict access with host-based firewall rules when binding to `0.0.0.0`.

### 7.5 Cryptographic Primitives

| Primitive | Usage | Notes |
|-----------|-------|-------|
| secp256k1 | Key exchange (both transports) | 128-bit security |
| ChaCha20-Poly1305 | BIP 324 packet encryption | 256-bit key, 96-bit nonce |
| AES-256-CTR | RLPx frame encryption | 256-bit key |
| HMAC-SHA256 | RLPx ECIES MAC | |
| HKDF-SHA256 | BIP 324 session key derivation | |
| Keccak256 | RLPx session key derivation + MAC | |

---

## 8. Test Vectors

### 8.1 ARK1 Payload

For UUID `550e8400-e29b-41d4-a716-446655440000`:

```
ASCII: A R K 1 [16 UUID bytes in RFC 4122 big-endian order]
Hex:   41 52 4b 31 55 0e 84 00 e2 9b 41 d4 a7 16 44 66 55 44 00 00
```

### 8.2 BIP 324

See the official BIP 324 test vectors:
- `bip-0324/ellswift_decode_test_vectors.csv`
- `bip-0324/xswiftec_inv_test_vectors.csv`
- `bip-0324/packet_encoding_test_vectors.csv`

The ArkTunnel reference implementation MUST pass all of these vectors. (Full compliance is tracked as a Phase 8 hardening item.)

### 8.3 RLPx

See the devp2p RLPx test vectors in the [ethereum/devp2p](https://github.com/ethereum/devp2p/blob/master/rlpx.md) repository for ECIES and session key derivation.

---

## 9. Changelog

| Version | Date | Notes |
|---------|------|-------|
| 0.1 | 2026-05-05 | Initial draft. BIP 324 + RLPx transports. VLESS v0 payload. |
