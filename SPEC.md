# ArkTunnel Protocol Specification

**Version:** 0.3  
**Status:** Current  
**Reference implementation:** https://github.com/st-hannibal/ArkTunnel  
**Current release:** v0.3.1

---

## 1. Overview

ArkTunnel is a censorship-resistant transport layer. It disguises tunnel
traffic as Bitcoin P2P or Ethereum P2P so that deep-packet-inspection
sees a connection indistinguishable from a real cryptocurrency node —
because the server *is* a real cryptocurrency node.

**Cover-traffic strategy:** the server runs a fully-validated Bitcoin
Core node (or geth) on the same port it uses for tunnel traffic.
Connections that do not carry ArkTunnel credentials are spliced to the
local crypto daemon and receive a genuine peer handshake. An adversary
probing the server gets real mainnet traffic.

### 1.1 Protocol stack

```
Client application
    │  SOCKS5 / HTTP CONNECT / TUN  (to ark-client, local loopback)
    ▼
ark-client
    │  BIP324 or RLPx  ← transport handshake (fully pseudorandom)
    │  ARK-frame v2    ← 2-byte capability negotiation + UUID auth
    │  Request envelope ← VLESS-style destination header
    ▼  bidirectional byte stream
ark-server
    │
    ├── [ARK client] mux → destination TCP (direct)
    │
    └── [real peer]  splice → local bitcoind / geth
```

The server has no subprocess dependencies. All protocol parsing and
proxying is done natively in Rust.

### 1.2 Design goals

| Goal | Status |
|---|---|
| Fully pseudorandom wire bytes from byte 0 | ✅ (BIP324 EllSwift encoding) |
| Unrecognised connections forward to a real node | ✅ (Phase-13 splice) |
| No plaintext distinguisher anywhere in the session | ✅ |
| Shape negotiation (padding / cover traffic) | ✅ (ARK-frame v2 capability bits) |
| Signed operator pool (no single-point-of-failure for discovery) | ✅ |
| Multi-hop anonymity | ⏳ v0.5.0 (Phase 16) |

---

## 2. URI Format

Operators distribute connection parameters as an `arktunnel://` URI.

```
arktunnel://<uuid>@<host>:<port>[?transport=<name>][&nodekey=<hex>][&pool=<url>][&poolkey=<hex>]
```

### 2.1 Components

| Field | Description |
|---|---|
| `uuid` | RFC 4122 UUID (hyphenated, case-insensitive). Tunnel credential. |
| `host` | Server hostname or IP. IPv6 MUST be bracket-enclosed: `[::1]`. |
| `port` | TCP port. Conventional: `8333` for `bip324`, `30303` for `rlpx`. |
| `transport` | `bip324` (default) or `rlpx`. |
| `nodekey` | RLPx only — 64-byte uncompressed secp256k1 public key (x‖y, no `04` prefix), hex-encoded. |
| `pool` | Optional HTTPS URL to a signed pool-registry document (see Section 7). |
| `poolkey` | Optional hex-encoded Ed25519 public key used to verify the pool document. |

### 2.2 Examples

```
# BIP324 (typical)
arktunnel://0aa6288b-f524-42f8-b54a-16782918e339@3.127.69.152:8333

# RLPx
arktunnel://0aa6288b-f524-42f8-b54a-16782918e339@3.127.69.152:30303?transport=rlpx&nodekey=04ab…ef

# With pool discovery
arktunnel://0aa6288b-…@3.127.69.152:8333?pool=https://pool.example.com/pool.json&poolkey=aabb…
```

### 2.3 Forward compatibility

Clients MUST ignore unknown query parameters.

---

## 3. Session Establishment

Every ArkTunnel session has four stages:

```
1. Transport handshake   — BIP324 or RLPx; no ArkTunnel bytes visible
2. ARK-frame v2 open     — 2-byte capability negotiation + UUID
3. Request envelope      — destination address (VLESS-style)
4. Bidirectional stream  — application data
```

---

## 4. ARK-frame v2

ARK-frame v2 replaces the flat 20-byte ARK1 marker from earlier versions.
It adds in-band capability negotiation so both sides agree on shape mode
and cover-traffic behaviour before any application data flows.

### 4.1 Client → Server opening frame

Sent as the first application-layer payload inside the encrypted
transport channel:

```
 Offset  Size  Field
 ------  ----  -----
  0       4    Magic: 0x41 0x52 0x4B 0x31  ("ARK1")
  1      16    UUID (RFC 4122 binary big-endian)
 20       2    Capability flags (see 4.3)
```

Total: **22 bytes**.

### 4.2 Server → Client capability response

Sent immediately after the server validates the UUID:

```
 Offset  Size  Field
 ------  ----  -----
  0       2    Accepted capability flags
```

Total: **2 bytes**.

The accepted flags are the bitwise AND of the client's offer and the
server's own capability mask. Both sides MUST use only the bits present
in the accepted mask for the remainder of the session.

### 4.3 Capability flag register

| Bit | Hex  | Name    | Description |
|-----|------|---------|-------------|
| 0   | 0x01 | `SHAPE` | Shape mode active — both sides pad/trim packets to the distribution described in Section 6.1. |
| 1   | 0x02 | `COVER` | Cover-traffic interspersing active (Section 6.2). |
| 2–15 | — | reserved | MUST be zero. Clients MUST accept reserved bits being set by future servers without aborting. |

### 4.4 RealPeer splice (Phase-13)

After the transport handshake the server reads the first decrypted frame.

- If bytes 0–3 equal `ARK1` (0x41 0x52 0x4B 0x31): tunnel client path (→ UUID validation → capability exchange → request envelope).
- Otherwise: real crypto peer. The server prepends the already-consumed bytes to a raw TCP splice aimed at the local Bitcoin Core node on `:18444` (or geth on the equivalent internal port). The prober receives a genuine mainnet handshake. No ArkTunnel-specific bytes are emitted.

The server MUST NOT close or RST the connection during the splice decision.
The splice MUST forward all bytes bidirectionally without modification.

---

## 5. Request Envelope

Immediately after the capability exchange, the client sends a
**VLESS-style request envelope** specifying the destination:

```
 Offset  Size  Field
 ------  ----  -----
  0       1    Version = 0x00
  1      16    UUID (same UUID as ARK-frame open, binary big-endian)
 17       1    Addon length = 0x00 (reserved)
 18       1    Command: 0x01 = TCP CONNECT
 19       2    Destination port (big-endian)
 21       1    Address type: 0x01=IPv4 / 0x02=domain / 0x03=IPv6
 22       *    Destination address:
                 IPv4:   4 bytes
                 domain: 1-byte length + N bytes (N ≤ 255)
                 IPv6:  16 bytes
```

### 5.1 Server response

```
 Offset  Size  Field
 ------  ----  -----
  0       1    Version = 0x00
  1       1    Addon length = 0x00
```

After the 2-byte response, bidirectional application data flows over the
encrypted channel.

### 5.2 Multi-hop target (Phase 16, v0.5.0)

When `Command = 0x01` and the destination address decodes to an
`arktunnel://` URI (address type `0x02`, domain prefixed with the scheme
bytes), the server enters **relay mode**: it opens a fresh BIP324
session to the next hop URI and pumps bytes bidirectionally. See Phase 16
in `localDocs/progress.md` for the full design.

---

## 6. Shape and Cover Traffic

### 6.1 Shape mode (`SHAPE` bit)

When negotiated, both sides bucket each outgoing write into one of four
size classes and pad to the nearest class boundary before encrypting:

| Class | Padded size |
|---|---|
| Micro | 64 B |
| Small | 512 B |
| Medium | 4096 B |
| Large | 16384 B |

Padding bytes are random. The recipient strips the pad using a 2-byte
big-endian actual-length prefix prepended before the pad (inside the
encrypted frame).

The class selected for each write is the smallest class ≥ the actual
payload length. Writes larger than 16384 B are fragmented.

Shape mode is on by default when the server's capability mask includes
`SHAPE`. Clients may suppress it by not offering the `SHAPE` bit (e.g.
`ark-client --shape off`).

### 6.2 Cover traffic (`COVER` bit)

When negotiated, both sides may send **cover frames** — empty or
random-payload frames — at any time to fill bandwidth during idle
periods. Cover frames use a reserved command byte (currently `0xFF`) in
the payload so the receiving side can drop them silently.

Cover traffic rate and pattern are implementation-defined; the protocol
does not mandate a specific schedule. The reference implementation uses
randomised inter-arrival times drawn from an exponential distribution
tuned to approximate Bitcoin gossip message cadence.

---

## 7. Pool Registry

Operators may publish a **pool registry document** — a signed JSON file
listing server entries — so that clients can discover endpoints without
receiving a per-server URI out-of-band.

### 7.1 Document format

```json
{
  "version": 1,
  "servers": [
    {
      "host": "3.127.69.152",
      "port": 8333,
      "uuid": "0aa6288b-f524-42f8-b54a-16782918e339",
      "transport": "bip324",
      "weight": 100,
      "role": "any"
    }
  ],
  "expires": "2026-12-31T00:00:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `version` | integer | Always `1` for this format. |
| `servers[].host` | string | Hostname or IP. |
| `servers[].port` | integer | TCP port. |
| `servers[].uuid` | string | RFC 4122 UUID hyphenated. |
| `servers[].transport` | string | `"bip324"` or `"rlpx"`. |
| `servers[].weight` | integer | Relative selection weight. Default `100`. |
| `servers[].role` | string | `"any"` (default), `"relay-only"`, or `"exit"`. Phase 16. |
| `expires` | string | RFC 3339 timestamp. Clients MUST reject expired documents. |

### 7.2 Signature

The document is signed with **Ed25519**. The canonical form for signing
is the JSON document with all keys sorted lexicographically and no
insignificant whitespace (compact form). The signature is a 64-byte
Ed25519 signature over `SHA-512(canonical_json)`.

Distribution format is implementation-defined; the reference uses a
sidecar `pool.json.sig` file containing the 64-byte signature hex-encoded,
or an inline `"signature"` key appended after serialisation (the signature
key is excluded from the canonical form).

### 7.3 Client behaviour

1. Fetch the pool document from the `pool=` URI in the user's arktunnel
   URI.
2. Verify the Ed25519 signature against the `poolkey=` public key.
3. Reject if `expires` is in the past.
4. Cache locally (TTL = `expires` value). Serve from cache on network
   failure.
5. Select a server weighted-randomly by `weight`.
6. For Phase 16 multi-hop: select entry from servers with
   `role ∈ {relay-only, any}` and exit from `role ∈ {exit, any}`.

---

## 8. Transport Specifications

### 8.1 BIP324 (`bip324`)

**Reference:** [BIP 324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)  
**Default port:** 8333  
**DPI resistance:** Fully pseudorandom from byte 0. No TLS, no HTTP, no Shadowsocks patterns.

#### Handshake (unmodified BIP324)

```
Initiator → Responder:  EllSwift pubkey (64B) ‖ garbage (0–4095B)
Responder → Initiator:  EllSwift pubkey (64B) ‖ garbage (0–4095B)
Both:                   garbage terminator (16B) ‖ encrypted version packet
```

Session keys via HKDF-SHA256, salt `"bitcoin_v2_shared_secret"‖NETWORK_MAGIC`:

| Label | Usage |
|---|---|
| `session_id` | 32-byte session identifier |
| `initiator_L` | Initiator→Responder length cipher (FSChaCha20) |
| `initiator_P` | Initiator→Responder packet cipher (FSChaCha20Poly1305) |
| `responder_L` | Responder→Initiator length cipher (FSChaCha20) |
| `responder_P` | Responder→Initiator packet cipher (FSChaCha20Poly1305) |
| `garbage_terminators` | [0:16] initiator terminator; [16:32] responder terminator |

**Length field:** FSChaCha20, rekeyed every 2²⁴ chunks.  
**Packet content:** FSChaCha20Poly1305, rekeyed every 2²⁴ messages.

ArkTunnel sends the ARK-frame v2 opening (Section 4.1) as the first
application-layer BIP324 packet with the ignore bit unset.

#### v1 peer detection

Before beginning the BIP324 state machine the server reads the first 16
bytes. If they match the Bitcoin mainnet v1 magic
(`\xf9\xbe\xb4\xd9version\x00\x00\x00\x00\x00`) the server exits
BIP324 and enters splice mode (Section 4.4), prepending the 16 bytes to
the splice stream so bitcoind receives a complete message.

### 8.2 RLPx (`rlpx`)

**Reference:** [devp2p RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md)  
**Default port:** 30303  
**DPI resistance:** ECIES payload opaque; 2-byte cleartext size prefix present. Less ideal than BIP324.

**Note:** The current implementation uses the pre-EIP-8 format. EIP-8
(forward-compatibility framing) is deferred to Phase 17 WP4. Until then
RLPx is marked **experimental** — prefer BIP324 for production deployments.

#### Static key requirement

RLPx auth is ECIES-encrypted to the responder's static secp256k1 key.
URIs for `rlpx` transport MUST include `nodekey=<hex64>` (64-byte x‖y,
no `04` prefix, 128 hex chars).

#### Handshake (pre-EIP-8)

**Auth message** (initiator → responder):
```
ECIES.encrypt(responder_static_pub,
    sig(65B) ‖ initiator_static_pub(64B) ‖ nonce(32B) ‖ vsn(1B=4))
```
Signature covers `keccak256(eph_shared_secret ⊕ nonce_I)`.

**Ack message** (responder → initiator):
```
ECIES.encrypt(initiator_static_pub,
    eph_pub(64B) ‖ nonce(32B) ‖ vsn(1B=4))
```

ECIES wire format:
```
04 ‖ eph_x(32B) ‖ eph_y(32B) ‖ IV(16B) ‖ AES-128-CTR ciphertext ‖ HMAC-SHA256(32B)
```

Key derivation: `kE‖kM = ConcatKDF(SHA-256, eph_shared_x, 32B)`.

#### Session keys
```
eph_shared  = ECDH(initiator_eph_priv, responder_eph_pub).x
shared      = keccak256(eph_shared ‖ keccak256(nonce_R ‖ nonce_I))
aes_secret  = keccak256(eph_shared ‖ shared)
mac_secret  = keccak256(eph_shared ‖ aes_secret)
```

Egress/ingress MACs: Keccak256 states seeded with
`mac_secret ⊕ nonce_R ‖ auth_ct` (egress for initiator; swapped for responder).

#### Frame format
```
header_ct(16B) ‖ header_mac(16B) ‖ frame_ct(padded to 16B) ‖ frame_mac(16B)
```
Cipher: AES-256-CTR, stateful across frames (IV = 0×16).

#### ArkTunnel integration via Hello capabilities

The RLPx p2p Hello message carries a capabilities list. ArkTunnel
clients MUST include `["ARK1", 0]`:

```
[["ARK1", 0], ["p2p", 5], ...]
```

If `ARK1` is absent the connection is treated as a real Ethereum peer and
spliced to geth (currently logged and dropped — full geth splice is a
future hardening item).

---

## 9. Transport Registry

| Name | Port | Underlying protocol | DPI resistance | Status |
|---|---|---|---|---|
| `bip324` | 8333 | Bitcoin P2P v2 (BIP 324) | Fully pseudorandom | Production |
| `rlpx` | 30303 | Ethereum devp2p RLPx | ECIES opaque; 2B cleartext prefix | Experimental |

---

## 10. Versioning and Interoperability

| Semver change | Wire impact | Policy |
|---|---|---|
| Patch (0.x.Y) | None | No wire change permitted. |
| Minor (0.X.0) | Additive | New capability bits, new URI params, new pool fields. Old clients degrade gracefully. |
| Major (X.0.0) | Breaking allowed | Requires `INTEROP.md` migration guide and simultaneous old-format support period. |

**Minimum interop matrix:**

| Client version | Server version | Result |
|---|---|---|
| 0.2.x | 0.3.x | Capability bits unknown to client ignored; session proceeds without SHAPE/COVER. |
| 0.3.x | 0.3.x | Full capability negotiation. |
| 0.3.x | 0.4.x | 0.4.x additive bits offered; 0.3.x client ignores unknown bits. |

---

## 11. Security Considerations

### 11.1 What ArkTunnel protects against

- **DPI classification:** Both transports produce ciphertext with no known proxy
  protocol signature. BIP324 is fully pseudorandom from byte 0.
- **Port-based blocking:** `:8333` is used by Bitcoin nodes globally. Blocking it
  disrupts real Bitcoin connectivity — a high political cost for governments that
  rely on cryptocurrency infrastructure.
- **IP-based blocking:** The server participates in real Bitcoin P2P peer discovery.
  Distinguishing it from real nodes by IP alone requires active probing.
- **Active probing:** Unrecognised connections receive a genuine Bitcoin mainnet
  handshake (Phase-13 splice). No timing or response difference betrays the server.

### 11.2 What ArkTunnel does not protect against

- **Traffic timing/volume analysis:** No mandatory padding schedule for raw flows
  (shape mode helps; cover traffic helps; neither is provably sufficient against a
  global passive adversary).
- **Single-operator trust:** In single-hop mode the server operator sees both the
  client source IP and the tunnel destination. Phase 16 (v0.5.0) adds a 2-hop
  chain to mitigate this.
- **UUID leakage:** The UUID is a shared secret. If the URI is leaked over an
  insecure channel, an attacker with the UUID can impersonate the user to the server.
- **Application-layer inspection by server:** The server reads the destination
  address from the request envelope. A compromised server can log destinations.

### 11.3 UUID security

- Transmitted only inside the encrypted channel; never visible on the wire.
- MUST be generated with a cryptographically secure RNG (128-bit entropy).
- Revocation: remove from `server.toml` and reload. No in-band revocation signal.
- Issue one UUID per user in multi-user deployments.

### 11.4 Cryptographic primitives

| Primitive | Usage |
|---|---|
| secp256k1 / X25519 | Key exchange |
| ChaCha20-Poly1305 | BIP324 packet encryption |
| FSChaCha20 | BIP324 length-field stream cipher |
| HKDF-SHA256 | BIP324 session key derivation |
| AES-256-CTR | RLPx frame encryption |
| HMAC-SHA256 | RLPx ECIES MAC |
| Keccak256 | RLPx session key derivation + MAC |
| Ed25519 | Pool registry document signatures |

---

## 12. Test Vectors

### 12.1 ARK-frame v2 opening (UUID `550e8400-e29b-41d4-a716-446655440000`, SHAPE+COVER)

```
Hex: 41 52 4b 31                   -- "ARK1" magic
     55 0e 84 00 e2 9b 41 d4        -- UUID bytes 0–7
     a7 16 44 66 55 44 00 00        -- UUID bytes 8–15
     00 03                          -- capability flags (SHAPE=1 | COVER=2)
Total: 22 bytes
```

### 12.2 BIP324

Official BIP 324 test vectors (all MUST pass):
- `bip-0324/ellswift_decode_test_vectors.csv`
- `bip-0324/xswiftec_inv_test_vectors.csv`
- `bip-0324/packet_encoding_test_vectors.csv`

Tracked in `ark-core/tests/bip324_vectors.rs`.

### 12.3 RLPx

devp2p ECIES and session-key vectors:
https://github.com/ethereum/devp2p/blob/master/rlpx.md

EIP-8 vector compliance deferred to Phase 17 WP4.

---

## 13. Changelog

| Version | Date | Notes |
|---|---|---|
| 0.1 | 2026-01-15 | Initial draft. BIP324 + RLPx. VLESS v0 framing over sing-box (superseded). |
| 0.2 | 2026-03-01 | Phase 9: dropped sing-box subprocess. Native Rust mux. ARK1 20-byte marker. |
| 0.3 | 2026-05-05 | Phase 12/13: ARK-frame v2 (22-byte open + 2-byte response, capability bits). Phase-13 RealPeer splice to local bitcoind. Pool registry with Ed25519 signatures. Shape and cover traffic. |
