// SOCKS5 proxy server (RFC 1928).
//
// Listens on 127.0.0.1:1080 by default.  Supports:
//   - NO_AUTH method negotiation (method 0x00)
//   - CONNECT command (TCP proxy through ark-server)
//   - UDP ASSOCIATE command — UDP datagrams are framed and tunneled through
//     the encrypted ARK-frame v1 channel to ark-server (since v0.1.9).
//   - BIND returns "command not supported"
//
// Address types: IPv4 (0x01), domain (0x03), IPv6 (0x04).

use crate::pool::Pool;
use crate::proxy::{open_udp_associate_stream, Target};
use crate::uri::ArkUri;
use anyhow::{bail, Result};
use ark_core::arkframe;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error};

// SOCKS5 reply codes (RFC 1928 §6).
const REP_SUCCESS: u8 = 0x00;
const REP_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Run the SOCKS5 proxy server until an unrecoverable listener error.
pub async fn run_socks5_server(addr: &str, uri: Arc<ArkUri>, pool: Arc<Pool>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("SOCKS5 listening on {addr}");
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!("SOCKS5 new connection from {peer}");
                let uri = uri.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5(stream, uri, pool).await {
                        debug!("SOCKS5 connection closed: {e}");
                    }
                });
            }
            Err(e) => error!("SOCKS5 accept error: {e}"),
        }
    }
}

async fn handle_socks5(mut client: TcpStream, uri: Arc<ArkUri>, pool: Arc<Pool>) -> Result<()> {
    // ── Step 1: method negotiation ──────────────────────────────────────────
    // Client sends: VER(1) NMETHODS(1) METHODS(NMETHODS)
    let mut buf2 = [0u8; 2];
    client.read_exact(&mut buf2).await?;
    if buf2[0] != 0x05 {
        bail!("SOCKS5: unsupported version byte: 0x{:02x}", buf2[0]);
    }
    let nmethods = buf2[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        // No acceptable methods.
        client.write_all(&[0x05, 0xFF]).await?;
        bail!("SOCKS5: client does not support NO_AUTH");
    }
    // Choose NO_AUTH.
    client.write_all(&[0x05, 0x00]).await?;

    // ── Step 2: request ─────────────────────────────────────────────────────
    // Client sends: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
    let mut hdr = [0u8; 4];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("SOCKS5: unexpected version in request: 0x{:02x}", hdr[0]);
    }
    let cmd = hdr[1];
    // hdr[2] = RSV, ignored
    let atyp = hdr[3];

    let target = match read_socks5_addr(&mut client, atyp).await {
        Ok(t) => t,
        Err(e) => {
            send_reply(&mut client, REP_ATYP_NOT_SUPPORTED).await?;
            return Err(e);
        }
    };

    match cmd {
        0x01 => handle_connect(client, uri, pool, target).await?,
        0x03 => handle_udp_associate(client, uri).await?,
        _ => {
            send_reply(&mut client, REP_CMD_NOT_SUPPORTED).await?;
            bail!("SOCKS5: unsupported command: 0x{cmd:02x}");
        }
    }
    Ok(())
}

async fn read_socks5_addr(client: &mut TcpStream, atyp: u8) -> Result<Target> {
    match atyp {
        0x01 => {
            // IPv4 — 4 bytes
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let port = read_port(client).await?;
            Ok(Target::Ipv4(addr, port))
        }
        0x03 => {
            // Domain — 1-byte length prefix + N bytes
            let len = client.read_u8().await? as usize;
            let mut domain_buf = vec![0u8; len];
            client.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf)
                .map_err(|_| anyhow::anyhow!("SOCKS5: domain is not valid UTF-8"))?;
            let port = read_port(client).await?;
            Ok(Target::Domain(domain, port))
        }
        0x04 => {
            // IPv6 — 16 bytes
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let port = read_port(client).await?;
            Ok(Target::Ipv6(addr, port))
        }
        other => bail!("SOCKS5: unsupported address type: 0x{other:02x}"),
    }
}

async fn read_port(client: &mut TcpStream) -> Result<u16> {
    let mut p = [0u8; 2];
    client.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

async fn handle_connect(mut client: TcpStream, _uri: Arc<ArkUri>, pool: Arc<Pool>, target: Target) -> Result<()> {
    // Acquire a stream from the pool (pre-established transport) or open a fresh one.
    let mut stream = match pool.acquire(&target).await {
        Ok(s) => s,
        Err(e) => {
            send_reply(&mut client, REP_FAILURE).await?;
            return Err(e);
        }
    };

    // Inform the SOCKS5 client that the connection is established.
    // BND.ADDR = 0.0.0.0, BND.PORT = 0 (we don't know the real bound address).
    send_reply(&mut client, REP_SUCCESS).await?;

    // Bidirectional copy: SOCKS5 client ↔ encrypted transport → sing-box → target.
    tokio::io::copy_bidirectional(&mut client, &mut stream).await?;
    Ok(())
}

/// Send a SOCKS5 reply with the given REP code.
/// BND.ADDR is always 0.0.0.0 and BND.PORT is always 0.
async fn send_reply(client: &mut TcpStream, rep: u8) -> Result<()> {
    // VER=5 REP RSV=0 ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
    let reply = [0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    client.write_all(&reply).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP ASSOCIATE (RFC 1928 §7)
// ---------------------------------------------------------------------------
//
// Design notes:
// UDP traffic is relayed directly to/from the real destination — it is NOT
// tunneled through the encrypted BIP 324 / RLPx transport (which is TCP-only).
// This means UDP datagrams (e.g. DNS queries) are not protected by the tunnel.
// TCP CONNECT traffic still goes through the encrypted transport as normal.
//
// Protocol flow:
//   1. Client sends UDP ASSOCIATE request (DST.ADDR/PORT are the client's
//      intended sending address, often 0.0.0.0:0).
//   2. We bind a UDP relay socket and reply with BND.ADDR:BND.PORT.
//   3. Client sends UDP datagrams to BND.ADDR:BND.PORT with SOCKS5 UDP header:
//        RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2) | DATA
//   4. We strip the header and forward DATA to the real destination.
//   5. Responses come back on the forwarding socket; we prepend the SOCKS5
//      header and send to the client's UDP address.
//   6. When the TCP control connection closes, the relay is torn down.
//
// Fragmentation (FRAG != 0) is not supported; fragmented datagrams are dropped.
//
// Since v0.1.9 (Phase 11): UDP datagrams are framed as ARK-frame v1
// length-prefixed datagrams (see `arkframe::write_udp_datagram`) and
// tunneled through the encrypted ark-server channel established by
// `CMD_UDP_ASSOCIATE`. The destination is preserved end-to-end (the
// server resolves domain destinations on the egress side).
async fn handle_udp_associate(mut client: TcpStream, uri: Arc<ArkUri>) -> Result<()> {
    // Open the UDP_ASSOCIATE channel to the server first; if that fails,
    // tell the SOCKS5 client cleanly.
    let tunnel = match open_udp_associate_stream(&uri).await {
        Ok(t) => t,
        Err(e) => {
            send_reply(&mut client, REP_FAILURE).await?;
            return Err(e);
        }
    };

    // Bind the local relay socket on all interfaces so the SOCKS5 caller (which
    // may be on another LAN address) can reach it.
    let relay = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let relay_port = relay.local_addr()?.port();

    // SOCKS5 reply: VER=5 REP=0 RSV=0 ATYP=1 BND=0.0.0.0:relay_port.
    let port_be = relay_port.to_be_bytes();
    let reply = [
        0x05, REP_SUCCESS, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        port_be[0], port_be[1],
    ];
    client.write_all(&reply).await?;

    // The client's UDP source address is unknown until the first datagram
    // arrives; replies are sent back to whichever source we last saw.
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let (mut tun_r, mut tun_w) = tokio::io::split(tunnel);

    let relay_outbound = relay.clone();
    let client_addr_outbound = client_addr.clone();
    let outbound = async move {
        // Max SOCKS5 UDP datagram size: 65535 + 22 byte header.
        let mut buf = vec![0u8; 65535 + 22];
        loop {
            let (n, from) = relay_outbound.recv_from(&mut buf).await?;
            let pkt = &buf[..n];
            if pkt.len() < 4 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
                continue;
            }
            let atyp = pkt[3];
            let (target, hdr_len) = match parse_socks5_udp_target(pkt, atyp) {
                Some(v) => v,
                None => continue,
            };
            *client_addr_outbound.lock().await = Some(from);
            let payload = &pkt[hdr_len..];
            if let Err(e) = arkframe::write_udp_datagram(&mut tun_w, &target, payload).await {
                debug!("SOCKS5 UDP → tunnel write failed: {e}");
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    let relay_inbound = relay.clone();
    let client_addr_inbound = client_addr.clone();
    let inbound = async move {
        loop {
            let (target, payload) = match arkframe::read_udp_datagram(&mut tun_r).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("SOCKS5 UDP ← tunnel read ended: {e}");
                    return Ok::<(), anyhow::Error>(());
                }
            };
            let to = match *client_addr_inbound.lock().await {
                Some(a) => a,
                None => continue, // no client UDP source seen yet — drop
            };
            let mut out = build_socks5_udp_hdr_target(&target);
            out.extend_from_slice(&payload);
            let _ = relay_inbound.send_to(&out, to).await;
        }
    };

    // Per RFC 1928 §7: when the TCP control connection closes, the UDP
    // relay MUST be torn down. Watch the TCP side for EOF.
    let control = async move {
        let mut drain = [0u8; 4];
        let _ = client.read(&mut drain).await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = outbound => r,
        r = inbound => r,
        r = control => r,
    }
}

/// Parse a SOCKS5 UDP request datagram's destination and return it as a
/// `FrameTarget` (preserving domain names) plus the byte offset where the
/// payload starts.
fn parse_socks5_udp_target(pkt: &[u8], atyp: u8) -> Option<(arkframe::FrameTarget, usize)> {
    match atyp {
        0x01 => {
            if pkt.len() < 4 + 4 + 2 {
                return None;
            }
            let mut a = [0u8; 4];
            a.copy_from_slice(&pkt[4..8]);
            let port = u16::from_be_bytes([pkt[8], pkt[9]]);
            Some((arkframe::FrameTarget::Ipv4(a, port), 10))
        }
        0x04 => {
            if pkt.len() < 4 + 16 + 2 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[4..20]);
            let port = u16::from_be_bytes([pkt[20], pkt[21]]);
            Some((arkframe::FrameTarget::Ipv6(a, port), 22))
        }
        0x03 => {
            if pkt.len() < 5 {
                return None;
            }
            let len = pkt[4] as usize;
            if len == 0 || pkt.len() < 5 + len + 2 {
                return None;
            }
            let name = std::str::from_utf8(&pkt[5..5 + len]).ok()?.to_string();
            let port = u16::from_be_bytes([pkt[5 + len], pkt[5 + len + 1]]);
            Some((arkframe::FrameTarget::Domain(name, port), 5 + len + 2))
        }
        _ => None,
    }
}

/// Build a SOCKS5 UDP reply header for a datagram from a given `FrameTarget`.
fn build_socks5_udp_hdr_target(target: &arkframe::FrameTarget) -> Vec<u8> {
    let mut hdr = vec![0x00, 0x00, 0x00]; // RSV(2) + FRAG(1)
    match target {
        arkframe::FrameTarget::Ipv4(a, p) => {
            hdr.push(0x01);
            hdr.extend_from_slice(a);
            hdr.extend_from_slice(&p.to_be_bytes());
        }
        arkframe::FrameTarget::Ipv6(a, p) => {
            hdr.push(0x04);
            hdr.extend_from_slice(a);
            hdr.extend_from_slice(&p.to_be_bytes());
        }
        arkframe::FrameTarget::Domain(d, p) => {
            hdr.push(0x03);
            let bytes = d.as_bytes();
            // Domain length is bounded by ARK-frame to <= 253; SOCKS5 supports up to 255.
            hdr.push(bytes.len() as u8);
            hdr.extend_from_slice(bytes);
            hdr.extend_from_slice(&p.to_be_bytes());
        }
    }
    hdr
}

