// SOCKS5 proxy server (RFC 1928).
//
// Listens on 127.0.0.1:1080 by default.  Supports:
//   - NO_AUTH method negotiation (method 0x00)
//   - CONNECT command (TCP proxy through ark-server)
//   - UDP ASSOCIATE command (local UDP relay; UDP traffic is not tunneled through
//     the encrypted transport — see implementation notes in handle_udp_associate)
//   - BIND returns "command not supported"
//
// Address types: IPv4 (0x01), domain (0x03), IPv6 (0x04).

use crate::pool::Pool;
use crate::proxy::Target;
use crate::uri::ArkUri;
use anyhow::{bail, Result};
use std::collections::HashMap;
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
        0x03 => handle_udp_associate(client).await?,
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
async fn handle_udp_associate(mut client: TcpStream) -> Result<()> {
    // Bind the relay socket on all interfaces so the client (which may be on
    // another LAN address) can reach it.  Using port 0 lets the OS pick a
    // free ephemeral port.
    let relay = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let relay_port = relay.local_addr()?.port();

    // SOCKS5 reply: VER=5, REP=0 (success), RSV=0, ATYP=1 (IPv4),
    // BND.ADDR=0.0.0.0, BND.PORT=relay_port.
    let port_be = relay_port.to_be_bytes();
    let reply = [
        0x05, REP_SUCCESS, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        port_be[0], port_be[1],
    ];
    client.write_all(&reply).await?;

    // Forwarding table: maps (client_udp_addr, dst_addr) -> forwarding UdpSocket.
    // Arc<Mutex<...>> so the relay task and the response tasks can both access it.
    type FwdMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>>>;
    let fwd_map: FwdMap = Arc::new(Mutex::new(HashMap::new()));

    let relay_for_task = relay.clone();
    let fwd_map_for_task = fwd_map.clone();

    // Spawn the UDP relay loop.
    let udp_task = tokio::spawn(async move {
        udp_relay_loop(relay_for_task, fwd_map_for_task).await
    });

    // Per RFC 1928 §7: when the TCP control connection closes, the UDP relay
    // MUST be torn down.  We wait here for the TCP EOF.
    let mut drain = [0u8; 4];
    let _ = client.read(&mut drain).await;

    udp_task.abort();
    Ok(())
}

type FwdMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>>>;

async fn udp_relay_loop(
    relay: Arc<UdpSocket>,
    fwd_map: FwdMap,
) -> Result<()> {
    // 22 bytes = max SOCKS5 UDP header (RSV:2 + FRAG:1 + ATYP:1 + IPv6:16 + PORT:2)
    let mut buf = vec![0u8; 65535 + 22];
    loop {
        let (n, from) = relay.recv_from(&mut buf).await?;
        let pkt = &buf[..n];

        // Validate SOCKS5 UDP header: RSV must be 0x0000, FRAG must be 0.
        if pkt.len() < 4 || pkt[0] != 0 || pkt[1] != 0 {
            continue;
        }
        if pkt[2] != 0 {
            // Fragmented datagrams are not supported.
            continue;
        }

        let atyp = pkt[3];
        let (dst, hdr_len) = match parse_socks5_udp_addr(pkt, atyp) {
            Some(v) => v,
            None => continue,
        };
        let payload = &pkt[hdr_len..];

        let key = (from, dst);
        let fwd_sock = {
            let mut map = fwd_map.lock().await;
            if let Some(s) = map.get(&key) {
                s.clone()
            } else {
                // Open a forwarding socket for this (client, destination) pair
                // and spawn a task that relays responses back to the client.
                let sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Arc::new(s),
                    Err(_) => continue,
                };
                map.insert(key, sock.clone());

                let sock2 = sock.clone();
                let relay2 = relay.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 65535];
                    loop {
                        match sock2.recv_from(&mut rbuf).await {
                            Ok((rn, resp_from)) => {
                                let hdr = build_socks5_udp_hdr(resp_from);
                                let mut out = hdr;
                                out.extend_from_slice(&rbuf[..rn]);
                                let _ = relay2.send_to(&out, from).await;
                            }
                            Err(_) => return,
                        }
                    }
                });

                sock
            }
        };

        let _ = fwd_sock.send_to(payload, dst).await;
    }
}

/// Parse a SOCKS5 address field (starting at pkt[1] after ATYP byte which is pkt[0]).
///
/// `pkt`: the full UDP datagram starting at the ATYP byte (pkt[0] = ATYP).
/// Returns `(resolved SocketAddr, total header length)`.
fn parse_socks5_udp_addr(pkt: &[u8], atyp: u8) -> Option<(SocketAddr, usize)> {
    // pkt layout: RSV(2) FRAG(1) ATYP(1) ADDR(var) PORT(2)
    // We are called with the full packet; addr starts at byte 4.
    match atyp {
        0x01 => {
            // IPv4: 4 bytes + 2 port
            if pkt.len() < 4 + 4 + 2 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(pkt[4], pkt[5], pkt[6], pkt[7]);
            let port = u16::from_be_bytes([pkt[8], pkt[9]]);
            Some((SocketAddr::from((ip, port)), 10))
        }
        0x04 => {
            // IPv6: 16 bytes + 2 port
            if pkt.len() < 4 + 16 + 2 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([pkt[20], pkt[21]]);
            Some((SocketAddr::from((ip, port)), 22))
        }
        0x03 => {
            // Domain name: 1-byte length + N bytes + 2 port.
            // We resolve synchronously using std; for DNS UDP relay this is fast enough.
            if pkt.len() < 5 {
                return None;
            }
            let len = pkt[4] as usize;
            if pkt.len() < 5 + len + 2 {
                return None;
            }
            let name = std::str::from_utf8(&pkt[5..5 + len]).ok()?;
            let port = u16::from_be_bytes([pkt[5 + len], pkt[5 + len + 1]]);
            use std::net::ToSocketAddrs;
            let addr = format!("{name}:{port}")
                .to_socket_addrs()
                .ok()?
                .next()?;
            Some((addr, 5 + len + 2))
        }
        _ => None,
    }
}

/// Build a SOCKS5 UDP reply header for a response originating from `src`.
fn build_socks5_udp_hdr(src: SocketAddr) -> Vec<u8> {
    let mut hdr = vec![0x00, 0x00, 0x00]; // RSV(2) + FRAG(1)
    match src {
        SocketAddr::V4(v4) => {
            hdr.push(0x01); // ATYP = IPv4
            hdr.extend_from_slice(&v4.ip().octets());
            hdr.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            hdr.push(0x04); // ATYP = IPv6
            hdr.extend_from_slice(&v6.ip().octets());
            hdr.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    hdr
}
