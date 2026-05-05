//! Full-device TUN mode (Phase 10).
//!
//! Spawns the upstream `tun2socks` binary
//! (https://github.com/xjasonlyu/tun2socks) and points it at the in-process
//! SOCKS5 listener on `127.0.0.1:1080`. Installs OS-specific routes so that
//! the system default route runs through the TUN device, while keeping a
//! /32 host bypass route to the ark-server itself (otherwise the encrypted
//! ArkTunnel session would loop through itself and dead-lock).
//!
//! UDP is intentionally dropped at the TUN layer in v0.1.8 because the
//! ArkTunnel server only carries TCP. UDP support is queued for Phase 11.
//!
//! All routes are recorded in a `RouteJanitor` so they are reverted on
//! `Ctrl-C` / `SIGTERM` / panic.

use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::uri::ArkUri;

/// Default IPv4 inside the TUN device.  We use the IANA "benchmark" range
/// (198.18.0.0/15) which is reserved and never globally routed, so it is safe
/// to use as a virtual gateway.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
const TUN_LOCAL_IP: &str = "198.18.0.1";
#[cfg_attr(target_os = "linux", allow(dead_code))]
const TUN_GATEWAY_IP: &str = "198.18.0.2";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const TUN_NETMASK_PREFIX: u8 = 15;

#[derive(Debug, Clone)]
pub struct TunConfig {
    #[allow(dead_code)]
    pub uri: Arc<ArkUri>,
    pub socks5_addr: String,
    pub tun_name: String,
    pub mtu: u16,
    #[allow(dead_code)]
    pub tun2socks_override: Option<PathBuf>,
}

/// Locate the `tun2socks` binary using, in order:
///
/// 1. explicit `--tun2socks` flag (`override_path`),
/// 2. `ARK_TUN2SOCKS` environment variable,
/// 3. installer drop location `/usr/local/libexec/arktunnel/tun2socks`,
/// 4. lookup on `$PATH`.
pub fn locate_tun2socks(override_path: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        if p.exists() {
            return Ok(p.clone());
        }
        bail!("--tun2socks path does not exist: {}", p.display());
    }
    if let Ok(p) = env::var("ARK_TUN2SOCKS") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
    }
    let installed = PathBuf::from("/usr/local/libexec/arktunnel/tun2socks");
    if installed.exists() {
        return Ok(installed);
    }
    if let Ok(p) = which("tun2socks") {
        return Ok(p);
    }
    bail!(
        "tun2socks binary not found.\n\
         Install it from https://github.com/xjasonlyu/tun2socks/releases\n\
         and place it on PATH or at /usr/local/libexec/arktunnel/tun2socks,\n\
         or pass --tun2socks /path/to/tun2socks."
    )
}

/// Tiny `which`-equivalent so we don't take an extra dependency.
fn which(bin: &str) -> Result<PathBuf> {
    let path = env::var_os("PATH").ok_or_else(|| anyhow!("PATH not set"))?;
    for entry in env::split_paths(&path) {
        let candidate = entry.join(bin);
        if candidate.is_file() {
            return Ok(candidate);
        }
        #[cfg(windows)]
        {
            let with_ext = entry.join(format!("{bin}.exe"));
            if with_ext.is_file() {
                return Ok(with_ext);
            }
        }
    }
    bail!("{bin} not found on PATH")
}

/// Resolve the configured ark-server hostname to an IP literal so that we can
/// install a /32 bypass route. If the URI host is already an IP, return it.
pub async fn resolve_server_ip(uri: &ArkUri) -> Result<std::net::IpAddr> {
    if let Ok(ip) = uri.host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    let addrs = tokio::net::lookup_host((uri.host.as_str(), uri.port))
        .await
        .with_context(|| format!("resolving server host {}", uri.host))?;
    let v4 = addrs
        .into_iter()
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow!("no IPv4 address for {}", uri.host))?;
    Ok(v4.ip())
}

/// Refuse to run if the process does not have privileges to add routes / open
/// the TUN device on this OS.
pub fn require_privileges() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        if libc_geteuid() != 0 {
            bail!(
                "tun mode requires root.\n\
                 Re-run with: sudo -E ark-client tun --uri '...'"
            );
        }
    }
    #[cfg(windows)]
    {
        // Best-effort hint; route.exe will fail loudly if not elevated.
        info!("ensure this Command Prompt / PowerShell is running as Administrator");
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

/// Routes that need to be torn down on shutdown. The destructor reverses
/// every entry in LIFO order, on a best-effort basis (a failed cleanup is
/// logged but not re-raised so we always continue tearing down the rest).
#[derive(Default)]
pub struct RouteJanitor {
    undo: Mutex<Vec<Vec<String>>>,
}

impl RouteJanitor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn record_undo(&self, argv: Vec<String>) {
        self.undo.lock().await.push(argv);
    }

    pub async fn run_all(&self) {
        let mut guard = self.undo.lock().await;
        while let Some(argv) = guard.pop() {
            info!("cleanup: {}", argv.join(" "));
            let _ = run_cmd(&argv).await;
        }
    }
}

/// Install OS-specific routes so that the system default route flows through
/// the TUN device, while a /32 to the ark-server escapes via the original
/// gateway. Returns the routes registered with the janitor for cleanup.
pub async fn install_routes(
    cfg: &TunConfig,
    server_ip: std::net::IpAddr,
    janitor: &RouteJanitor,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // 1. Bring the device up and assign it the inner IP.
        run_cmd(&[
            "ip",
            "addr",
            "add",
            &format!("{TUN_LOCAL_IP}/{TUN_NETMASK_PREFIX}"),
            "dev",
            &cfg.tun_name,
        ])
        .await
        .context("ip addr add")?;
        run_cmd(&["ip", "link", "set", &cfg.tun_name, "up"])
            .await
            .context("ip link set up")?;
        janitor
            .record_undo(vec!["ip".into(), "link".into(), "set".into(), cfg.tun_name.clone(), "down".into()])
            .await;
        janitor
            .record_undo(vec![
                "ip".into(), "addr".into(), "del".into(),
                format!("{TUN_LOCAL_IP}/{TUN_NETMASK_PREFIX}"),
                "dev".into(), cfg.tun_name.clone(),
            ])
            .await;

        // 2. Server bypass route via the original default gateway.
        let (orig_gw, orig_dev) = read_default_route_linux().await?;
        run_cmd(&[
            "ip", "route", "add",
            &format!("{server_ip}/32"),
            "via", &orig_gw,
            "dev", &orig_dev,
        ])
        .await
        .context("ip route add server bypass")?;
        janitor
            .record_undo(vec![
                "ip".into(), "route".into(), "del".into(),
                format!("{server_ip}/32"),
            ])
            .await;

        // 3. Replace default route to go through TUN device.
        run_cmd(&["ip", "route", "del", "default"]).await.ok();
        run_cmd(&["ip", "route", "add", "default", "dev", &cfg.tun_name])
            .await
            .context("ip route add default via tun")?;
        // Restore the original default on cleanup.
        janitor
            .record_undo(vec![
                "ip".into(), "route".into(), "add".into(), "default".into(),
                "via".into(), orig_gw, "dev".into(), orig_dev,
            ])
            .await;
        janitor
            .record_undo(vec!["ip".into(), "route".into(), "del".into(), "default".into()])
            .await;

        // 4. Block IPv6 entirely — ArkTunnel only carries IPv4 today, so any
        //    v6-capable site would otherwise bypass the tunnel and leak the
        //    user's real IPv6 address.
        for net6 in ["::/1", "8000::/1"] {
            if run_cmd(&["ip", "-6", "route", "add", "blackhole", net6])
                .await
                .is_ok()
            {
                janitor
                    .record_undo(vec![
                        "ip".into(), "-6".into(), "route".into(), "del".into(),
                        "blackhole".into(), net6.into(),
                    ])
                    .await;
            } else {
                warn!("could not install IPv6 blackhole route for {net6}; v6 may leak");
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let (orig_gw, _orig_dev) = read_default_route_macos().await?;

        // tun2socks opens the utun device on macOS but does NOT assign it an
        // address — without an address the kernel silently drops every packet
        // routed at it. Configure a point-to-point address and MTU so traffic
        // actually flows.
        run_cmd(&[
            "ifconfig",
            &cfg.tun_name,
            TUN_LOCAL_IP,
            TUN_GATEWAY_IP,
            "up",
        ])
        .await
        .context("ifconfig utun assign address")?;
        run_cmd(&[
            "ifconfig",
            &cfg.tun_name,
            "mtu",
            &cfg.mtu.to_string(),
        ])
        .await
        .context("ifconfig utun mtu")?;
        janitor
            .record_undo(vec![
                "ifconfig".into(), cfg.tun_name.clone(), "down".into(),
            ])
            .await;

        // Server bypass via original gateway.
        run_cmd(&[
            "route", "-n", "add", "-host",
            &server_ip.to_string(),
            &orig_gw,
        ])
        .await
        .context("route add -host server bypass")?;
        janitor
            .record_undo(vec![
                "route".into(), "-n".into(), "delete".into(), "-host".into(),
                server_ip.to_string(),
            ])
            .await;

        // Keep DNS working while UDP forwarding is disabled in v0.1.8:
        // bypass system resolver IPs via the original gateway.
        for dns_ip in read_system_dns_servers_macos().await? {
            let dns = dns_ip.to_string();
            if dns == orig_gw {
                // Resolver is the LAN gateway itself; traffic to it is already
                // on-link and does not need an explicit host route.
                continue;
            }
            match run_cmd(&["route", "-n", "add", "-host", &dns, &orig_gw]).await {
                Ok(()) => {
                    janitor
                        .record_undo(vec![
                            "route".into(), "-n".into(), "delete".into(), "-host".into(),
                            dns,
                        ])
                        .await;
                }
                Err(err) => {
                    warn!("failed to add DNS bypass route for {}: {}", dns, err);
                }
            }
        }

        // Split-default: 0/1 + 128/1 covers all v4 without touching the real default.
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            run_cmd(&[
                "route", "-n", "add", "-net", net, TUN_GATEWAY_IP,
            ])
            .await
            .with_context(|| format!("route add -net {net}"))?;
            janitor
                .record_undo(vec![
                    "route".into(), "-n".into(), "delete".into(), "-net".into(),
                    net.into(),
                ])
                .await;
        }

        // Block IPv6 entirely while the tunnel is up. ArkTunnel only carries
        // IPv4 today, so without these blackhole routes any v6-capable site
        // (Google, YouTube, most CDNs) would silently bypass the tunnel and
        // leak the user's real IPv6 address. Use ::1 (loopback) as the gateway
        // so the kernel drops packets locally instead of trying to forward.
        for net6 in ["::/1", "8000::/1"] {
            if run_cmd(&["route", "-n", "add", "-inet6", "-net", net6, "::1", "-blackhole"])
                .await
                .is_ok()
            {
                janitor
                    .record_undo(vec![
                        "route".into(), "-n".into(), "delete".into(), "-inet6".into(),
                        "-net".into(), net6.into(),
                    ])
                    .await;
            } else {
                warn!("could not install IPv6 blackhole route for {net6}; v6 may leak");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = cfg;
        let (orig_gw, _) = read_default_route_windows().await?;
        run_cmd(&[
            "route", "add", &server_ip.to_string(),
            "mask", "255.255.255.255", &orig_gw, "metric", "1",
        ])
        .await
        .context("route add server bypass")?;
        janitor
            .record_undo(vec![
                "route".into(), "delete".into(), server_ip.to_string(),
            ])
            .await;

        for (net, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            run_cmd(&[
                "route", "add", net, "mask", mask, TUN_GATEWAY_IP, "metric", "1",
            ])
            .await
            .with_context(|| format!("route add {net}/{mask}"))?;
            janitor
                .record_undo(vec![
                    "route".into(), "delete".into(), net.into(),
                ])
                .await;
        }

        // Block IPv6 entirely — ArkTunnel only carries IPv4 today, so any
        // v6-capable site would otherwise bypass the tunnel and leak the
        // user's real IPv6 address.
        for net6 in ["::/1", "8000::/1"] {
            if run_cmd(&[
                "netsh", "interface", "ipv6", "add", "route",
                net6, "interface=Loopback Pseudo-Interface 1",
            ])
            .await
            .is_ok()
            {
                janitor
                    .record_undo(vec![
                        "netsh".into(), "interface".into(), "ipv6".into(),
                        "delete".into(), "route".into(), net6.into(),
                        "interface=Loopback Pseudo-Interface 1".into(),
                    ])
                    .await;
            } else {
                warn!("could not install IPv6 blackhole route for {net6}; v6 may leak");
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (cfg, server_ip, janitor);
        bail!("tun mode is not supported on this OS");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn read_default_route_linux() -> Result<(String, String)> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .await?;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    // Parse: "default via <gw> dev <dev> ..."
    let mut gw = None;
    let mut dev = None;
    let mut iter = s.split_whitespace();
    while let Some(tok) = iter.next() {
        match tok {
            "via" => gw = iter.next().map(|s| s.to_string()),
            "dev" => dev = iter.next().map(|s| s.to_string()),
            _ => {}
        }
    }
    Ok((
        gw.ok_or_else(|| anyhow!("no default gateway found via `ip route`"))?,
        dev.ok_or_else(|| anyhow!("no default device found via `ip route`"))?,
    ))
}

#[cfg(target_os = "macos")]
async fn read_default_route_macos() -> Result<(String, String)> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .await?;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let mut gw = None;
    let mut dev = None;
    for line in s.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            gw = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("interface:") {
            dev = Some(rest.trim().to_string());
        }
    }
    Ok((
        gw.ok_or_else(|| anyhow!("no default gateway found via `route get default`"))?,
        dev.ok_or_else(|| anyhow!("no default interface found via `route get default`"))?,
    ))
}

#[cfg(target_os = "macos")]
async fn read_system_dns_servers_macos() -> Result<Vec<std::net::Ipv4Addr>> {
    let out = Command::new("scutil").args(["--dns"]).output().await?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut dns = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if !line.contains("nameserver[") {
            continue;
        }
        let Some((_, rhs)) = line.split_once(':') else {
            continue;
        };
        let candidate = rhs.trim();
        if let Ok(ip) = candidate.parse::<std::net::Ipv4Addr>() {
            if !dns.contains(&ip) {
                dns.push(ip);
            }
        }
    }
    Ok(dns)
}

#[cfg(target_os = "windows")]
async fn read_default_route_windows() -> Result<(String, String)> {
    let out = Command::new("route").args(["print", "0.0.0.0"]).output().await?;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    // Find the first "0.0.0.0  0.0.0.0  <gw>  <iface>  <metric>" line.
    for line in s.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            return Ok((cols[2].to_string(), cols[3].to_string()));
        }
    }
    bail!("could not parse default route from `route print 0.0.0.0`")
}

async fn run_cmd(argv: &[impl AsRef<str>]) -> Result<()> {
    let argv: Vec<&str> = argv.iter().map(|a| a.as_ref()).collect();
    let (head, tail) = argv.split_first().expect("non-empty argv");
    let status = Command::new(head)
        .args(tail)
        .stdin(Stdio::null())
        .status()
        .await
        .with_context(|| format!("spawning {head}"))?;
    if !status.success() {
        bail!("`{}` exited with {}", argv.join(" "), status);
    }
    Ok(())
}

/// Spawn tun2socks with the agreed-upon flag set and stream its logs.
pub async fn spawn_tun2socks(cfg: &TunConfig, binary: &PathBuf) -> Result<Child> {
    let mut cmd = Command::new(binary);
    cmd.args([
        "-device", &cfg.tun_name,
        "-proxy", &format!("socks5://{}", cfg.socks5_addr),
        "-loglevel", "warning",
        "-mtu", &cfg.mtu.to_string(),
        // UDP is now tunneled (Phase 11 / v0.1.9): tun2socks will use
        // SOCKS5 UDP_ASSOCIATE against the in-process listener, which
        // wraps each datagram in ARK-frame v1 over the encrypted channel.
    ]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().with_context(|| {
        format!("failed to spawn tun2socks at {}", binary.display())
    })?;

    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!("tun2socks: {line}");
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!("tun2socks: {line}");
            }
        });
    }
    Ok(child)
}
