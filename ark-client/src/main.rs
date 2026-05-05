mod endpoints;
mod http_proxy;
mod pool;
mod pool_registry;
mod proxy;
mod socks5;
mod tun;
mod uri;

use anyhow::Result;
use ark_core::shaping::Shape;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_SOCKS5_ADDR: &str = "127.0.0.1:1080";
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:8118";

#[cfg(target_os = "macos")]
const DEFAULT_TUN_NAME: &str = "utun8";
#[cfg(target_os = "linux")]
const DEFAULT_TUN_NAME: &str = "tun8";
#[cfg(target_os = "windows")]
const DEFAULT_TUN_NAME: &str = "wintun";
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const DEFAULT_TUN_NAME: &str = "tun8";

#[derive(Parser)]
#[command(
    name = "ark-client",
    about = "ArkTunnel client — SOCKS5/HTTP-CONNECT proxy bridge to an ark-server",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the local SOCKS5 + HTTP CONNECT proxy.
    Run {
        /// arktunnel:// URI provided by the server operator.
        #[arg(long, short)]
        uri: String,
        /// SOCKS5 listen address.
        #[arg(long, default_value = DEFAULT_SOCKS5_ADDR)]
        socks5: String,
        /// HTTP CONNECT listen address.
        #[arg(long, default_value = DEFAULT_HTTP_ADDR)]
        http: String,
        /// Optional URL of a signed JSON pool registry (Phase 12 / WP3).
        /// When set, the verified server list replaces the URI's endpoints.
        #[arg(long)]
        pool_url: Option<String>,
        /// Hex-encoded 32-byte Ed25519 public key used to verify the pool
        /// registry signature. Required together with --pool-url.
        #[arg(long)]
        pool_pubkey: Option<String>,
        /// Traffic shaping policy (Phase 12 / WP4): `off`|`light`|`heavy`.
        /// `off` ships no padding or cover packets and is wire-compatible
        /// with v0.1.x servers. `light`/`heavy` activate length quantization
        /// plus Poisson cover frames once the v2 capability bits are
        /// negotiated (WP5).
        #[arg(long, default_value = "off")]
        shape: String,
    },
    /// Test connectivity to the server. Exits 0 on success, 1 on failure.
    Test {
        /// arktunnel:// URI to test.
        #[arg(long, short)]
        uri: String,
        #[arg(long)]
        pool_url: Option<String>,
        #[arg(long)]
        pool_pubkey: Option<String>,
        #[arg(long, default_value = "off")]
        shape: String,
    },
    /// Full-device mode: spawn tun2socks and route the system through ArkTunnel.
    /// Requires sudo (Linux/macOS) or Administrator (Windows).
    Tun {
        /// arktunnel:// URI provided by the server operator.
        #[arg(long, short)]
        uri: String,
        /// SOCKS5 listen address used as the tun2socks upstream.
        #[arg(long, default_value = DEFAULT_SOCKS5_ADDR)]
        socks5: String,
        /// TUN/utun/Wintun device name.
        #[arg(long, default_value = DEFAULT_TUN_NAME)]
        tun_name: String,
        /// MTU for the TUN device.
        #[arg(long, default_value_t = 1500)]
        mtu: u16,
        /// Optional override for the tun2socks binary path.
        #[arg(long)]
        tun2socks: Option<PathBuf>,
        #[arg(long)]
        pool_url: Option<String>,
        #[arg(long)]
        pool_pubkey: Option<String>,
        #[arg(long, default_value = "off")]
        shape: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { uri, socks5, http, pool_url, pool_pubkey, shape } => {
            let shape: Shape = shape.parse().map_err(anyhow::Error::msg)?;
            let mut ark_uri = uri::ArkUri::parse(&uri)?;
            apply_pool(&mut ark_uri, pool_url.as_deref(), pool_pubkey.as_deref()).await?;
            log_shape(shape);
            run_proxy(Arc::new(ark_uri), socks5, http).await?;
        }
        Commands::Test { uri, pool_url, pool_pubkey, shape } => {
            let shape: Shape = shape.parse().map_err(anyhow::Error::msg)?;
            let mut ark_uri = uri::ArkUri::parse(&uri)?;
            apply_pool(&mut ark_uri, pool_url.as_deref(), pool_pubkey.as_deref()).await?;
            log_shape(shape);
            test_connectivity(ark_uri).await;
        }
        Commands::Tun { uri, socks5, tun_name, mtu, tun2socks, pool_url, pool_pubkey, shape } => {
            let shape: Shape = shape.parse().map_err(anyhow::Error::msg)?;
            let mut ark_uri = uri::ArkUri::parse(&uri)?;
            apply_pool(&mut ark_uri, pool_url.as_deref(), pool_pubkey.as_deref()).await?;
            log_shape(shape);
            run_tun(Arc::new(ark_uri), socks5, tun_name, mtu, tun2socks).await?;
        }
    }

    Ok(())
}

/// Log the configured traffic-shaping policy. Until WP5 negotiates the
/// v2 capability bits, anything other than `off` is recorded but not
/// emitted on the wire (the wiring lands in WP5).
fn log_shape(shape: Shape) {
    proxy::set_shape(shape);
    match shape {
        Shape::Off => tracing::info!(shape = %shape, "traffic shaping disabled"),
        _ => tracing::info!(
            shape = %shape,
            "traffic shaping requested; capabilities will be negotiated with the server"
        ),
    }
}

/// If `--pool-url` is provided, fetch and verify the signed pool registry,
/// then replace `uri.endpoints` with the verified list (filtered by
/// transport). The URI's UUID and transport are preserved.
async fn apply_pool(
    uri: &mut uri::ArkUri,
    pool_url: Option<&str>,
    pool_pubkey: Option<&str>,
) -> Result<()> {
    let Some(url) = pool_url else { return Ok(()) };
    let pubkey = pool_pubkey.ok_or_else(|| {
        anyhow::anyhow!("--pool-url requires --pool-pubkey (32-byte hex Ed25519 key)")
    })?;
    let doc = pool_registry::load(url, pubkey).await?;
    let new_eps = pool_registry::doc_to_endpoints(&doc, &uri.transport);
    if new_eps.is_empty() {
        anyhow::bail!(
            "pool registry contains no servers matching transport={}",
            uri.transport
        );
    }
    tracing::info!(
        servers = new_eps.len(),
        "applied pool registry; replacing URI endpoint list"
    );
    uri.endpoints = new_eps;
    Ok(())
}

async fn run_tun(
    uri: Arc<uri::ArkUri>,
    socks5_addr: String,
    tun_name: String,
    mtu: u16,
    tun2socks_override: Option<PathBuf>,
) -> Result<()> {
    use tracing::{error, info};

    tun::require_privileges()?;
    let binary = tun::locate_tun2socks(tun2socks_override.as_ref())?;
    let server_ip = tun::resolve_server_ip(&uri).await?;

    println!("ArkTunnel client (TUN mode)");
    println!("  Transport   : {}", uri.transport);
    println!("  Server      : {}:{} ({server_ip})", uri.host(), uri.port());
    println!("  UUID        : {}", uri.uuid);
    println!("  SOCKS5      : {socks5_addr}");
    println!("  TUN device  : {tun_name}");
    println!("  tun2socks   : {}", binary.display());

    // 1. Start in-process SOCKS5 (the upstream that tun2socks will dial).
    let pool = pool::Pool::new(uri.clone());
    let socks5_addr_clone = socks5_addr.clone();
    let pool_s = pool.clone();
    let uri_for_socks5 = uri.clone();
    let socks5_task = tokio::spawn(async move {
        if let Err(e) = socks5::run_socks5_server(&socks5_addr_clone, uri_for_socks5, pool_s).await {
            error!("SOCKS5 server error: {e}");
        }
    });

    // Give the SOCKS5 listener a beat to bind before tun2socks dials it.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let cfg = tun::TunConfig {
        uri: uri.clone(),
        socks5_addr,
        tun_name,
        mtu,
        tun2socks_override,
    };

    // 2. Spawn tun2socks (it creates the device on macOS/Windows; on Linux
    //    we add the addr/up below).
    let mut child = tun::spawn_tun2socks(&cfg, &binary).await?;

    // Give tun2socks a moment to create the device on macOS / Windows.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 3. Install routes.
    let janitor = tun::RouteJanitor::new();
    if let Err(e) = tun::install_routes(&cfg, server_ip, &janitor).await {
        error!("failed to install routes: {e}");
        let _ = child.kill().await;
        janitor.run_all().await;
        return Err(e);
    }
    info!("routes installed; system traffic now flows through ArkTunnel");

    // 4. Wait for either Ctrl-C or tun2socks to exit, then clean up.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received, shutting down");
        }
        status = child.wait() => {
            warn!("tun2socks exited unexpectedly: {:?}", status);
        }
        _ = socks5_task => {
            warn!("SOCKS5 task exited unexpectedly");
        }
    }

    let _ = child.start_kill();
    janitor.run_all().await;
    info!("shutdown complete; routes restored");
    Ok(())
}

use tracing::warn;

async fn run_proxy(uri: Arc<uri::ArkUri>, socks5_addr: String, http_addr: String) -> Result<()> {
    println!("ArkTunnel client");
    println!("  Transport   : {}", uri.transport);
    println!("  Server      : {}:{}", uri.host(), uri.port());
    println!("  UUID        : {}", uri.uuid);
    println!("  SOCKS5      : {socks5_addr}");
    println!("  HTTP CONNECT: {http_addr}");

    // Pre-warm a pool of transport connections so first requests don't pay
    // the full handshake RTT.  The pool runs a background filler for the
    // lifetime of the process.
    let pool = pool::Pool::new(uri.clone());

    let pool_s = pool.clone();
    let uri_for_socks5 = uri.clone();
    let socks5_task = tokio::spawn(async move {
        if let Err(e) = socks5::run_socks5_server(&socks5_addr, uri_for_socks5, pool_s).await {
            tracing::error!("SOCKS5 server error: {e}");
        }
    });

    let pool_h = pool.clone();
    let http_task = tokio::spawn(async move {
        if let Err(e) = http_proxy::run_http_proxy(&http_addr, uri, pool_h).await {
            tracing::error!("HTTP proxy server error: {e}");
        }
    });

    // Run until either server exits unexpectedly.
    tokio::select! {
        _ = socks5_task => {},
        _ = http_task => {},
    }

    Ok(())
}

async fn test_connectivity(uri: uri::ArkUri) {
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    println!("Testing connectivity to {}:{}…", uri.host(), uri.port());
    let start = Instant::now();

    // Use example.com:80 as a well-known reachable test target.
    let target = proxy::Target::Domain("example.com".to_string(), 80);
    let mut stream = match proxy::open_proxied_stream(&uri, &target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FAIL  connection error: {e}");
            std::process::exit(1);
        }
    };

    // Send a minimal HEAD request.
    if let Err(e) = stream
        .write_all(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await
    {
        eprintln!("FAIL  write error: {e}");
        std::process::exit(1);
    }
    let _ = stream.flush().await;

    // Read at least the first few bytes of the response.
    let mut buf = vec![0u8; 16];
    match stream.read(&mut buf).await {
        Ok(0) => {
            eprintln!("FAIL  server closed connection before sending data");
            std::process::exit(1);
        }
        Ok(_) => {
            let elapsed = start.elapsed();
            println!("OK    {:.0}ms", elapsed.as_millis());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("FAIL  read error: {e}");
            std::process::exit(1);
        }
    }
}
