mod http_proxy;
mod pool;
mod proxy;
mod socks5;
mod uri;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;

const DEFAULT_SOCKS5_ADDR: &str = "127.0.0.1:1080";
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:8118";

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
    },
    /// Test connectivity to the server. Exits 0 on success, 1 on failure.
    Test {
        /// arktunnel:// URI to test.
        #[arg(long, short)]
        uri: String,
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
        Commands::Run { uri, socks5, http } => {
            let ark_uri = Arc::new(uri::ArkUri::parse(&uri)?);
            run_proxy(ark_uri, socks5, http).await?;
        }
        Commands::Test { uri } => {
            let ark_uri = uri::ArkUri::parse(&uri)?;
            test_connectivity(ark_uri).await;
        }
    }

    Ok(())
}

async fn run_proxy(uri: Arc<uri::ArkUri>, socks5_addr: String, http_addr: String) -> Result<()> {
    println!("ArkTunnel client");
    println!("  Transport   : {}", uri.transport);
    println!("  Server      : {}:{}", uri.host, uri.port);
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

    println!("Testing connectivity to {}:{}…", uri.host, uri.port);
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
