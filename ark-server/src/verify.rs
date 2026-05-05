//! `ark-server verify` — operator readiness check. (Phase 13 WP4.)
//!
//! Runs a series of checks that an operator should be able to pass
//! before announcing a v0.3.x server as production-ready:
//!
//!   1. ark-server local config is loadable.
//!   2. The metrics endpoint is reachable on its configured address.
//!   3. bitcoind is reachable via `bitcoin-cli` and serving mainnet.
//!   4. bitcoind is fully synced (blocks == headers, IBD complete).
//!   5. bitcoind has at least 8 sustained peer connections.
//!   6. The server's public IP appears in the bitnodes.io crawler.
//!
//! Prints a green/yellow/red summary; exits non-zero if any *critical*
//! check fails. Network calls have hard timeouts so a flaky probe
//! cannot hang the operator's terminal.

use anyhow::{Context, Result};
use std::process::Command;
use std::time::Duration;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_PEERS: u64 = 8;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Ok,
    Warn,
    Fail,
}

fn label(v: &Verdict) -> &'static str {
    match v {
        Verdict::Ok => "[ OK ]",
        Verdict::Warn => "[WARN]",
        Verdict::Fail => "[FAIL]",
    }
}

fn print(v: &Verdict, name: &str, detail: &str) {
    println!("{} {} — {}", label(v), name, detail);
}

pub async fn run_verify() -> Result<()> {
    let cfg = crate::config::ServerConfig::load()
        .context("loading /etc/arktunnel/server.toml — has `ark-server init` been run?")?;
    print(&Verdict::Ok, "config", "loaded /etc/arktunnel/server.toml");

    let mut critical_failures = 0usize;

    // --- Metrics endpoint ---------------------------------------------------
    let metrics_addr = cfg.resolve_metrics_addr();
    match metrics_addr {
        Some(addr_s) => match check_metrics(&addr_s).await {
            Ok(()) => print(&Verdict::Ok, "metrics", &format!("http://{addr_s}/metrics responding")),
            Err(e) => {
                print(&Verdict::Warn, "metrics", &format!("{addr_s}: {e}"));
            }
        },
        None => print(&Verdict::Warn, "metrics", "endpoint disabled in config"),
    }

    // --- bitcoind ----------------------------------------------------------
    let conf = cfg
        .resolve_bitcoin_conf()
        .unwrap_or_else(|| "/etc/bitcoin/bitcoin.conf".to_string());

    match bitcoin_cli(&conf, &["getblockchaininfo"]).await {
        Ok(json) => {
            // Cheap parse without serde_json: look for "chain" and
            // headers/blocks numbers. We have no JSON dep here.
            let chain = field_str(&json, "chain").unwrap_or_default();
            let blocks = field_u64(&json, "blocks").unwrap_or(0);
            let headers = field_u64(&json, "headers").unwrap_or(0);
            let ibd = field_bool(&json, "initialblockdownload").unwrap_or(true);

            if chain == "main" {
                print(&Verdict::Ok, "bitcoind:network", "chain=main");
            } else {
                print(&Verdict::Fail, "bitcoind:network", &format!("chain={chain} (expected 'main')"));
                critical_failures += 1;
            }

            if !ibd && blocks > 0 && blocks >= headers.saturating_sub(2) {
                print(&Verdict::Ok, "bitcoind:sync", &format!("blocks={blocks} headers={headers} ibd=false"));
            } else {
                print(
                    &Verdict::Fail,
                    "bitcoind:sync",
                    &format!("blocks={blocks} headers={headers} ibd={ibd} — IBD not complete yet"),
                );
                critical_failures += 1;
            }
        }
        Err(e) => {
            print(&Verdict::Fail, "bitcoind:network", &format!("bitcoin-cli failed: {e}"));
            critical_failures += 1;
        }
    }

    match bitcoin_cli(&conf, &["getconnectioncount"]).await {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(n) if n >= MIN_PEERS => {
                print(&Verdict::Ok, "bitcoind:peers", &format!("{n} peers (>= {MIN_PEERS})"));
            }
            Ok(n) => {
                print(&Verdict::Warn, "bitcoind:peers", &format!("{n} peers (< {MIN_PEERS}); allow more time"));
            }
            Err(_) => print(&Verdict::Warn, "bitcoind:peers", "could not parse peer count"),
        },
        Err(e) => print(&Verdict::Warn, "bitcoind:peers", &format!("{e}")),
    }

    // --- bitnodes.io reachability -----------------------------------------
    match check_bitnodes().await {
        Ok((ip, listed)) => {
            if listed {
                print(&Verdict::Ok, "bitnodes.io", &format!("{ip} appears in the crawler"));
            } else {
                print(
                    &Verdict::Warn,
                    "bitnodes.io",
                    &format!("{ip} not listed yet (crawler refreshes ~24h)"),
                );
            }
        }
        Err(e) => print(&Verdict::Warn, "bitnodes.io", &format!("skipped: {e}")),
    }

    println!();
    if critical_failures == 0 {
        println!("verify: PASS (no critical failures)");
        Ok(())
    } else {
        anyhow::bail!("verify: {} critical failure(s)", critical_failures);
    }
}

async fn check_metrics(addr: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let connect = TcpStream::connect(addr);
    let mut s = tokio::time::timeout(HTTP_TIMEOUT, connect)
        .await
        .context("connect timed out")??;
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await?;
    let mut buf = Vec::new();
    let read = s.read_to_end(&mut buf);
    tokio::time::timeout(HTTP_TIMEOUT, read)
        .await
        .context("read timed out")??;
    let head = std::str::from_utf8(&buf[..buf.len().min(64)]).unwrap_or("");
    if !head.starts_with("HTTP/1.1 200") {
        anyhow::bail!("non-200 response: {}", head.lines().next().unwrap_or("<empty>"));
    }
    Ok(())
}

async fn bitcoin_cli(conf: &str, args: &[&str]) -> Result<String> {
    let conf = conf.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("bitcoin-cli")
            .arg(format!("-conf={conf}"))
            .args(&args)
            .output()
    })
    .await?
    .context("spawning bitcoin-cli")?;
    if !out.status.success() {
        anyhow::bail!(
            "bitcoin-cli exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn check_bitnodes() -> Result<(String, bool)> {
    // Get our public IP first.
    let ip = http_get("https://api.ipify.org").await
        .context("api.ipify.org")?;
    let ip = ip.trim().to_string();
    if ip.is_empty() {
        anyhow::bail!("could not detect public IP");
    }
    let url = format!("https://bitnodes.io/api/v1/nodes/{ip}-8333/");
    match http_get(&url).await {
        Ok(body) => Ok((ip, body.contains("\"address\""))),
        // 404 = not listed (yet); treat as "not listed", not as an error.
        Err(_) => Ok((ip, false)),
    }
}

async fn http_get(url: &str) -> Result<String> {
    // Use the `curl` binary to avoid pulling reqwest into ark-server.
    let url = url.to_string();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("curl")
            .args(["-fsSL", "--max-time", "10"])
            .arg(&url)
            .output()
    })
    .await?
    .context("spawning curl")?;
    if !out.status.success() {
        anyhow::bail!("curl exited {}", out.status);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// --- tiny JSON-ish field grabbers (no serde_json dep) ---------------------

fn after_key<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\"");
    let i = json.find(&pat)? + pat.len();
    let rest = json[i..].trim_start();
    let rest = rest.strip_prefix(':')?;
    Some(rest.trim_start())
}

fn field_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let rest = after_key(json, key)?;
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn field_u64(json: &str, key: &str) -> Option<u64> {
    let rest = after_key(json, key)?;
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn field_bool(json: &str, key: &str) -> Option<bool> {
    let rest = after_key(json, key)?;
    if rest.starts_with("true") { Some(true) }
    else if rest.starts_with("false") { Some(false) }
    else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_string_field() {
        let j = r#"{"chain":"main","blocks":12345,"initialblockdownload":false}"#;
        assert_eq!(field_str(j, "chain"), Some("main"));
        assert_eq!(field_u64(j, "blocks"), Some(12345));
        assert_eq!(field_bool(j, "initialblockdownload"), Some(false));
    }

    #[test]
    fn parse_with_whitespace() {
        let j = r#"{ "chain" :  "test" , "headers" :  890 , "ibd" :  true }"#;
        assert_eq!(field_str(j, "chain"), Some("test"));
        assert_eq!(field_u64(j, "headers"), Some(890));
        assert_eq!(field_bool(j, "ibd"), Some(true));
    }

    #[test]
    fn missing_field_returns_none() {
        let j = r#"{"chain":"main"}"#;
        assert!(field_u64(j, "blocks").is_none());
        assert!(field_bool(j, "ibd").is_none());
    }
}
