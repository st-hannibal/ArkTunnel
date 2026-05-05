use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub const CONFIG_DIR: &str = "/etc/arktunnel";
pub const CONFIG_PATH: &str = "/etc/arktunnel/server.toml";

/// Local address of bitcoind P2P (different from public port to avoid clash).
pub const BITCOIND_LOCAL_ADDR: &str = "127.0.0.1:18444";
/// Local address of geth P2P (offset from public 30303).
pub const GETH_LOCAL_ADDR: &str = "127.0.0.1:30304";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Bip324,
    Rlpx,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Bip324 => write!(f, "bip324"),
            TransportKind::Rlpx => write!(f, "rlpx"),
        }
    }
}

impl std::str::FromStr for TransportKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "bip324" => Ok(TransportKind::Bip324),
            "rlpx" => Ok(TransportKind::Rlpx),
            other => anyhow::bail!("unknown transport: '{}' (expected bip324 or rlpx)", other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub transport: TransportKind,
    /// TCP listen address, e.g. "0.0.0.0:8333".
    pub listen_addr: String,
    /// Authorized user UUIDs (string form).
    pub uuids: Vec<String>,
    /// RLPx static public key (64-byte hex, x||y). Only present for rlpx transport.
    pub nodekey: Option<String>,
    /// Local bitcoind P2P address to splice real Bitcoin peers into.
    /// `None` or empty string disables the RealPeer splice (connections
    /// from non-ARK Bitcoin peers are silently dropped). Overridden by
    /// the `ARK_BITCOIND_ADDR` env var when set. Only used for the
    /// `bip324` transport. (Phase 13 WP1.)
    #[serde(default)]
    pub bitcoind_addr: Option<String>,
    /// Localhost-only metrics endpoint address (Phase 13 WP3).
    /// `None` defaults to `127.0.0.1:9899`. Empty string disables.
    /// Overridden by `ARK_METRICS_ADDR` env var.
    #[serde(default)]
    pub metrics_addr: Option<String>,
    /// Path to bitcoin.conf for the metrics endpoint to invoke
    /// `bitcoin-cli` against. Defaults to `/etc/bitcoin/bitcoin.conf`.
    /// Overridden by `ARK_BITCOIN_CONF` env var.
    #[serde(default)]
    pub bitcoin_conf: Option<String>,
}

impl ServerConfig {
    /// Load from the default config path `/etc/arktunnel/server.toml`.
    pub fn load() -> Result<Self> {
        Self::load_from(CONFIG_PATH)
    }

    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading {}", path.as_ref().display()))?;
        toml::from_str(&text).with_context(|| "parsing server.toml")
    }

    /// Save to the default config path, creating `/etc/arktunnel/` if needed.
    pub fn save(&self) -> Result<()> {
        self.save_to(CONFIG_PATH)
    }

    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let p = path.as_ref();
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating directory {}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(p, text)
            .with_context(|| format!("writing {}", p.display()))?;
        Ok(())
    }

    /// Returns the port extracted from listen_addr.
    pub fn port(&self) -> &str {
        self.listen_addr.rsplit(':').next().unwrap_or("8333")
    }

    /// Returns the local address for the upstream crypto node, or
    /// `None` when the operator has explicitly disabled the splice
    /// (only meaningful for the `bip324` transport — RLPx always uses
    /// `GETH_LOCAL_ADDR`).
    ///
    /// Resolution order for `bip324`:
    ///   1. `ARK_BITCOIND_ADDR` env var (empty string = disabled).
    ///   2. `bitcoind_addr` config field (empty string = disabled).
    ///   3. Built-in default `BITCOIND_LOCAL_ADDR`.
    pub fn crypto_node_addr(&self) -> Option<String> {
        match self.transport {
            TransportKind::Bip324 => {
                if let Ok(env) = std::env::var("ARK_BITCOIND_ADDR") {
                    return if env.trim().is_empty() { None } else { Some(env) };
                }
                match self.bitcoind_addr.as_deref() {
                    Some("") => None,
                    Some(s) => Some(s.to_string()),
                    None => Some(BITCOIND_LOCAL_ADDR.to_string()),
                }
            }
            TransportKind::Rlpx => Some(GETH_LOCAL_ADDR.to_string()),
        }
    }

    /// Config directory as a PathBuf.
    #[allow(dead_code)]
    pub fn config_dir() -> PathBuf {
        PathBuf::from(CONFIG_DIR)
    }

    /// Resolved metrics listen address. Returns `None` if explicitly
    /// disabled (env var or config field set to an empty string).
    /// Resolution order: `ARK_METRICS_ADDR` env > `metrics_addr`
    /// config field > built-in `127.0.0.1:9899`.
    pub fn resolve_metrics_addr(&self) -> Option<String> {
        if let Ok(env) = std::env::var("ARK_METRICS_ADDR") {
            return if env.trim().is_empty() { None } else { Some(env) };
        }
        match self.metrics_addr.as_deref() {
            Some("") => None,
            Some(s) => Some(s.to_string()),
            None => Some("127.0.0.1:9899".to_string()),
        }
    }

    /// Resolved bitcoin.conf path for the metrics endpoint. Returns
    /// `None` only if explicitly disabled. `ARK_BITCOIN_CONF` env >
    /// `bitcoin_conf` field > `/etc/bitcoin/bitcoin.conf`.
    pub fn resolve_bitcoin_conf(&self) -> Option<String> {
        if let Ok(env) = std::env::var("ARK_BITCOIN_CONF") {
            return if env.trim().is_empty() { None } else { Some(env) };
        }
        match self.bitcoin_conf.as_deref() {
            Some("") => None,
            Some(s) => Some(s.to_string()),
            None => Some("/etc/bitcoin/bitcoin.conf".to_string()),
        }
    }
}
