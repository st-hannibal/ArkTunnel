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

    /// Returns the local address for the upstream crypto node.
    pub fn crypto_node_addr(&self) -> &'static str {
        match self.transport {
            TransportKind::Bip324 => BITCOIND_LOCAL_ADDR,
            TransportKind::Rlpx => GETH_LOCAL_ADDR,
        }
    }

    /// Config directory as a PathBuf.
    #[allow(dead_code)]
    pub fn config_dir() -> PathBuf {
        PathBuf::from(CONFIG_DIR)
    }
}
