use crate::config::{ServerConfig, TransportKind, CONFIG_PATH};
use crate::singbox::write_singbox_config;
use anyhow::{bail, Result};
use ark_core::rlpx;
use uuid::Uuid;

/// `ark-server init` — generate a new server config, write it to disk, and print the URI.
pub async fn run_init(transport: TransportKind, server_ip: Option<String>) -> Result<()> {
    // Refuse to overwrite an existing config without an explicit flag.
    if std::path::Path::new(CONFIG_PATH).exists() {
        bail!(
            "Config already exists at {}.\n\
             To re-initialize, delete the file first:\n\
             sudo rm {}",
            CONFIG_PATH,
            CONFIG_PATH
        );
    }

    let uuid = Uuid::new_v4();

    let (listen_addr, nodekey) = match &transport {
        TransportKind::Bip324 => ("0.0.0.0:8333".to_string(), None),
        TransportKind::Rlpx => {
            let pub_bytes = rlpx::server_pub_bytes();
            let hex_key = hex_encode(&pub_bytes);
            ("0.0.0.0:30303".to_string(), Some(hex_key))
        }
    };

    let cfg = ServerConfig {
        transport: transport.clone(),
        listen_addr: listen_addr.clone(),
        uuids: vec![uuid.to_string()],
        singbox_api: "127.0.0.1:9090".to_string(),
        nodekey: nodekey.clone(),
    };

    cfg.save()?;
    write_singbox_config(&cfg)?;

    // Determine the host to embed in the URI.
    let host = server_ip
        .unwrap_or_else(|| get_local_ip().unwrap_or_else(|| "<your-server-ip>".to_string()));

    let uri = build_uri(&uuid, &host, cfg.port(), &transport, nodekey.as_deref());

    println!("=== ArkTunnel Server Initialized ===");
    println!("Config:    {}", CONFIG_PATH);
    println!("Transport: {}", transport);
    println!("UUID:      {}", uuid);
    println!();
    println!("URI (share this with your users):");
    println!("  {}", uri);
    println!();
    println!("Start the server:");
    println!("  ark-server run");
    println!();
    println!("Add more users:");
    println!("  ark-server add-user");

    Ok(())
}

/// Build an `arktunnel://` URI.
pub fn build_uri(
    uuid: &Uuid,
    host: &str,
    port: &str,
    transport: &TransportKind,
    nodekey: Option<&str>,
) -> String {
    let mut uri = format!(
        "arktunnel://{}@{}:{}?transport={}",
        uuid, host, port, transport
    );
    if let Some(key) = nodekey {
        uri.push_str("&nodekey=");
        uri.push_str(key);
    }
    uri
}

/// Best-effort local IP detection via UDP routing table trick.
/// Works on typical Linux VPSes where the public IP is the primary NIC address.
pub fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
