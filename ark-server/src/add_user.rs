use crate::config::ServerConfig;
use crate::init::{build_uri, get_local_ip};
use anyhow::Result;
use uuid::Uuid;

/// `ark-server add-user` — generate a new UUID, add it to the config, and print the URI.
///
/// The caller must restart ark-server (or SIGHUP it) for the new user to be active.
pub fn run_add_user() -> Result<()> {
    let mut cfg = ServerConfig::load()?;

    let uuid = Uuid::new_v4();
    cfg.uuids.push(uuid.to_string());

    cfg.save()?;

    let host = get_local_ip().unwrap_or_else(|| "<your-server-ip>".to_string());
    let uri = build_uri(
        &uuid,
        &host,
        cfg.port(),
        &cfg.transport,
        cfg.nodekey.as_deref(),
    );

    println!("New user added.");
    println!("UUID: {}", uuid);
    println!("URI:  {}", uri);
    println!();
    println!("Restart ark-server for the new user to take effect:");
    println!("  systemctl restart arktunnel");

    Ok(())
}
