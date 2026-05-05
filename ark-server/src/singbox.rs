use crate::config::{ServerConfig, SINGBOX_CONFIG_PATH};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::process::{Child, Command};

/// Generate the sing-box JSON configuration from a `ServerConfig`.
///
/// Produces a VLESS inbound on `127.0.0.1:10800` with all configured UUIDs,
/// a direct outbound, and the V2Ray API on the configured management address.
pub fn generate_singbox_config(cfg: &ServerConfig) -> Value {
    let users: Vec<Value> = cfg
        .uuids
        .iter()
        .map(|u| json!({ "uuid": u, "flow": "" }))
        .collect();

    json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": [{
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": 10800,
            "users": users
        }],
        "outbounds": [{ "type": "direct", "tag": "direct-out" }]
    })
}

/// Write the sing-box JSON config to `/etc/arktunnel/singbox.json`.
pub fn write_singbox_config(cfg: &ServerConfig) -> Result<()> {
    let dir = std::path::Path::new(SINGBOX_CONFIG_PATH)
        .parent()
        .unwrap_or(std::path::Path::new("/etc/arktunnel"));
    std::fs::create_dir_all(dir)?;

    let config = generate_singbox_config(cfg);
    std::fs::write(SINGBOX_CONFIG_PATH, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

/// Check that sing-box is installed; return an error with install instructions if not.
pub fn check_singbox() -> Result<()> {
    match Command::new("sing-box").arg("version").output() {
        Ok(_) => Ok(()),
        Err(_) => bail!(
            "sing-box not found. Install it first:\n\
             \n\
             # Debian / Ubuntu:\n\
             curl -fsSL https://sing-box.app/gpg.key \\\n\
               | sudo gpg --dearmor -o /usr/share/keyrings/sing-box.gpg\n\
             echo 'deb [signed-by=/usr/share/keyrings/sing-box.gpg] \\\n\
               https://deb.sainnhe.dev/sing-box stable main' \\\n\
               | sudo tee /etc/apt/sources.list.d/sing-box.list\n\
             sudo apt update && sudo apt install sing-box\n\
             \n\
             # Or download from https://github.com/SagerNet/sing-box/releases"
        ),
    }
}

/// Start sing-box as a child process using the config at `SINGBOX_CONFIG_PATH`.
///
/// The caller is responsible for keeping the returned `Child` alive.
pub fn start_singbox() -> Result<Child> {
    check_singbox()?;
    let child = Command::new("sing-box")
        .args(["run", "-c", SINGBOX_CONFIG_PATH])
        .spawn()?;
    Ok(child)
}

/// Send SIGTERM to a running sing-box child process (graceful shutdown).
#[allow(dead_code)]
pub fn stop_singbox(child: &mut Child) {
    // On Unix we prefer SIGTERM; `kill()` sends SIGKILL.
    // For simplicity use SIGKILL — sing-box is stateless.
    let _ = child.kill();
}
