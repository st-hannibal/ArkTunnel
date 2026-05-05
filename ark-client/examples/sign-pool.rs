// One-shot helper that emits a signed pool registry JSON to stdout.
//
//   cargo run --example sign-pool -- <signing-key-hex> <updated-iso> \
//       <host>:<port>:<transport>[:<weight>] ...
//
// Example:
//   cargo run --example sign-pool -- $(openssl rand -hex 32) \
//       2026-05-05T09:00:00Z 18.196.101.239:8333:bip324
//
// To produce a matching public key for `--pool-pubkey`, derive it from the
// signing key (the verifier prints it on the second line of stderr).

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use std::env;

#[derive(Serialize)]
struct Server {
    host: String,
    port: u16,
    weight: u32,
    transport: String,
}

#[derive(Serialize)]
struct SignedPayload<'a> {
    servers: &'a [Server],
    updated: &'a str,
    version: u32,
}

#[derive(Serialize)]
struct Doc<'a> {
    version: u32,
    updated: &'a str,
    servers: &'a [Server],
    sig: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 3 {
        bail!("usage: sign-pool <signing-key-hex64> <updated-iso> <host:port:transport[:weight]> ...");
    }
    let key_bytes_vec = hex::decode(&args[0]).context("signing key must be hex")?;
    let key_bytes: [u8; 32] = key_bytes_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signing key must be 32 bytes (got {})", key_bytes_vec.len()))?;
    let sk = SigningKey::from_bytes(&key_bytes);

    let updated = args[1].clone();
    let mut servers = Vec::new();
    for raw in &args[2..] {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() < 3 || parts.len() > 4 {
            bail!("server entry must be host:port:transport[:weight], got {raw}");
        }
        servers.push(Server {
            host: parts[0].to_string(),
            port: parts[1].parse().context("invalid port")?,
            weight: parts.get(3).map(|w| w.parse()).transpose()?.unwrap_or(1),
            transport: parts[2].to_string(),
        });
    }

    let payload = SignedPayload {
        servers: &servers,
        updated: &updated,
        version: 1,
    };
    let bytes = serde_json::to_vec(&payload)?;
    let sig = sk.sign(&bytes);

    let doc = Doc {
        version: 1,
        updated: &updated,
        servers: &servers,
        sig: hex::encode(sig.to_bytes()),
    };
    println!("{}", serde_json::to_string_pretty(&doc)?);
    eprintln!("signing pubkey (give to client as --pool-pubkey):");
    eprintln!("{}", hex::encode(sk.verifying_key().to_bytes()));
    Ok(())
}
