//! Record one answer from each default Roughtime server, as test fixtures.
//!
//! ```sh
//! cargo run -p pubky-switch --example roughtime_record -- crates/pubky-switch/tests/fixtures/roughtime
//! ```
//!
//! Each file holds the server, the nonce, the request and the answer, in hex. The tests
//! replay them, so they never reach a live server. Run this only to refresh the fixtures.

use std::{path::PathBuf, process::ExitCode, time::Duration};

use pubky_switch::time::roughtime::{
    Exchange, RoughtimeConfig, UdpExchange, build_request, verify_response,
};

#[tokio::main]
async fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: roughtime_record <fixture directory>");
        return ExitCode::FAILURE;
    };
    let mut failed = false;
    for server in RoughtimeConfig::default().servers {
        match record(&server, &dir).await {
            Ok(path) => println!("{}: {}", server.name, path.display()),
            Err(error) => {
                eprintln!("{}: {error}", server.name);
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn record(
    server: &pubky_switch::time::roughtime::RoughtimeServerConfig,
    dir: &std::path::Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    use base64::Engine;
    let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&server.public_key)?
        .try_into()
        .map_err(|_| "public key length")?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| "randomness")?;
    let request = build_request(nonce, &key)?;
    let response = UdpExchange
        .exchange(&server.address, &request, Duration::from_secs(3))
        .await?;
    let interval = verify_response(&key, &nonce, &request, &response)?;
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let fixture = serde_json::json!({
        "name": server.name,
        "address": server.address,
        "public_key": server.public_key,
        "recorded_at_ms": recorded_at_ms,
        "earliest_ms": interval.earliest_ms,
        "latest_ms": interval.latest_ms,
        "nonce": hex::encode(nonce),
        "request": hex::encode(&request),
        "response": hex::encode(&response),
    });
    let path = dir.join(format!("{}.json", server.name));
    std::fs::write(&path, serde_json::to_string_pretty(&fixture)? + "\n")?;
    Ok(path)
}
