//! A local agent's identity and read credential, from the shipped CLI.
//!
//! Wave 9 long-context A/B: a fresh vault gave an agent no owner principal
//! and no plain Read credential. The worker derived the embedded owner id by
//! hand and ran the server with authentication off. `oneiron whoami` now
//! prints the principal and vault id, and `oneiron token read` mints a
//! `core:read` credential through the host-rooted pairing doors.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::memory::{RecallScope, WitnessTurn};
use oneiron_remote::OneironClient;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;

const SECRET: &str = "agent-credentials-issuer-key";

fn oneiron(args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(args)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "oneiron {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap_or_else(|_| serde_json::json!(stdout.trim()))
}

fn whoami(vault: &Path, config: &Path) -> serde_json::Value {
    oneiron(&[
        "whoami",
        vault.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ])
}

fn turn(content: &str) -> WitnessTurn {
    serde_json::from_value(serde_json::json!({
        "conversation_ref": "61616161616161616161616161616161",
        "messages": [{
            "author": "user", "message_type": "text", "content": content,
            "is_visible": true, "order": 0,
        }],
        "occurred_at": oneiron_remote::unix_seconds_now(),
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whoami_names_the_principal_a_write_accepts_and_token_read_only_reads() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let config_path = dir.path().join("self-host.toml");
    oneiron(&[
        "init",
        vault_path.to_str().unwrap(),
        "--config",
        config_path.to_str().unwrap(),
        "--embedder",
        "none",
    ]);
    let config = config_path.to_str().unwrap();

    let before = whoami(&vault_path, &config_path);
    let owner = before["owner_principal"].as_str().unwrap().to_owned();
    assert_eq!(owner.len(), 32, "{before}");
    assert_eq!(before["actor_class"], "human");
    assert_eq!(
        before["vault_id"],
        serde_json::Value::Null,
        "not rooted yet"
    );

    let read = oneiron(&["token", "read", "--config", config]);
    assert_eq!(read["principal_ref"], owner.as_str());
    let credential = read["credential"].as_str().unwrap().to_owned();
    let slip =
        oneiron::authority::CapabilitySlip::from_token(read["token"].as_str().unwrap()).unwrap();
    let after = whoami(&vault_path, &config_path);
    assert_eq!(after["owner_principal"], owner.as_str());
    let vault_id: String = slip
        .claims
        .vault_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(after["vault_id"], vault_id.as_str(), "the id slips carry");
    let owner_link = oneiron(&[
        "token",
        "bootstrap",
        "--config",
        config,
        "--url",
        "http://127.0.0.1:1",
    ]);
    let (_, code, holder) =
        oneiron::authority::parse_pairing_link(owner_link.as_str().unwrap()).unwrap();
    assert_eq!(holder, owner);

    let vault =
        Arc::new(oneiron::Vault::open_owned(&vault_path, oneiron::VaultConfig::server()).unwrap());
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, build_app(server)).await.unwrap();
    });
    let owner_link = oneiron::authority::format_pairing_link(&origin, &code, &holder);

    tokio::task::spawn_blocking(move || {
        // A write naming whoami's principal is accepted.
        let (url, owner_credential) = OneironClient::pair(&owner_link).unwrap();
        let writer = OneironClient::connect(&url, &owner_credential).unwrap();
        let witnessed = writer
            .witness(&turn("The nightly backup runs at 03:46."))
            .unwrap();

        // The read credential recalls it and cannot write.
        let reader = OneironClient::connect(&origin, &credential).unwrap();
        let effort = oneiron_remote::parse_effort("medium").unwrap();
        let pack = reader
            .recall(
                "nightly backup",
                effort,
                &RecallScope::default(),
                5,
                None,
                None,
            )
            .unwrap();
        assert!(
            pack.items
                .iter()
                .any(|item| Some(&item.short_id) == witnessed.message_short_ids.first()),
            "{pack:?}"
        );
        let refused = reader.witness(&turn("an agent may not write")).unwrap_err();
        assert_eq!(refused.code, "FORBIDDEN", "{refused:?}");
    })
    .await
    .unwrap();
}
