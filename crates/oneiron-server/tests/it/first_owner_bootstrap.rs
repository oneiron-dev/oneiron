//! Fresh self-host pairing through the shipped offline command and HTTP door.
use std::process::Command;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, pairing_binding_transcript, parse_pairing_link};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use tower::ServiceExt;

const SECRET: &str = "only-the-offline-issuer-key-not-a-bearer";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn init_bootstrap_redeem_and_protected_read_need_no_preexisting_slip() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let config_path = dir.path().join("self-host.toml");
    let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args([
            "init",
            vault_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "--embedder",
            "none",
        ])
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let unsafe_origin = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args([
            "token",
            "bootstrap",
            "--config",
            config_path.to_str().unwrap(),
            "--url",
            "http://example.com",
        ])
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .output()
        .unwrap();
    assert!(
        !unsafe_origin.status.success(),
        "plaintext public pairing link must be refused"
    );
    let bootstrap = Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args([
            "token",
            "bootstrap",
            "--config",
            config_path.to_str().unwrap(),
            "--url",
            "http://127.0.0.1:3000",
            "--lifetime-secs",
            "600",
        ])
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .output()
        .unwrap();
    assert!(
        bootstrap.status.success(),
        "bootstrap: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let stdout = String::from_utf8(bootstrap.stdout).unwrap();
    let (origin, code, owner) = parse_pairing_link(stdout.trim()).unwrap();
    assert_eq!(origin, "http://127.0.0.1:3000");
    assert!(!stdout.contains(SECRET));
    let vault =
        Arc::new(oneiron::Vault::open_owned(&vault_path, oneiron::VaultConfig::server()).unwrap());
    assert!(
        vault
            .get(&oneiron::EntityId::from_hex(&owner).unwrap())
            .unwrap()
            .is_some()
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server.clone());
    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/core/discover")
                .header("authorization", format!("Bearer {SECRET}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let holder = SigningKey::from_bytes(&[52; 32]);
    let pubkey = holder.verifying_key().to_bytes();
    let signature = holder.sign(&pairing_binding_transcript(&code, &pubkey, &owner).unwrap());
    let payload = serde_json::json!({
        "code":code,"holder_ref":owner,"binding_key":hex(&pubkey),"signature":hex(&signature.to_bytes())
    });
    let redeem = || {
        Request::builder()
            .method("POST")
            .uri("/v1/core/pairing/redeem")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    };
    let response = app.clone().oneshot(redeem()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let paired: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = paired["token"].as_str().unwrap();
    let slip = CapabilitySlip::from_token(token).unwrap();
    assert_eq!(slip.claims.holder_ref, owner);
    assert_eq!(slip.claims.ttl_secs, 600);
    assert_eq!(
        app.clone().oneshot(redeem()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let timestamp = server.vault().now_recorded_at();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let proof = holder.sign(&slip.binding_transcript(challenge.as_bytes()).unwrap());
    let binding =
        serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":hex(&proof.to_bytes())});
    let read = app
        .oneshot(
            Request::builder()
                .uri("/api/core/discover")
                .header("authorization", format!("Bearer {token}"))
                .header("x-oneiron-binding", binding.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
}
