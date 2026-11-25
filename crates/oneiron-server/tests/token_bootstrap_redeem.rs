//! `oneiron token bootstrap --redeem` (R6 B7; Engine ANSWER R6-OWNER-CREDENTIAL = A, 25 Nov 23:35).
//!
//! On a stopped self-hosted vault, the first owner's link is redeemed in this process with a fresh
//! connection key. The command prints the owner's own credential in `token read`'s form, and
//! never the link or the issuer key. The slip is the owner's full one: it answers an owner act,
//! the revoke of a slip at `/v1/core/slips/revoke`, which a `token read` slip of the same owner
//! may not do. A managed config is refused before anything opens.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! cargo test --locked -p oneiron-server --all-features --test token_bootstrap_redeem
//! ```
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::CapabilitySlip;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "only-the-offline-issuer-key-not-a-bearer";
const ORIGIN: &str = "http://127.0.0.1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("lower hex"))
        .collect()
}

/// The shipped `oneiron` binary with `args`, holding the issuer key in its environment only.
fn oneiron(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(args)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .output()
        .expect("run the oneiron binary")
}

fn succeeded(what: &str, output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf-8 stdout");
    assert!(
        !stdout.contains(SECRET),
        "{what} never prints the issuer key"
    );
    serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{what} prints JSON: {error}"))
}

/// A self-hosted vault and its config, made by the shipped `init`.
fn init(dir: &Path) -> (String, String) {
    let vault = dir.join("vault").display().to_string();
    let config = dir.join("self-host.toml").display().to_string();
    let output = oneiron(&["init", &vault, "--config", &config, "--embedder", "none"]);
    assert!(
        output.status.success(),
        "init: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (vault, config)
}

/// The holder proof of one request for the slip `token`, whose connection key's seed is `seed`.
fn binding(server: &SyncServer, token: &str, seed: &str) -> String {
    let seed: [u8; 32] = unhex(seed).try_into().expect("a 32-byte seed");
    let holder = SigningKey::from_bytes(&seed);
    let slip = CapabilitySlip::from_token(token).expect("a slip token");
    let timestamp = server.vault().now_recorded_at();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let proof = holder.sign(
        &slip
            .binding_transcript(challenge.as_bytes())
            .expect("the binding transcript"),
    );
    json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&proof.to_bytes())}).to_string()
}

/// `credential` revokes the slip `slip_id` (64 hex) through the owner act at
/// `/v1/core/slips/revoke`: the answer's status.
async fn revoke(
    app: &axum::Router,
    server: &SyncServer,
    credential: &Value,
    slip_id: &str,
) -> StatusCode {
    let token = credential["token"].as_str().expect("a token");
    let seed = credential["binding_key"].as_str().expect("a binding key");
    let body = json!({ "slip_id": unhex(slip_id) });
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/core/slips/revoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-oneiron-binding", binding(server, token, seed))
                .body(Body::from(body.to_string()))
                .expect("the request"),
        )
        .await
        .expect("the answer")
        .status()
}

#[tokio::test]
async fn bootstrap_redeem_prints_the_owners_own_credential_which_answers_an_owner_act() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (vault_path, config) = init(dir.path());

    let output = oneiron(&[
        "token",
        "bootstrap",
        "--config",
        &config,
        "--url",
        ORIGIN,
        "--lifetime-secs",
        "600",
        "--redeem",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let owner = succeeded("token bootstrap --redeem", &output);
    assert!(
        !stdout.contains(ORIGIN),
        "the link is redeemed here and never printed"
    );
    let principal = owner["principal_ref"].as_str().expect("the owner's id");
    assert_eq!(owner["actor_class"], "human");
    let token = owner["token"].as_str().expect("a token");
    assert!(token.starts_with("v2.slip."), "{token}");
    let slip = CapabilitySlip::from_token(token).expect("a slip token");
    assert_eq!(slip.claims.holder_ref, principal, "the slip is the owner's");
    assert_eq!(slip.claims.ttl_secs, 600, "the lifetime the owner named");
    assert_eq!(
        owner["slip_id"].as_str(),
        Some(hex(&slip.claims.slip_id).as_str())
    );

    // The same owner's read-only credential, minted on the stopped vault beside it.
    let read = succeeded(
        "token read",
        &oneiron(&["token", "read", "--config", &config]),
    );
    assert_eq!(read["principal_ref"].as_str(), Some(principal));
    let read_slip = read["slip_id"].as_str().expect("the read slip's id");
    let owner_slip = owner["slip_id"].as_str().expect("the owner slip's id");

    let vault = Arc::new(
        oneiron::Vault::open_owned(Path::new(&vault_path), oneiron::VaultConfig::server())
            .expect("the stopped vault opens"),
    );
    // `token bootstrap` rooted the vault with this install's host issuer seed: install the same
    // keystore `oneiron serve` installs, so the in-process server loads that issuer.
    oneiron_server::config::KeystoreConfig::default().install_on(&vault, Path::new(&vault_path));
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .expect("the server"),
    );
    let app = build_app(server.clone());

    let refused = revoke(&app, &server, &read, owner_slip).await;
    assert!(
        refused.is_client_error(),
        "a core:read slip is no owner act's credential: {refused}"
    );
    assert_eq!(
        revoke(&app, &server, &owner, read_slip).await,
        StatusCode::OK,
        "the redeemed owner slip revokes a slip: an owner act"
    );
}

#[test]
fn bootstrap_redeem_refuses_a_managed_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (_vault, config) = init(dir.path());
    let output = oneiron(&[
        "token",
        "bootstrap",
        "--config",
        &config,
        "--url",
        ORIGIN,
        "--managed-by-hypnos",
        "--redeem",
    ]);
    assert!(!output.status.success(), "a managed vault is refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("managed vaults pair through their supervisor"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "nothing is printed");
}
