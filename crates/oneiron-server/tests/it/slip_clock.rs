//! An agent's holder proof is judged on wall time, not on time the vault was
//! seen running (perf pass, 2026-10-11). The proof window used to read the
//! authority clock, which counts neither the time a vault was stopped nor the
//! gaps between short `token agent` processes. So a stop of more than 60 s,
//! or about 200 mints in a row, left every agent's proof refused with 401.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, holder_proof, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::ports::ManualClock;
use oneiron_remote::unix_seconds_now;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::Value;
use tower::ServiceExt;

use super::reopen_after_restart::{oneiron, serve, sigterm, stdout};

const SECRET: &str = "slip-clock-issuer-key-not-a-bearer";

/// `oneiron serve` stopped for longer than the window: the same agent's next
/// proof is accepted. The shipped binary has no clock to inject, so the stop
/// is a real one.
#[test]
fn the_shipped_server_accepts_an_agents_proof_after_a_stop_longer_than_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let minted: Value = serde_json::from_str(&stdout(oneiron(
        &["token", "agent", "--name", "clock-check"],
        &config,
    )))
    .expect("token agent prints its credential as JSON");
    let token = minted["token"].as_str().expect("token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("v2 slip");
    let key = signing_key(minted["binding_key"].as_str().expect("binding key"));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let read = |proof: &Value| {
        reqwest::blocking::Client::new()
            .get(format!("http://127.0.0.1:{port}/v1/core/conversations"))
            .bearer_auth(&token)
            .header("x-oneiron-binding", proof.to_string())
            .send()
            .expect("read conversations")
            .status()
            .as_u16()
    };

    let first = serve(&config, port, &dir.path().join("serve-1.log"));
    let proof = holder_proof(&slip, &key, unix_seconds_now()).unwrap();
    assert_eq!(read(&proof), 200, "a fresh proof");
    assert_eq!(read(&proof), 401, "the same proof replayed");
    sigterm(first);

    // Down for 70 s, counted from the stop: the old window's clock moved
    // while the first server ran, and never while it was down.
    std::thread::sleep(Duration::from_secs(70));

    let _second = serve(&config, port, &dir.path().join("serve-2.log"));
    let now = unix_seconds_now();
    let at = |timestamp: u64| holder_proof(&slip, &key, timestamp).unwrap();
    assert_eq!(read(&at(now)), 200, "a fresh proof after the stop");
    assert_eq!(read(&at(now - 120)), 401, "a proof older than the window");
    assert_eq!(read(&at(now + 120)), 401, "a proof dated past the window");
}

/// The host clock ran a year ahead while an agent called, then was set
/// back. The shipped server refuses the agent's fresh proofs, and its 401
/// and its log say why and name the command. `oneiron recover-clock` refuses
/// while the server runs; with it stopped, the command lowers the clock, and
/// the same agent's next fresh proof is accepted. Run again, it finds
/// nothing to recover.
#[test]
fn an_owner_lets_agents_back_in_after_the_host_clock_ran_a_year_ahead() {
    const YEAR: u64 = 365 * 24 * 60 * 60;
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let minted: Value = serde_json::from_str(&stdout(oneiron(
        &["token", "agent", "--name", "clock-recovery"],
        &config,
    )))
    .expect("token agent prints its credential as JSON");
    let token = minted["token"].as_str().expect("token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("v2 slip");
    let key = signing_key(minted["binding_key"].as_str().expect("binding key"));

    // The agent calls while the host clock reads a year ahead.
    {
        let ahead = unix_seconds_now() + YEAR;
        let clock = ManualClock::new(ahead);
        let mut vault_config = oneiron::VaultConfig::server();
        vault_config.store_clock = clock.bundle();
        let jumped = oneiron::Vault::open_owned(&vault, vault_config).unwrap();
        let nonce = format!("{:032x}", 1);
        let challenge = oneiron::authority::holder_proof_challenge(ahead, &nonce);
        let signature = key
            .sign(&slip.binding_transcript(&challenge).unwrap())
            .to_bytes();
        jumped
            .admit_capability_slip_request(&slip, ahead, &signature, nonce.as_bytes())
            .expect("admitted while the clock read a year ahead");
    }

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let read = || {
        let proof = holder_proof(&slip, &key, unix_seconds_now()).unwrap();
        let response = reqwest::blocking::Client::new()
            .get(format!("http://127.0.0.1:{port}/v1/core/conversations"))
            .bearer_auth(&token)
            .header("x-oneiron-binding", proof.to_string())
            .send()
            .expect("read conversations");
        let status = response.status().as_u16();
        (status, response.text().expect("response body"))
    };
    let recover = || {
        oneiron(&["recover-clock"], &config)
            .output()
            .expect("run oneiron")
    };

    let log = dir.path().join("serve-1.log");
    let first = serve(&config, port, &log);
    let (status, body) = read();
    assert_eq!(status, 401, "a fresh proof under the year-ahead clock");
    assert!(
        body.contains("proof_clock_ahead") && body.contains("oneiron recover-clock"),
        "the 401 names its reason and the command: {body}"
    );
    let refused = recover();
    assert!(
        !refused.status.success(),
        "recover-clock beside a running serve"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("running `oneiron serve`"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    sigterm(first);
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(
        logged.contains("proof clock") && logged.contains("oneiron recover-clock"),
        "the server log names the reason and the command: {logged}"
    );
    assert!(
        logged.contains("proof_clock") && logged.contains("wall_clock"),
        "the server log gives both clocks: {logged}"
    );

    let recovered: Value = serde_json::from_str(&stdout(oneiron(&["recover-clock"], &config)))
        .expect("recover-clock prints JSON");
    let gap = recovered["gap_secs"].as_u64().expect("gap_secs");
    assert!(
        (YEAR - 600..=YEAR).contains(&gap),
        "a year ahead: {recovered}"
    );

    let second = serve(&config, port, &dir.path().join("serve-2.log"));
    assert_eq!(read().0, 200, "the same agent's next fresh proof");
    sigterm(second);
    let again = recover();
    assert!(!again.status.success(), "nothing left to recover");
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("nothing to recover"),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
}

/// 200 agents minted one process each, as `token agent` mints them, then a
/// serve: every agent's proof is accepted. The injected clock stands for the
/// wall clock: it moves on by at least a second between processes, which
/// the old window's clock never counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_hundred_agents_minted_one_process_each_all_prove_on_the_next_serve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let clock = ManualClock::new(unix_seconds_now());
    let open = |path: &Path| {
        let mut config = oneiron::VaultConfig::server();
        config.store_clock = clock.bundle();
        oneiron::Vault::open_owned(path, config).unwrap()
    };
    let mut agents = Vec::new();
    for agent in 0..200_u8 {
        let vault = open(&path);
        agents.push(mint_agent(&vault, &issuer, agent));
        drop(vault);
        clock.set(unix_seconds_now() + u64::from(agent) + 1);
    }

    let server = Arc::new(
        SyncServer::new(
            Arc::new(open(&path)),
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server.clone());
    let read = |slip: &CapabilitySlip, proof: &Value| {
        app.clone().oneshot(
            Request::builder()
                .uri("/v1/core/conversations")
                .header(
                    AUTHORIZATION,
                    format!("Bearer {}", slip.to_token().unwrap()),
                )
                .header("x-oneiron-binding", proof.to_string())
                .body(Body::empty())
                .unwrap(),
        )
    };
    let now = server.vault().now_recorded_at();
    for (slip, key) in &agents {
        let proof = holder_proof(slip, key, now).unwrap();
        let status = read(slip, &proof).await.unwrap().status();
        assert_eq!(status, StatusCode::OK, "agent {}", slip.claims.holder_ref);
    }

    let (slip, key) = &agents[0];
    let proof = holder_proof(slip, key, now).unwrap();
    assert_eq!(read(slip, &proof).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        read(slip, &proof).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "the same proof replayed"
    );
    for stale in [now - 61, now + 61] {
        let proof = holder_proof(slip, key, stale).unwrap();
        assert_eq!(
            read(slip, &proof).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "a proof dated {stale} against {now}"
        );
    }

    // The host sleeps for 90 s while the server runs.
    clock.set(now + 90);
    let proof = holder_proof(slip, key, now + 90).unwrap();
    assert_eq!(read(slip, &proof).await.unwrap().status(), StatusCode::OK);
}

/// What `token agent` mints: a named agent principal holding a paired slip.
fn mint_agent(
    vault: &oneiron::Vault,
    issuer: &HostSlipIssuer,
    agent: u8,
) -> (CapabilitySlip, SigningKey) {
    let principal = vault
        .ensure_agent_principal(&format!("clock-agent-{agent}"))
        .unwrap()
        .to_hex();
    vault.ensure_host_root_slip(issuer).unwrap();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            scope,
            30 * 24 * 60 * 60,
            PairingPrincipal {
                holder_ref: Some(principal.clone()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
            },
        )
        .unwrap();
    let key = SigningKey::from_bytes(&[agent; 32]);
    let binding_key = key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal).unwrap();
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &principal,
            binding_key,
            &key.sign(&transcript).to_bytes(),
        )
        .unwrap();
    (slip, key)
}

fn signing_key(seed: &str) -> SigningKey {
    let seed: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&seed[at..at + 2], 16).expect("hex seed"))
        .collect();
    SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"))
}
