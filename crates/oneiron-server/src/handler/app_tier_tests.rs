#![allow(clippy::unwrap_used)]

use super::*;
use crate::auth::{mint_core_token_v2, revoke_token_jti};
use crate::config::SyncServerConfig;
use serde_json::json;

const SECRET: &str = "app-tier-test-root";
const PRINCIPAL: &str = "01010101010101010101010101010101";
const JTI: &str = "02020202020202020202020202020202";

fn server() -> (tempfile::TempDir, SyncServer) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(SECRET.to_owned()),
            ..Default::default()
        },
    )
    .unwrap();
    (dir, server)
}

fn state(version: u8) -> ConnState {
    ConnState::new(1000, version, FederationQuotaConfig::new(10, 1))
}

fn token() -> String {
    mint_core_token_v2(
        SECRET,
        &format!("scope=core:read;principal_ref={PRINCIPAL};jti={JTI}"),
    )
}

fn bind(token: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"requestId": 7, "method": "auth.bind", "params": {"token": token}}))
        .unwrap()
}

#[tokio::test]
async fn app_version_and_bind_gates_precede_payload_decoding() {
    let (_dir, server) = server();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    for tag in [protocol::TAG_RPC, protocol::TAG_SUB] {
        let mut legacy = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION - 1);
        assert!(matches!(
            handle_app_message(&server, &mut legacy, tag, b"not-json", &tx),
            Err(ProtocolError::RpcVersionMismatch)
        ));
        let mut current = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
        assert!(matches!(
            handle_app_message(&server, &mut current, tag, b"not-json", &tx),
            Err(ProtocolError::RpcNoPrincipal)
        ));
    }
}

#[tokio::test]
async fn bind_is_once_only_and_does_not_change_sync_mode() {
    let (_dir, server) = server();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut state = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
    handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(&token()), &tx).unwrap();
    assert_eq!(
        state.bound_auth.as_ref().unwrap().principal_ref(),
        Some(PRINCIPAL)
    );
    assert_eq!(state.window_sync_mode, WindowSyncMode::Unbound);
    let reply = rx.try_recv().unwrap();
    assert_eq!(reply[0], protocol::TAG_RPC);
    let value: serde_json::Value = serde_json::from_slice(&reply[1..]).unwrap();
    assert_eq!(value["requestId"], 7);
    assert_eq!(value["last"], true);
    assert!(value["result"].is_null());
    assert!(rx.try_recv().is_err());
    assert!(matches!(
        handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(&token()), &tx),
        Err(ProtocolError::RpcNoPrincipal)
    ));
}

#[tokio::test]
async fn every_invalid_bind_fails_closed() {
    let (_dir, server) = server();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let malformed_mac = format!("v2.scope=core:read;principal_ref={PRINCIPAL}.bad");
    let unknown = mint_core_token_v2(
        SECRET,
        &format!("scope=core:read;principal_ref={PRINCIPAL};unknown=x"),
    );
    let no_principal = mint_core_token_v2(SECRET, "scope=core:read");
    for invalid in [
        SECRET,
        "app-tier-test-root;scope=core:read",
        &malformed_mac,
        &unknown,
        &no_principal,
    ] {
        let mut state = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
        assert!(
            matches!(
                handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(invalid), &tx),
                Err(ProtocolError::RpcNoPrincipal)
            ),
            "{invalid}"
        );
        assert!(state.bound_auth.is_none());
    }
    revoke_token_jti(server.vault(), JTI).unwrap();
    let mut state = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
    assert!(matches!(
        handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(&token()), &tx),
        Err(ProtocolError::RpcNoPrincipal)
    ));
}

#[tokio::test]
async fn bound_revocation_stops_app_requests_but_does_not_rebind_sync() {
    let (_dir, server) = server();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let mut state = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
    handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(&token()), &tx).unwrap();
    revoke_token_jti(server.vault(), JTI).unwrap();
    let read = br#"{"requestId":8,"method":"hydrate","params":{"refs":[]}}"#;
    assert!(matches!(
        handle_app_message(&server, &mut state, protocol::TAG_RPC, read, &tx),
        Err(ProtocolError::RpcNoPrincipal)
    ));
    assert_eq!(state.window_sync_mode, WindowSyncMode::Unbound);
}

#[tokio::test]
async fn missing_actor_class_is_forbidden_and_not_a_human_fallback() {
    let (_dir, server) = server();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut state = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
    handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(&token()), &tx).unwrap();
    rx.try_recv().unwrap();
    let read = br#"{"requestId":8,"method":"hydrate","params":{"refs":[]}}"#;
    handle_app_message(&server, &mut state, protocol::TAG_RPC, read, &tx).unwrap();
    let reply = rx.try_recv().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&reply[1..]).unwrap();
    assert_eq!(value["error"]["code"], "FORBIDDEN");
    assert_eq!(value["last"], true);
    assert!(value.get("result").is_none());
}

#[tokio::test]
async fn verified_class_reaches_production_rpc_and_scope_refusal_stays_typed() {
    let (_dir, server) = server();
    for scope in ["core:read", "core:write"] {
        let slip = mint_core_token_v2(
            SECRET,
            &format!("scope={scope};principal_ref={PRINCIPAL};actor_class=agent"),
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut state = state(protocol::APP_TIER_PROTOCOL_VERSION_VERSION);
        handle_app_message(&server, &mut state, protocol::TAG_RPC, &bind(&slip), &tx).unwrap();
        assert_eq!(
            state.bound_auth.as_ref().unwrap().actor_class(),
            Some("agent")
        );
        rx.try_recv().unwrap();
        let read = br#"{"requestId":8,"method":"hydrate","params":{"refs":[]}}"#;
        handle_app_message(&server, &mut state, protocol::TAG_RPC, read, &tx).unwrap();
        let frame = rx.try_recv().unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&frame[1..]).unwrap();
        assert_eq!(reply["requestId"], 8);
        assert_eq!(reply["last"], true);
        if scope == "core:read" {
            assert_eq!(reply["result"], json!([]));
            assert!(reply.get("error").is_none());
        } else {
            assert_eq!(reply["error"]["code"], "FORBIDDEN");
            assert!(reply.get("result").is_none());
        }
        assert_eq!(state.window_sync_mode, WindowSyncMode::Unbound);
        assert!(rx.try_recv().is_err());
    }
}

#[test]
fn legacy_hello_and_selector_semantics_survive_single_bump() {
    use oneiron::sync::transport::TAG_PROTOCOL_HELLO;
    for version in [
        protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION,
        protocol::LEGACY_SELECTOR_PROTOCOL_VERSION,
        protocol::PROTOCOL_VERSION,
    ] {
        assert_eq!(
            validate_protocol_hello(&[TAG_PROTOCOL_HELLO, version]),
            Ok(version)
        );
    }
    let mut selector = state(protocol::LEGACY_SELECTOR_PROTOCOL_VERSION);
    selector
        .bind_window_sync_mode(WindowSyncMode::Selector)
        .unwrap();
    assert!(
        selector
            .bind_window_sync_mode(WindowSyncMode::FullWindow)
            .is_err()
    );
    let mut full = state(protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION);
    full.bind_window_sync_mode(WindowSyncMode::FullWindow)
        .unwrap();
    assert!(
        full.bind_window_sync_mode(WindowSyncMode::Selector)
            .is_err()
    );
    assert_eq!(close_codes::CLOSE_RPC_VERSION_MISMATCH, 4007);
    assert_eq!(close_codes::CLOSE_RPC_NO_PRINCIPAL, 4008);
}

#[test]
fn bind_rejects_v2_shaped_root_and_unverified_dev_tokens() {
    struct Live;
    impl RevokedTokenJtis for Live {
        fn is_revoked(&self, _: &str) -> Result<bool, ()> {
            Ok(false)
        }
    }
    struct Unreadable;
    impl RevokedTokenJtis for Unreadable {
        fn is_revoked(&self, _: &str) -> Result<bool, ()> {
            Err(())
        }
    }
    let token = token();
    let config = SyncServerConfig {
        auth_secret: Some(token.clone()),
        ..Default::default()
    };
    assert!(CoreAuth::from_bind_token(&token, &config, &Live).is_err());
    let config = SyncServerConfig {
        auth_secret: None,
        allow_unauthenticated: true,
        ..Default::default()
    };
    assert!(CoreAuth::from_bind_token(&token, &config, &Live).is_err());
    let config = SyncServerConfig {
        auth_secret: Some(SECRET.to_owned()),
        ..Default::default()
    };
    assert!(CoreAuth::from_bind_token(&token, &config, &Unreadable).is_err());
}
