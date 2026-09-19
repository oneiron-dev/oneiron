use super::*;
use axum::http::HeaderMap;
use ed25519_dalek::{Signer, SigningKey};
fn proof(id: u64, key: &SigningKey) -> [u8; 64] {
    key.sign(&lease::lease_pop_transcript(
        id,
        &key.verifying_key().to_bytes(),
    ))
    .to_bytes()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn headers(vault: u64, id: u64, key: &SigningKey) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, value) in [
        ("x-oneiron-vault", format!("{vault:016x}")),
        ("x-oneiron-client", format!("{id:016x}")),
        ("x-oneiron-key", hex(&key.verifying_key().to_bytes())),
        ("x-oneiron-proof", hex(&proof(id, key))),
    ] {
        h.insert(name, value.parse().unwrap());
    }
    h
}
#[tokio::test]
async fn scoped_doors_and_rotation_keep_old_key_terminal() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = SyncServer::new(
        Arc::new(oneiron::Vault::open(a_dir.path(), oneiron::VaultConfig::device()).unwrap()),
        SyncServerConfig {
            lease_vault_id: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let b = SyncServer::new(
        Arc::new(oneiron::Vault::open(b_dir.path(), oneiron::VaultConfig::device()).unwrap()),
        SyncServerConfig {
            lease_vault_id: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let old = SigningKey::from_bytes(&[7; 32]);
    let new = SigningKey::from_bytes(&[8; 32]);
    assert!(a.require_vault_binding(&headers(1, 10, &old)).is_err());
    assert!(
        a.register_lease(10, &old.verifying_key().to_bytes(), &proof(10, &old))
            .await
            .unwrap()
            .granted
    );
    assert!(a.require_vault_binding(&headers(1, 10, &old)).is_ok());
    assert!(b.require_vault_binding(&headers(1, 10, &old)).is_err());
    assert!(b.require_vault_binding(&headers(2, 10, &old)).is_err());
    assert!(
        !a.rotate_lease(10, 11, &new.verifying_key().to_bytes(), &[0; 64])
            .await
            .unwrap()
            .granted
    );
    assert!(a.require_vault_binding(&headers(1, 10, &old)).is_ok());
    assert!(
        a.rotate_lease(10, 11, &new.verifying_key().to_bytes(), &proof(11, &new))
            .await
            .unwrap()
            .granted
    );
    assert!(a.require_vault_binding(&headers(1, 10, &old)).is_err());
    assert!(a.require_vault_binding(&headers(1, 11, &new)).is_ok());
    assert!(
        !a.register_lease(12, &old.verifying_key().to_bytes(), &proof(12, &old))
            .await
            .unwrap()
            .granted
    );
    // An independent vault's lease is not poisoned by the old-key revocation.
    assert!(
        b.register_lease(10, &old.verifying_key().to_bytes(), &proof(10, &old))
            .await
            .unwrap()
            .granted
    );
    assert!(b.require_vault_binding(&headers(2, 10, &old)).is_ok());
}

#[tokio::test]
async fn api_router_rejects_unleased_and_cross_vault_credentials_before_reads() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let server = Arc::new(
        SyncServer::new(
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap()),
            SyncServerConfig {
                lease_vault_id: 7,
                auth_secret: Some("owner-secret".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let key = SigningKey::from_bytes(&[21; 32]);
    let request = |vault| {
        let mut request = Request::builder()
            .uri("/v1/usage/owners/owner/vaults/local/rollup")
            .header("authorization", "Bearer owner-secret")
            .body(Body::empty())
            .unwrap();
        request.headers_mut().extend(headers(vault, 22, &key));
        request
    };
    let app = crate::build_app(server.clone());
    assert_eq!(
        app.clone().oneshot(request(7)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    server
        .register_lease(22, &key.verifying_key().to_bytes(), &proof(22, &key))
        .await
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request(8)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    // A valid local lease reaches the handler; the empty ledger returns its typed miss.
    assert_eq!(
        app.clone().oneshot(request(7)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    // Owner recovery cannot require the device it is trying to recover.
    let recovery = Request::builder()
        .method("POST")
        .uri("/api/lease/revoke")
        .header("authorization", "Bearer owner-secret")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"client_id":"0000000000000016"}"#))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(recovery).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request(7)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn granted_world_is_read_locally_but_never_by_a_cross_vault_lease() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use oneiron::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    };
    use oneiron::sync::selector::{
        FederationAdmissionRole, SyncSelector, SyncSelectorWorld, filtered_window_doc,
        put_selector_test_federation_grant,
    };
    use oneiron::sync::{SyncClient, SyncClientConfig, WindowKey, WindowManager};
    use oneiron::{EntityId, Vault, VaultConfig, temporal::TimeRange};
    use tower::ServiceExt;
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let servers: Vec<_> = dirs
        .iter()
        .enumerate()
        .map(|(i, d)| {
            Arc::new(
                SyncServer::new(
                    Arc::new(Vault::open(d.path(), VaultConfig::device()).unwrap()),
                    SyncServerConfig {
                        lease_vault_id: i as u64 + 1,
                        auth_secret: Some("owner-secret".into()),
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
        })
        .collect();
    let a = &servers[0];
    let b = &servers[1];
    let world = EntityId::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    a.vault()
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"granted foreign WORLD",
        )
        .unwrap();
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let scope = FederationGrantScope::vault(1);
    let grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    put_selector_test_federation_grant(a.vault(), &grant_id, &grant, now).unwrap();
    let window = WindowKey::from_timestamp(now);
    let doc = oneiron::sync::schema::create_window_doc("publisher", &window);
    oneiron::sync::window::reverse_rematerialize(a.vault(), &doc, &window).unwrap();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::World(oneiron::entity_id::LocalWorldId::from_entity_id(world).unwrap()),
        vec![],
        vec![oneiron::federation::SelectorRange::Core],
    );
    let selected = filtered_window_doc(a.vault(), &doc, &window, scope, &selector).unwrap();
    let payload = selected.export(loro::ExportMode::all_updates()).unwrap();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(b.vault()),
        Arc::new(oneiron::sync::bridge::Materializer::new()),
        "subscriber",
    ));
    let (mut client, _events) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();
    client.ensure_window(window.as_str()).unwrap();
    client
        .import_federated_window_update(window.as_str(), &payload, FederationAdmissionRole::Member)
        .unwrap();
    assert_eq!(
        b.vault().get(&world).unwrap(),
        Some(b"granted foreign WORLD".to_vec())
    );
    let key = SigningKey::from_bytes(&[42; 32]);
    b.register_lease(42, &key.verifying_key().to_bytes(), &proof(42, &key))
        .await
        .unwrap();
    let request = |vault_id| {
        let mut request = Request::builder()
            .uri(format!("/api/entity/{}", world.to_hex()))
            .header("authorization", "Bearer owner-secret")
            .body(Body::empty())
            .unwrap();
        request.headers_mut().extend(headers(vault_id, 42, &key));
        request
    };
    let app = crate::build_app(Arc::clone(b));
    assert_eq!(
        app.clone().oneshot(request(2)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request(1)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        oneiron::sync::lease::require_vault_lease(
            b.vault(),
            1,
            42,
            &key.verifying_key().to_bytes()
        )
        .is_err()
    );
    assert!(
        oneiron::sync::lease::require_vault_lease(
            b.vault(),
            2,
            43,
            &key.verifying_key().to_bytes()
        )
        .is_err()
    );
}

#[tokio::test]
async fn lease_registration_returns_lossless_header_ready_vault_id() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let vault_id = 0xfedc_ba98_7654_3210;
    let server = Arc::new(
        SyncServer::new(
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap()),
            SyncServerConfig {
                lease_vault_id: vault_id,
                auth_secret: Some("owner-secret".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let key = SigningKey::from_bytes(&[51; 32]);
    let body = serde_json::json!({
        "client_id": 22,
        "pubkey": hex(&key.verifying_key().to_bytes()),
        "proof": hex(&proof(22, &key)),
    });
    let app = crate::build_app(server.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/lease/register")
                .header("authorization", "Bearer owner-secret")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["granted"], true);
    let scope = body["vault_id"].as_str().expect("opaque scope is a string");
    assert_eq!(scope, "fedcba9876543210");
    let mut binding = headers(vault_id, 22, &key);
    binding.insert("x-oneiron-vault", scope.parse().unwrap());
    assert!(server.require_vault_binding(&binding).is_ok());
}
