//! Slip-only transport admission with a historical receipt-key registry row.
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::sync::lease::{self, LeaseStatus};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tower::ServiceExt;

const ISSUER_KEY: &str = "slip-only-transport-issuer";

fn server() -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(ISSUER_KEY.into()),
            lease_vault_id: 7,
            ..Default::default()
        },
    )
    .unwrap();
    (dir, Arc::new(server))
}

fn legacy_headers(request: &mut Request<Body>, id: u64, key: &SigningKey) {
    let pubkey = key.verifying_key().to_bytes();
    let proof = key
        .sign(&lease::lease_pop_transcript(id, &pubkey))
        .to_bytes();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for (name, value) in [
        ("x-oneiron-vault", "0000000000000007".to_owned()),
        ("x-oneiron-client", format!("{id:016x}")),
        ("x-oneiron-key", hex(&pubkey)),
        ("x-oneiron-proof", hex(&proof)),
    ] {
        request.headers_mut().insert(name, value.parse().unwrap());
    }
}

#[tokio::test]
async fn receipt_key_cannot_authorize_http_or_rotate_into_a_new_binding() {
    let (_dir, server) = server();
    let key = SigningKey::from_bytes(&[17; 32]);
    super::tests::seed_historical_lease(
        &server,
        7,
        42,
        key.verifying_key().to_bytes(),
        LeaseStatus::Active,
    );
    // The row remains as receipt provenance, not transport authority.
    let record = server
        .vault()
        .sync_state_get(&lease::lease_key(7, 42))
        .unwrap()
        .unwrap();
    assert_eq!(
        lease::decode_lease_record(&record).unwrap().status,
        LeaseStatus::Active
    );
    let app = crate::build_app(server.clone());
    let private = || {
        Request::builder()
            .uri("/v1/core/conversations")
            .body(Body::empty())
            .unwrap()
    };
    let mut old = private();
    legacy_headers(&mut old, 42, &key);
    assert_eq!(
        app.clone().oneshot(old).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut root = Request::builder()
        .uri("/v1/core/conversations")
        .header("authorization", format!("Bearer {ISSUER_KEY}"))
        .body(Body::empty())
        .unwrap();
    legacy_headers(&mut root, 42, &key);
    assert_eq!(
        app.clone().oneshot(root).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let (slip, holder) = crate::test_credentials::credential(&server, "jti=slip-only-http");
    let bound = crate::test_credentials::bind_slip_request(&server, &slip, &holder, private());
    assert_eq!(
        app.clone().oneshot(bound).await.unwrap().status(),
        StatusCode::OK
    );
    let rotation = serde_json::json!({
        "old_client_id": "000000000000002a", "client_id": "000000000000002b",
        "pubkey": "00", "proof": "00"
    });
    for path in ["/api/lease/register", "/api/lease/rotate"] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(rotation.to_string()))
            .unwrap();
        let bound = crate::test_credentials::bind_slip_request(&server, &slip, &holder, request);
        assert_eq!(
            app.clone().oneshot(bound).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
    assert!(
        server
            .root_doc
            .get_map(lease::ROOT_LEASES_MAP)
            .get(&lease::lease_registry_key(7, 43))
            .is_none()
    );
    assert!(
        server
            .vault()
            .sync_state_get(&lease::lease_key(7, 43))
            .unwrap()
            .is_none()
    );
    // The remaining owner-only mutation can revoke a receipt-signing key;
    // it cannot grant HTTP access or rotate the device into a new authority.
    let revoke = Request::builder()
        .method("POST")
        .uri("/api/lease/revoke")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"client_id":"000000000000002a"}"#))
        .unwrap();
    let bound = crate::test_credentials::bind_slip_request(&server, &slip, &holder, revoke);
    assert_eq!(
        app.clone().oneshot(bound).await.unwrap().status(),
        StatusCode::OK
    );
    let record = server
        .vault()
        .sync_state_get(&lease::lease_key(7, 42))
        .unwrap()
        .unwrap();
    assert_eq!(
        lease::decode_lease_record(&record).unwrap().status,
        LeaseStatus::Revoked
    );
    let bound = crate::test_credentials::bind_slip_request(&server, &slip, &holder, private());
    assert_eq!(app.oneshot(bound).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn receipt_key_and_verbatim_root_fail_ws_but_holder_bound_slip_upgrades() {
    let (_dir, server) = server();
    let key = SigningKey::from_bytes(&[19; 32]);
    super::tests::seed_historical_lease(
        &server,
        7,
        42,
        key.verifying_key().to_bytes(),
        LeaseStatus::Active,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = crate::build_app(server.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for bearer in [None, Some(ISSUER_KEY)] {
        let mut request = url.clone().into_client_request().unwrap();
        if let Some(bearer) = bearer {
            request
                .headers_mut()
                .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
        }
        let mut historical = Request::builder().body(Body::empty()).unwrap();
        legacy_headers(&mut historical, 42, &key);
        for name in [
            "x-oneiron-vault",
            "x-oneiron-client",
            "x-oneiron-key",
            "x-oneiron-proof",
        ] {
            request
                .headers_mut()
                .insert(name, historical.headers()[name].clone());
        }
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio_tungstenite::connect_async(request),
        )
        .await
        .unwrap()
        .unwrap_err();
        match status {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
            other => panic!("unexpected socket error: {other:?}"),
        }
    }
    let (slip, holder) = crate::test_credentials::credential(&server, "jti=slip-only-ws");
    let headers = crate::test_credentials::bind_slip_request(
        &server,
        &slip,
        &holder,
        Request::builder().body(Body::empty()).unwrap(),
    );
    let mut request = url.into_client_request().unwrap();
    for name in ["authorization", "x-oneiron-binding"] {
        request
            .headers_mut()
            .insert(name, headers.headers()[name].clone());
    }
    let (socket, response) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio_tungstenite::connect_async(request),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    drop(socket);
    task.abort();
}
