//! Log-backed v2 credentials at the HTTP boundary.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, pairing_binding_transcript};
use oneiron::federation::{Scope, ScopeAxis};

const SLIP_SECRET: &str = "retained-http-host-root";
fn server() -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        auth_secret: Some(SLIP_SECRET.into()),
        ..Default::default()
    })
}
fn proof(slip: &CapabilitySlip, key: &SigningKey) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = key
        .sign(&slip.binding_transcript(challenge.as_bytes()).unwrap())
        .to_bytes();
    let signature: String = signature.iter().map(|b| format!("{b:02x}")).collect();
    json!({"timestamp":timestamp,"nonce":nonce,"signature":signature}).to_string()
}
#[tokio::test]
async fn descriptor_is_unauthenticated_and_pairing_link_is_one_use() {
    let (_dir, server) = server();
    let (status, body) = route_json(
        server.clone(),
        Request::builder()
            .uri("/.well-known/oneiron")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["slip_version"], 2);
    let actor = seed_turn(&server, "pairing fixture actor").to_hex();
    let issuer = HostSlipIssuer::from_secret(SLIP_SECRET.as_bytes()).unwrap();
    let link = server
        .vault()
        .issue_pairing_link(&issuer, Scope::top(), 600)
        .unwrap();
    let holder = SigningKey::from_bytes(&[81; 32]);
    let binding_key = holder.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript(&link.ticket, &binding_key, &actor).unwrap();
    let signature = holder.sign(&transcript).to_bytes().to_vec();
    let data = json!({"ticket":link.ticket,"holder_ref":actor,"binding_key":binding_key,"signature":signature});
    let mut no_key = data.clone();
    no_key["signature"] = json!([]);
    let (status, _) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/pairing/redeem", no_key),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/pairing/redeem", data.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["token"].as_str().unwrap().starts_with("v2.slip."));
    let (status, _) = route_json(
        server,
        json_request("POST", "/v1/core/pairing/redeem", data),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn v2_http_tamper_and_token_without_private_binding_refuse_401() {
    let (_dir, server) = server();
    let issuer = HostSlipIssuer::from_secret(SLIP_SECRET.as_bytes()).unwrap();
    let holder = SigningKey::from_bytes(&[82; 32]);
    let mut claims = server
        .vault()
        .ensure_host_root_slip(&issuer)
        .unwrap()
        .claims;
    claims.slip_id = [82; 32];
    claims.holder_ref = seed_turn(&server, "holder").to_hex();
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".into()]));
    let slip = server
        .vault()
        .mint_capability_slip(&issuer, claims)
        .unwrap();
    let token = slip.to_token().unwrap();
    let headers = || {
        Request::builder()
            .uri("/v1/core/conversations")
            .header(AUTHORIZATION, format!("Bearer {token}"))
    };
    let (status, _) = route_json(server.clone(), headers().body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = route_json(
        server.clone(),
        headers()
            .header("x-oneiron-binding", proof(&slip, &holder))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let used_proof = proof(&slip, &holder);
    for expected in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
        let (status, _) = route_json(
            server.clone(),
            headers()
                .header("x-oneiron-binding", &used_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, expected);
    }
    let (status, _) = route_json(
        server.clone(),
        headers()
            .header("x-oneiron-binding", proof(&slip, &holder))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut tampered = slip.clone();
    tampered.claims.scope = Scope::top();
    let (status, _) = route_json(
        server.clone(),
        Request::builder()
            .uri("/v1/core/conversations")
            .header(
                AUTHORIZATION,
                format!("Bearer {}", tampered.to_token().unwrap()),
            )
            .header("x-oneiron-binding", proof(&tampered, &holder))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    server
        .vault()
        .revoke_capability_slip(&issuer, slip.claims.slip_id)
        .unwrap();
    let (status, _) = route_json(
        server,
        headers()
            .header("x-oneiron-binding", proof(&slip, &holder))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn unlogged_mac_tokens_and_dev_tokens_never_become_production_slips() {
    let (_dir, server) = server();
    let token = crate::auth::mint_core_token_v2(SLIP_SECRET, "scope=core:read");
    let (status, _) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/conversations")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_dir, dev) = test_server();
    assert!(dev.vault().authority_fold().unwrap().vault_id.is_none());
}
