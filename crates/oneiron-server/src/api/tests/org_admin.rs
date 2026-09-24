//! Organization credentials expose only their fixed administrative action list.
use super::*;

#[tokio::test]
async fn org_admin_routes_render_only_setup_powers_and_refuse_excluded_operations() {
    use ed25519_dalek::{Signer, SigningKey};
    use oneiron::authority::{HostSlipIssuer, PairingPrincipal, pairing_binding_transcript};
    use oneiron::federation::{OrgAdminPolicy, OrgAdminPower, Scope, ScopeAxis};

    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("org-root".into()),
        ..Default::default()
    });
    let org = oneiron::EntityId::now();
    let admin = oneiron::EntityId::now();
    let policy = OrgAdminPolicy::new(
        org,
        BTreeSet::from([admin]),
        BTreeSet::from([OrgAdminPower::AddMember]),
    )
    .unwrap();
    server.vault().configure_org_admin(&policy).unwrap();
    server
        .vault()
        .put_entity(
            &admin,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"admin",
        )
        .unwrap();
    let issuer = HostSlipIssuer::from_secret(b"org-root").unwrap();
    let holder = SigningKey::from_bytes(&[37; 32]);
    let key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["org:add-member".into()]));
    let ticket = server
        .vault()
        .issue_pairing_link_for_principal(
            &issuer,
            scope,
            600,
            PairingPrincipal {
                holder_ref: Some(admin.to_hex()),
                actor_class: Some("human".into()),
                org_ref: Some(org.to_hex()),
            },
        )
        .unwrap();
    let signature =
        holder.sign(&pairing_binding_transcript(&ticket.code, &key, &admin.to_hex()).unwrap());
    let slip = server
        .vault()
        .redeem_pairing_link(
            &issuer,
            &ticket.code,
            &admin.to_hex(),
            key,
            &signature.to_bytes(),
        )
        .unwrap();
    let bind =
        |request| crate::test_credentials::bind_slip_request(&server, &slip, &holder, request);
    let (status, body) = route_json(
        server.clone(),
        bind(
            Request::builder()
                .uri(format!("/v1/core/org-admin/{}/powers", org.to_hex()))
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["powers"], json!(["org:add-member"]));
    // Neither authority to change setup (self-grant/root) nor private reads is delegated.
    for (path, payload) in [
        (
            format!("/v1/core/org-admin/{}/policy", org.to_hex()),
            serde_json::to_value(&policy).unwrap(),
        ),
        (
            "/v1/core/query".to_owned(),
            json!({"text":"private member data"}),
        ),
    ] {
        let path_is_private = path == "/v1/core/query";
        let (status, _) = route_json(
            server.clone(),
            bind(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            ),
        )
        .await;
        assert_eq!(
            status,
            if path_is_private {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
    }
}
