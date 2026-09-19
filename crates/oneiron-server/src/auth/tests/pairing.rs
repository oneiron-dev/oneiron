//! Owner-approved principal delivery through the actual pairing HTTP routes.
use super::*;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::authority::{PairingPrincipal, pairing_binding_transcript};
use oneiron::federation::OrgAdminPolicy;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn request(
    server: &Arc<SyncServer>,
    method: &str,
    path: &str,
    headers: HeaderMap,
    payload: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    *request.headers_mut().unwrap() = headers;
    let body = if let Some(payload) = payload {
        request = request.header("content-type", "application/json");
        Body::from(payload.to_string())
    } else {
        Body::empty()
    };
    let response = crate::api::api_routes(server.clone())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}
fn principal(fixture: &Fixture, org: oneiron::EntityId) -> PairingPrincipal {
    PairingPrincipal {
        holder_ref: Some(fixture.actor.to_hex()),
        actor_class: Some("human".into()),
        org_ref: Some(org.to_hex()),
    }
}
fn org_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = verbs(&["org:add-member"]);
    scope
}
fn configure(fixture: &Fixture, org: oneiron::EntityId) {
    fixture.register(fixture.actor);
    fixture
        .vault
        .configure_org_admin(
            &OrgAdminPolicy::new(
                org,
                BTreeSet::from([fixture.actor]),
                BTreeSet::from([OrgAdminPower::AddMember]),
            )
            .unwrap(),
        )
        .unwrap();
}
fn redemption(ticket: &str, actor: oneiron::EntityId, holder: &SigningKey) -> Value {
    let binding_key = holder.verifying_key().to_bytes();
    let holder_ref = actor.to_hex();
    let transcript = pairing_binding_transcript(ticket, &binding_key, &holder_ref).unwrap();
    json!({"ticket":ticket,"holder_ref":holder_ref,"binding_key":binding_key,
        "signature":holder.sign(&transcript).to_bytes().to_vec()})
}

#[tokio::test]
async fn owner_approved_org_ticket_delivers_fixed_principal_and_only_approved_powers() {
    let fixture = Fixture::new();
    let org = oneiron::EntityId::now();
    configure(&fixture, org);
    let other = oneiron::EntityId::now();
    fixture.register(other);
    let server = Arc::new(SyncServer::new(fixture.vault.clone(), fixture.config.clone()).unwrap());
    let payload =
        json!({"scope":org_scope(),"lifetime_secs":600,"principal":principal(&fixture, org)});
    let narrow = fixture.mint(|claims| claims.scope.verbs = verbs(&["read"]));
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/pairing/links",
        fixture.headers(&narrow),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = request(
        &server,
        "POST",
        "/v1/core/pairing/links",
        bearer(SECRET),
        Some(payload),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ticket = body["ticket"].as_str().unwrap();
    // Even a valid holder signature cannot substitute the intended admin.
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/pairing/redeem",
        HeaderMap::new(),
        Some(redemption(ticket, other, &fixture.holder)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let payload = redemption(ticket, fixture.actor, &fixture.holder);
    let mut injected = payload.clone();
    injected["org_ref"] = json!(oneiron::EntityId::now().to_hex());
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/pairing/redeem",
        HeaderMap::new(),
        Some(injected),
    )
    .await;
    assert!(status.is_client_error());
    // Refusal did not spend the enrollment grant. The intended actor can use it.
    let (status, body) = request(
        &server,
        "POST",
        "/v1/core/pairing/redeem",
        HeaderMap::new(),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let slip = CapabilitySlip::from_token(body["token"].as_str().unwrap()).unwrap();
    assert_eq!(slip.claims.holder_ref, fixture.actor.to_hex());
    assert_eq!(slip.claims.actor_class.as_deref(), Some("human"));
    assert_eq!(slip.claims.org_ref.as_deref(), Some(org.to_hex().as_str()));
    assert_eq!(slip.claims.scope, org_scope());
    let (status, body) = request(
        &server,
        "GET",
        &format!("/v1/core/org-admin/{}/powers", org.to_hex()),
        fixture.headers(&slip),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["powers"], json!(["org:add-member"]));
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/query",
        fixture.headers(&slip),
        Some(json!({"text":"private"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/pairing/links",
        fixture.headers(&slip),
        Some(json!({"scope":Scope::top(),"lifetime_secs":600})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/pairing/redeem",
        HeaderMap::new(),
        Some(payload),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn org_ticket_requires_fixed_policy_registered_admin_and_closed_subset() {
    let fixture = Fixture::new();
    let org = oneiron::EntityId::now();
    let approved = principal(&fixture, org);
    let issue = |scope, principal| {
        fixture
            .vault
            .issue_pairing_link_for_principal(&fixture.issuer, scope, 600, principal)
    };
    assert!(issue(org_scope(), approved.clone()).is_err());
    // Policy membership alone does not manufacture a registered principal.
    fixture
        .vault
        .configure_org_admin(
            &OrgAdminPolicy::new(
                org,
                BTreeSet::from([fixture.actor]),
                BTreeSet::from([OrgAdminPower::AddMember]),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(issue(org_scope(), approved.clone()).is_err());
    fixture.register(fixture.actor);
    assert!(issue(org_scope(), approved.clone()).is_ok());
    for axis in [
        ScopeAxis::All,
        ScopeAxis::Bottom,
        verbs(&["org:add-member", "read"]),
        verbs(&["org:add-member", "core:auth"]),
        verbs(&["org:add-member", "companion:profile:read"]),
        verbs(&["org:assign-role"]),
        verbs(&["org:root"]),
        verbs(&["org:self-grant"]),
    ] {
        let mut scope = Scope::top();
        scope.verbs = axis;
        assert!(issue(scope, approved.clone()).is_err());
    }
    let other = oneiron::EntityId::now();
    fixture.register(other);
    let mut changed = approved.clone();
    changed.holder_ref = Some(other.to_hex());
    assert!(issue(org_scope(), changed).is_err());
    let mut changed = approved.clone();
    changed.holder_ref = None;
    assert!(issue(org_scope(), changed).is_err());
    let mut changed = approved.clone();
    changed.org_ref = None;
    assert!(issue(org_scope(), changed).is_err());
    let mut changed = approved;
    changed.actor_class = Some("owner".into());
    assert!(issue(org_scope(), changed).is_err());
}

#[tokio::test]
async fn mixed_org_request_is_refused_and_generic_pairing_remains_available() {
    let fixture = Fixture::new();
    let org = oneiron::EntityId::now();
    configure(&fixture, org);
    let server = Arc::new(SyncServer::new(fixture.vault.clone(), fixture.config.clone()).unwrap());
    let mut scope = org_scope();
    scope.verbs = verbs(&["org:add-member", "read"]);
    let (status, _) = request(
        &server,
        "POST",
        "/v1/core/pairing/links",
        bearer(SECRET),
        Some(json!({"scope":scope,"lifetime_secs":600,"principal":principal(&fixture, org)})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let link = fixture
        .vault
        .issue_pairing_link(&fixture.issuer, Scope::top(), 600)
        .unwrap();
    let (status, body) = request(
        &server,
        "POST",
        "/v1/core/pairing/redeem",
        HeaderMap::new(),
        Some(redemption(&link.ticket, fixture.actor, &fixture.holder)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let slip = CapabilitySlip::from_token(body["token"].as_str().unwrap()).unwrap();
    assert_eq!(slip.claims.org_ref, None);
    assert_eq!(slip.claims.actor_class, None);
    assert!(fixture.auth(&slip).unwrap().is_owner_grade());
}
