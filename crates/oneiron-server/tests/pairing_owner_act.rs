//! A pairing link and a slip revocation are owner acts, and a holder
//! revokes its own slips (FIX 8216, lead ruling FIX-8216-PAIRING-OWNER-ACT
//! = A: links need the owner; a revoke is owner or self).
//!
//! `POST /v1/core/pairing/links` with no `machine` answer used to take any
//! owner-grade credential, and `POST /v1/core/slips/revoke` revoked any slip
//! id for the same callers. #8012 (OWNER-GRADE-IS-NOT-OWNERSHIP) made both
//! doors ask for the owner. This file pins the ruling on top: the owner
//! makes every link and revokes any slip; anyone else gets 403 on the link
//! door, and revokes only the slips its own logged mints name.
//!
//! Red on this PR's base (#8012's head): `a_non_owner_revokes_its_own_slip`
//! fails, because a holder's revoke of its own slip answers 403 there. On
//! main, `a_non_owner_top_scope_slip_gets_403_on_the_link_door` and
//! `a_non_owner_cannot_revoke_another_holders_slip` fail instead (200). The
//! owner's link and the owner's revoke pass everywhere.
//!
//! The owner acts on its host-root credential, the established self-hosted
//! owner path. Every other credential is a real logged mint at top scope,
//! bound to its holder's own key, presented with a fresh holder proof.
//! Deterministic: an in-process vault and router (`oneshot`, no TCP ports,
//! no sleeps, no models); each test owns its vault.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test pairing_owner_act`. It calls no
//! test door; it needs `oneiron/test-support` for `MemoryKeystore`.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::Scope;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// A credential's token and the proof its holder signs for each request.
enum Holder {
    /// The host root: the issuer proves it.
    Root,
    /// A minted slip: its holder's own key proves it.
    Key(SigningKey),
}

struct Credential {
    slip: CapabilitySlip,
    holder: Holder,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: Credential,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("pairing-owner-act".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    Fixture {
        _dir: dir,
        vault,
        app: build_app(server),
        issuer,
        owner: Credential {
            slip: root,
            holder: Holder::Root,
        },
    }
}

/// A logged top-scope slip for `holder_ref` of class `class`: owner grade by
/// its scope, and no ownership (it is neither the owner's own human slip nor
/// the host root).
fn top_slip(fixture: &Fixture, holder_ref: &str, class: &str, seed: u8) -> Credential {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = fixture.owner.slip.claims.clone();
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = holder_ref.to_owned();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some(class.to_owned());
    assert_eq!(claims.scope, Scope::top(), "a top-scope slip");
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint a top-scope slip");
    Credential {
        slip,
        holder: Holder::Key(key),
    }
}

/// A registered agent PERSON's top-scope agent slip.
fn agent(fixture: &Fixture, name: &str, seed: u8) -> Credential {
    let principal = fixture
        .vault
        .ensure_agent_principal(name)
        .expect("agent principal");
    top_slip(fixture, &principal.to_hex(), "agent", seed)
}

/// A registered PERSON who is not the owner, on a top-scope human slip.
fn other_person(fixture: &Fixture, seed: u8) -> Credential {
    let person = EntityId::now();
    fixture
        .vault
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"another person",
        )
        .expect("register another person");
    top_slip(fixture, &person.to_hex(), "human", seed)
}

fn binding(fixture: &Fixture, credential: &Credential) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = match &credential.holder {
        Holder::Root => fixture
            .issuer
            .binding_proof(&credential.slip, challenge.as_bytes())
            .expect("root holder proof"),
        Holder::Key(key) => {
            let transcript = credential
                .slip
                .binding_transcript(challenge.as_bytes())
                .expect("holder binding transcript");
            key.sign(&transcript).to_bytes().to_vec()
        }
    };
    json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)}).to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    credential: &Credential,
    body: Value,
) -> (StatusCode, Value) {
    let token = credential.slip.to_token().expect("slip token");
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding(fixture, credential))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn link_request() -> Value {
    json!({"scope": Scope::top(), "lifetime_secs": 600})
}

async fn revoke(fixture: &Fixture, by: &Credential, slip_id: [u8; 32]) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/slips/revoke",
        by,
        json!({"slip_id": slip_id}),
    )
    .await
}

fn live(fixture: &Fixture, credential: &Credential) -> bool {
    fixture
        .vault
        .capability_slip_id_is_live(&credential.slip.claims.slip_id)
        .expect("slip liveness")
}

#[tokio::test]
async fn a_non_owner_top_scope_slip_gets_403_on_the_link_door() {
    let fixture = setup();
    for (who, credential) in [
        ("an agent", agent(&fixture, "pairing-owner-act-agent", 0x31)),
        ("another person", other_person(&fixture, 0x32)),
    ] {
        let (status, body) = post(
            &fixture,
            "/v1/core/pairing/links",
            &credential,
            link_request(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{who}'s top-scope slip makes no pairing link: {body}"
        );
        assert!(body.get("code").is_none(), "{who} got no link: {body}");
    }
}

#[tokio::test]
async fn the_owner_makes_a_pairing_link() {
    let fixture = setup();
    let (status, body) = post(
        &fixture,
        "/v1/core/pairing/links",
        &fixture.owner,
        link_request(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the owner's link: {body}");
    assert!(
        body["code"].is_string(),
        "the owner's link has a code: {body}"
    );
}

#[tokio::test]
async fn a_non_owner_cannot_revoke_another_holders_slip() {
    let fixture = setup();
    let first = agent(&fixture, "pairing-owner-act-first", 0x41);
    let second = agent(&fixture, "pairing-owner-act-second", 0x42);
    let person = other_person(&fixture, 0x43);
    for (who, by) in [("an agent", &first), ("another person", &person)] {
        let (status, body) = revoke(&fixture, by, second.slip.claims.slip_id).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{who} revokes no other holder's slip: {body}"
        );
        assert!(live(&fixture, &second), "the other holder's slip stands");
        // An id no logged mint names is not the caller's either, and its
        // answer is the same refusal.
        let (status, body) = revoke(&fixture, by, [0x5a; 32]).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{who} revokes no unlogged id: {body}"
        );
    }
    let (status, body) = revoke(&fixture, &first, fixture.owner.slip.claims.slip_id).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent revokes no root: {body}"
    );
    assert!(live(&fixture, &fixture.owner), "the root stands");
}

#[tokio::test]
async fn a_non_owner_revokes_its_own_slip() {
    let fixture = setup();
    let name = "pairing-owner-act-self";
    let held = agent(&fixture, name, 0x51);
    let spare = agent(&fixture, name, 0x52);
    assert_eq!(held.slip.claims.holder_ref, spare.slip.claims.holder_ref);
    let (status, body) = revoke(&fixture, &held, spare.slip.claims.slip_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a holder revokes its own slip: {body}"
    );
    assert_eq!(body["revoked"], json!(true), "{body}");
    assert!(!live(&fixture, &spare), "the revoked slip is gone");
    assert!(live(&fixture, &held), "the caller's own slip stands");
}

#[tokio::test]
async fn the_owner_revokes_any_slip() {
    let fixture = setup();
    let held = agent(&fixture, "pairing-owner-act-held", 0x61);
    let (status, body) = revoke(&fixture, &fixture.owner, held.slip.claims.slip_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner revokes an agent's slip: {body}"
    );
    assert!(!live(&fixture, &held), "the agent's slip is gone");
}
