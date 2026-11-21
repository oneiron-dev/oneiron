//! FIX SETTINGS-SET-DOOR-CO-OWNER: the Setting primitive's facade doors (`vault.settings.set`,
//! `.get` and `.list`) take a live co-owner, on their own owner-grade slip, as the owner, as the
//! owner doors the setting keys replaced took one (`/v1/owner` takes any live Owner). The engine
//! door took only the embedded owner's own proof and refused every other human (`agent_of`).
//!
//! Each case owns its vault: an in-process vault served over the real router (`oneshot`, no TCP
//! ports, no sleeps, no models), shared with a co-owner and a Member whose founding invitations
//! are accepted. Each of them presents a slip this host mints from its root slip's claims, with
//! the holder's proof on each request; the owner acts on the host-root credential.
//!
//! Red at the base (opus-setting/setting-standing 30536924a2eb): the co-owner's set, get and
//! list answer 403 FORBIDDEN. Guards (they pass there too): the owner sets and reads; a Member on
//! a slip of the same shape is refused, since the Member owns nothing.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test setting_doors_co_owner`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A plain owner-set boolean key with a vault row (the run review's agent read).
const KEY: &str = "memory.run_review.agent_may_read";
const SET: &str = "vault.settings.set";
const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SHARED: u64 = 47;

/// The key every minted credential binds; its holder proves it on each request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5C; 32])
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    co_owner_slip: CapabilitySlip,
    member_slip: CapabilitySlip,
}

/// A live PERSON `id`.
fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

/// `person`'s proof as this vault authenticates a live person, owner or not.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `who` accepts its founding invitation at `role`.
fn accept(vault: &Vault, who: EntityId, role: Role) {
    let who_proof = proof(vault, who);
    let invitation = vault
        .shared_invitations(&who_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&who_proof, SHARED, &invitation.id)
        .expect("the invitation is accepted");
}

/// The slip this host mints `who` as a human from its root slip's claims: every scope the root
/// holds, bound to [`holder_key`]. For a live owner it is that owner's own unattenuated slip.
fn human_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
    slip_id: u8,
) -> CapabilitySlip {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = [slip_id; 32];
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a human slip")
}

/// A vault served over the real router, shared by its owner with a co-owner and a Member, both
/// founding invitations accepted.
fn setup(auth_secret: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(auth_secret.into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    vault
        .prepare_install_signing()
        .expect("this install's signing keys");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (co_owner, member) = (EntityId::now(), EntityId::now());
    person(&vault, co_owner);
    person(&vault, member);
    let founding = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[
                founding(owner, Role::Owner),
                founding(co_owner, Role::Owner),
                founding(member, Role::Member),
            ],
            1,
        )
        .expect("a shared vault");
    accept(&vault, co_owner, Role::Owner);
    accept(&vault, member, Role::Member);
    let co_owner_slip = human_slip(&vault, &issuer, co_owner, 0x41);
    let member_slip = human_slip(&vault, &issuer, member, 0x42);
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        co_owner_slip,
        member_slip,
    }
}

impl Fixture {
    /// `POST /v1/core/facade/{verb}` under `token` with the holder's `binding` proof.
    async fn post(
        &self,
        verb: &str,
        token: &str,
        binding: String,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("facade response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    /// `verb` as the owner, on the host-root credential.
    async fn as_owner(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let token = self.owner_slip.to_token().expect("owner token");
        self.post(verb, &token, binding, body).await
    }

    /// `verb` on `slip`, with [`holder_key`]'s proof.
    async fn as_holder(
        &self,
        slip: &CapabilitySlip,
        verb: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let binding = holder_proof(slip, &holder_key(), self.vault.now_recorded_at())
            .expect("holder proof")
            .to_string();
        let token = slip.to_token().expect("token");
        self.post(verb, &token, binding, body).await
    }
}

fn set_body(value: bool) -> Value {
    json!({ "key": KEY, "scope": {"kind": "vault"}, "value": value })
}

fn get_body() -> Value {
    json!({ "key": KEY })
}

fn list_body() -> Value {
    json!({ "prefix": KEY })
}

/// Whether a `vault.settings.list` answer names [`KEY`].
fn lists_key(body: &Value) -> bool {
    body["keys"]
        .as_array()
        .is_some_and(|keys| keys.iter().any(|entry| entry["key"] == KEY))
}

fn assert_forbidden(status: StatusCode, body: &Value, what: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{what}: {body}");
}

/// Red: the co-owner sets the key on their own slip, and the owner reads the co-owner's row in
/// force. 403 at the base.
#[test]
fn a_co_owner_sets_a_key_on_their_own_slip() {
    run_on_engine_stack("setting-co-owner-set", || async {
        let fixture = setup("setting-co-owner-set");
        let (status, body) = fixture
            .as_holder(&fixture.co_owner_slip, SET, set_body(true))
            .await;
        assert_eq!(status, StatusCode::OK, "the co-owner's set: {body}");
        assert_eq!(body["status"].as_str(), Some("applied"), "{body}");
        assert_eq!(body["value"], json!(true), "{body}");

        let (status, body) = fixture.as_owner(GET, get_body()).await;
        assert_eq!(status, StatusCode::OK, "the owner's read: {body}");
        assert_eq!(
            body["value"],
            json!(true),
            "the co-owner's row is in force: {body}"
        );
    });
}

/// Red: the co-owner reads the owner's row and lists the key on their own slip. 403 at the base.
#[test]
fn a_co_owner_reads_and_lists_a_key_on_their_own_slip() {
    run_on_engine_stack("setting-co-owner-read", || async {
        let fixture = setup("setting-co-owner-read");
        let (status, body) = fixture.as_owner(SET, set_body(true)).await;
        assert_eq!(status, StatusCode::OK, "the owner's set: {body}");
        assert_eq!(body["status"].as_str(), Some("applied"), "{body}");

        let (status, body) = fixture
            .as_holder(&fixture.co_owner_slip, GET, get_body())
            .await;
        assert_eq!(status, StatusCode::OK, "the co-owner's read: {body}");
        assert_eq!(
            body["value"],
            json!(true),
            "the co-owner reads the owner's row: {body}"
        );

        let (status, body) = fixture
            .as_holder(&fixture.co_owner_slip, LIST, list_body())
            .await;
        assert_eq!(status, StatusCode::OK, "the co-owner's list: {body}");
        assert!(lists_key(&body), "the co-owner's list names {KEY}: {body}");
    });
}

/// Guard: a Member on a slip of the same shape owns nothing, so each door still refuses them, and
/// the Member's refused set leaves the owner's row in force.
#[test]
fn a_member_on_a_slip_of_the_same_shape_is_refused() {
    run_on_engine_stack("setting-member-refused", || async {
        let fixture = setup("setting-member-refused");
        let (status, body) = fixture.as_owner(SET, set_body(false)).await;
        assert_eq!(status, StatusCode::OK, "the owner's set: {body}");

        let (status, body) = fixture
            .as_holder(&fixture.member_slip, SET, set_body(true))
            .await;
        assert_forbidden(status, &body, "the Member's set");
        let (status, body) = fixture
            .as_holder(&fixture.member_slip, GET, get_body())
            .await;
        assert_forbidden(status, &body, "the Member's read");
        let (status, body) = fixture
            .as_holder(&fixture.member_slip, LIST, list_body())
            .await;
        assert_forbidden(status, &body, "the Member's list");

        let (status, body) = fixture.as_owner(GET, get_body()).await;
        assert_eq!(status, StatusCode::OK, "the owner's read: {body}");
        assert_eq!(
            body["value"],
            json!(false),
            "the owner's row stays in force: {body}"
        );
    });
}
