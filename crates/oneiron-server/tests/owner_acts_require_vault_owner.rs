//! Owner acts check vault ownership, not slip grade (FIX-LIST
//! OWNER-GRADE-IS-NOT-OWNERSHIP H2-H8; the lead's ruling 15 Nov 02:2x).
//!
//! A full-vault slip is a scope, not a Grant naming an owner act, and its
//! grade says nothing of whose it is. Seven doors took the act for any
//! owner-grade credential. Each now asks the owner door, so a live,
//! unattenuated, reusable full-vault slip the host minted to a person who
//! does not own the vault, or to an agent, is refused and the act does not
//! happen:
//! - H2 `POST /v1/core/batch` and the `remember` verb commit below owner: an
//!   agent definition the owner turned off stays off, and a TURN that calls
//!   itself a platform announcement is stored as its writer's, not the
//!   platform's;
//! - H3 `POST /v1/core/memory/verbs/delete` goes to the delete authority, not
//!   the owner path: the owner's NOTE stays;
//! - H4 the voice bank (`GET /v1/ai/voices/{voice}`; its four other routes
//!   share the same door) is not read;
//! - H5 `POST /v1/core/org-admin/{org}/policy` configures nothing;
//! - H6 `POST /v1/core/pairing/links` issues no link (no ownerless fallback);
//! - H7 `POST /v1/core/slips/revoke` revokes nothing;
//! - H8 `GET /ws` opens no full replication socket.
//!
//! The owner's own credentials pass every door: his full slip on one of his
//! devices, and the host's root slip his CLI acts on.
//!
//! On main each door checks only the credential's grade, so every
//! `non_owner_*` case is red there (the act happens) and green with the owner
//! door. The `owner_*` cases pass on both.
//!
//! Deterministic: one in-process vault, server and router per case
//! (`oneshot`; H8 serves the same router on a loopback port for the socket
//! upgrade). No model is configured and none is called.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test owner_acts_require_vault_owner`
//! (the target's required feature: it brings `MemoryKeystore`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::federation::{OrgAdminPolicy, OrgAdminPower, Scope};
use oneiron::note::TakeTarget;
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tower::ServiceExt;

/// The holders that are not the owner, each on a live full-vault slip.
const NON_OWNER_CLASSES: [&str; 2] = ["human", "agent"];

/// A distinct slip id for each credential a case mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A distinct holder key for each credential a case mints.
fn next_holder_key() -> SigningKey {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    SigningKey::from_bytes(&[NEXT.fetch_add(1, Ordering::Relaxed); 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One self-hosted vault with its embedded owner and its served router.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    _host: AiHost,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in before the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("this install's signing key");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("owner-acts-require-vault-owner".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    // No model is configured; the voice bank's routes are served all the same.
    let (server, host) = AiHost::attach(server, None).await;
    let app = build_app(Arc::new(server));
    Fixture {
        _dir: dir,
        vault,
        _host: host,
        app,
        issuer,
        root,
        owner,
    }
}

/// A live person of this vault who is not its owner.
fn person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    person
}

/// A credential a case presents: a slip and its holder's proof of
/// possession, fresh for each request.
struct Caller {
    slip: CapabilitySlip,
    /// The holder's key; `None` for the host root, which the host proves.
    key: Option<SigningKey>,
}

impl Caller {
    /// One request's `x-oneiron-binding` header for this credential.
    fn binding(&self, fx: &Fixture) -> String {
        let timestamp = fx.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match &self.key {
            Some(key) => {
                let transcript = self
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("binding transcript");
                key.sign(&transcript).to_bytes().to_vec()
            }
            None => fx
                .issuer
                .binding_proof(&self.slip, challenge.as_bytes())
                .expect("root holder proof"),
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)}).to_string()
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.slip.to_token().expect("slip token"))
    }
}

/// A live, logged, reusable full-vault slip the host mints `holder` at
/// `class`: the root's own top scope and no caveat, so it is owner grade
/// whoever holds it.
fn full_slip(fx: &Fixture, holder: EntityId, class: &str) -> Caller {
    let key = next_holder_key();
    let mut claims = fx.root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    let slip = fx
        .vault
        .mint_capability_slip(&fx.issuer, claims)
        .expect("a live full-vault slip");
    Caller {
        slip,
        key: Some(key),
    }
}

/// A full-vault slip held by someone who does not own the vault: a person
/// (`class` "human") or a registered agent (`class` "agent").
fn non_owner(fx: &Fixture, class: &str) -> Caller {
    let holder = if class == "human" {
        person(&fx.vault)
    } else {
        fx.vault
            .ensure_agent_principal("owner-acts-agent")
            .expect("a registered agent principal")
    };
    assert_ne!(holder, fx.owner, "the {class} holder is not the owner");
    full_slip(fx, holder, class)
}

/// The owner's own full slip, on one of his devices.
fn owner_device(fx: &Fixture) -> Caller {
    full_slip(fx, fx.owner, "human")
}

/// The self-hosted root slip the owner's CLI acts on.
fn host_root(fx: &Fixture) -> Caller {
    Caller {
        slip: fx.root.clone(),
        key: None,
    }
}

/// The owner's credentials, each named for its failure message.
fn owner_callers(fx: &Fixture) -> [(&'static str, Caller); 2] {
    [
        ("the owner's device slip", owner_device(fx)),
        ("the host root", host_root(fx)),
    ]
}

/// One request over the router as `caller`: its status and its JSON body
/// (`Null` when it has none).
async fn send(
    fx: &Fixture,
    caller: &Caller,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", caller.bearer())
        .header("x-oneiron-binding", caller.binding(fx));
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = fx
        .app
        .clone()
        .oneshot(request.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// H2: vault.batch / memory.remember commit as the owner only for the owner.

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.owner_acts",
        "Owner acts fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The AGENT_DEF codec refuses an empty provenance map.
        rmpv::Value::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

fn next(
    definition: &AgentDefinition,
    version: &str,
    edit: impl FnOnce(&mut AgentDefinition),
) -> AgentDefinition {
    let mut next = definition.clone();
    next.version = version.to_owned();
    edit(&mut next);
    next
}

/// The stored body as the JSON a core put carries.
fn json_of(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => Value::from(*flag),
        rmpv::Value::Integer(n) => n
            .as_i64()
            .map_or_else(|| Value::from(n.as_u64().expect("integer")), Value::from),
        rmpv::Value::F32(n) => Value::from(f64::from(*n)),
        rmpv::Value::F64(n) => Value::from(*n),
        rmpv::Value::String(text) => Value::from(text.as_str().expect("utf-8")),
        rmpv::Value::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        rmpv::Value::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

fn definition_entity(id: &EntityId, definition: &AgentDefinition) -> Value {
    let bytes = oneiron::agent_def::encode_agent_definition(definition).expect("encode");
    let body = rmpv::decode::read_value(&mut bytes.as_slice()).expect("decode");
    json!({ "id": id.to_hex(), "entity_type": ENTITY_TYPE_AGENT_DEF, "body": json_of(&body) })
}

/// An agent definition the owner turned off: disabled, rejected, retracted.
fn revoked_definition(fx: &Fixture) -> EntityId {
    let id = EntityId::now();
    let now = fx.vault.now_recorded_at();
    let revoked = next(&running_definition(), "1.0.1", |def| {
        def.enabled = false;
        def.approval_status = ClaimApprovalStatus::Rejected;
        def.lifecycle_status = ClaimLifecycleStatus::Retracted;
    });
    fx.vault
        .put_agent_definition(
            &id,
            &revoked,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("seed the turned-off definition");
    assert_eq!(stored(fx, &id), Some(revoked), "the definition is off");
    id
}

fn stored(fx: &Fixture, id: &EntityId) -> Option<AgentDefinition> {
    fx.vault
        .get_agent_definition(id)
        .expect("read the definition")
}

fn is_on(fx: &Fixture, id: &EntityId) -> bool {
    stored(fx, id).is_some_and(|def| def.enabled)
}

/// Puts the definition back on (enabled, approved, active) over the batch
/// route or the `remember` verb.
async fn turn_back_on(fx: &Fixture, caller: &Caller, door: &str, id: &EntityId) -> StatusCode {
    let restored = next(&running_definition(), "1.0.2", |_| {});
    let entity = definition_entity(id, &restored);
    let (uri, body) = match door {
        "batch" => ("/v1/core/batch", json!({ "entities": [entity] })),
        _ => (
            "/v1/core/memory/verbs/remember",
            json!({ "entity": entity }),
        ),
    };
    let (status, body) = send(fx, caller, "POST", uri, Some(body)).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::FORBIDDEN,
        "{door}: {status} {body}"
    );
    status
}

#[test]
fn non_owner_full_scope_slip_cannot_turn_an_agent_definition_back_on() {
    run_on_engine_stack("owner-acts-h2-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let caller = non_owner(&fx, class);
            for door in ["batch", "remember"] {
                let id = revoked_definition(&fx);
                let status = turn_back_on(&fx, &caller, door, &id).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "a non-owner {class}'s full-vault slip commits as the owner over {door}"
                );
                assert!(
                    !is_on(&fx, &id),
                    "a non-owner {class} turned the owner's agent definition back on over {door}"
                );
            }
        }
    });
}

#[test]
fn owner_credentials_turn_an_agent_definition_back_on() {
    run_on_engine_stack("owner-acts-h2-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            for door in ["batch", "remember"] {
                let id = revoked_definition(&fx);
                let status = turn_back_on(&fx, &caller, door, &id).await;
                assert_eq!(status, StatusCode::OK, "{name} over {door}");
                assert!(is_on(&fx, &id), "{name} turns it back on over {door}");
            }
        }
    });
}

// H2: a batch TURN publishes as the platform only for the owner (blind
// review F1 of #8012): one owner proof decides the batch's grade and its
// announcement authority.

/// A TURN whose body calls itself a platform announcement and bylines its
/// writer.
fn announcement_turn(id: &EntityId) -> Value {
    json!({
        "id": id.to_hex(),
        "entity_type": ENTITY_TYPE_TURN,
        "body": {
            "txt": "Maintenance begins at 22:00 UTC.",
            "message_type": "platform_announcement",
            "spkr": "owen",
        },
    })
}

/// One field of a stored TURN body, `None` when it has none.
fn turn_field<'a>(body: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    body.as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Whether a stored TURN body speaks as the platform.
fn platform_styled(body: &rmpv::Value) -> bool {
    let text = |key: &str| turn_field(body, key).and_then(rmpv::Value::as_str);
    text("message_type") == Some("platform_announcement")
        || text("spkr") == Some("platform")
        || turn_field(body, "platform_voice").and_then(rmpv::Value::as_bool) == Some(true)
}

/// Puts the announcement TURN over the batch route or the `remember` verb:
/// the status and the body the vault stored, `None` when it stored none.
async fn announce(fx: &Fixture, caller: &Caller, door: &str) -> (StatusCode, Option<rmpv::Value>) {
    let id = EntityId::now();
    let entity = announcement_turn(&id);
    let (uri, body) = match door {
        "batch" => ("/v1/core/batch", json!({ "entities": [entity] })),
        _ => (
            "/v1/core/memory/verbs/remember",
            json!({ "entity": entity }),
        ),
    };
    let (status, reply) = send(fx, caller, "POST", uri, Some(body)).await;
    let stored = fx
        .vault
        .get(&id)
        .expect("read the TURN")
        .map(|bytes| rmpv::decode::read_value(&mut bytes.as_slice()).expect("decode the TURN"));
    assert!(
        status == StatusCode::OK || stored.is_none(),
        "{door}: a refused TURN is stored: {status} {reply}"
    );
    (status, stored)
}

#[test]
fn non_owner_full_scope_slip_cannot_publish_as_the_platform() {
    run_on_engine_stack("owner-acts-h2-announcement-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let caller = non_owner(&fx, class);
            for door in ["batch", "remember"] {
                let (status, stored) = announce(&fx, &caller, door).await;
                // A person's TURN is an ordinary below-owner put. An agent's
                // may meet a refusal of its own; either way no TURN of theirs
                // is stored as the platform's.
                if class == "human" {
                    assert_eq!(
                        status,
                        StatusCode::OK,
                        "a non-owner person's TURN is an ordinary write over {door}"
                    );
                }
                if let Some(body) = stored {
                    assert!(
                        !platform_styled(&body),
                        "a non-owner {class}'s full-vault slip published as the platform over {door}: {body}"
                    );
                    assert_eq!(
                        turn_field(&body, "spkr").and_then(rmpv::Value::as_str),
                        Some("owen"),
                        "a non-owner {class}'s TURN keeps its own byline over {door}"
                    );
                }
            }
        }
    });
}

#[test]
fn owner_credentials_publish_as_the_platform() {
    run_on_engine_stack("owner-acts-h2-announcement-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            for door in ["batch", "remember"] {
                let (status, stored) = announce(&fx, &caller, door).await;
                assert_eq!(status, StatusCode::OK, "{name} over {door}");
                let body = stored.expect("the owner's TURN is stored");
                assert!(
                    platform_styled(&body),
                    "{name}'s announcement speaks as the platform over {door}: {body}"
                );
            }
        }
    });
}

// H3: core memory delete takes the owner path only for the owner.

/// A NOTE the owner wrote about a person: its full hex id.
fn owners_note(fx: &Fixture) -> String {
    let subject = person(&fx.vault);
    fx.vault
        .memory(fx.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(subject), "the owner's own take")
        .expect("the owner writes a NOTE")
        .id_hex
}

fn deleted(fx: &Fixture, note: &str) -> bool {
    fx.vault
        .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
        .expect("shell read")
}

async fn delete(fx: &Fixture, caller: &Caller, note: &str) -> (StatusCode, Value) {
    send(
        fx,
        caller,
        "POST",
        "/v1/core/memory/verbs/delete",
        Some(json!({ "id": note })),
    )
    .await
}

#[test]
fn non_owner_full_scope_slip_cannot_delete_on_the_owner_path() {
    run_on_engine_stack("owner-acts-h3-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let note = owners_note(&fx);
            let caller = non_owner(&fx, class);
            let (status, body) = delete(&fx, &caller, &note).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip deletes the owner's NOTE as the owner: {body}"
            );
            assert!(
                !deleted(&fx, &note),
                "a non-owner {class} deleted the owner's NOTE"
            );
        }
    });
}

#[test]
fn owner_credentials_delete_on_the_owner_path() {
    run_on_engine_stack("owner-acts-h3-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            let note = owners_note(&fx);
            let (status, body) = delete(&fx, &caller, &note).await;
            assert_eq!(status, StatusCode::OK, "{name}: {body}");
            assert!(deleted(&fx, &note), "{name} deletes the owner's NOTE");
        }
    });
}

// H4: the voice bank is the owner's.

/// A voice the bank holds nothing of: a caller the door admits reads the
/// bank and is answered 404 `unknown_voice`.
const VOICE: &str = "owner-acts-voice";

async fn view_voice(fx: &Fixture, caller: &Caller) -> (StatusCode, Value) {
    send(fx, caller, "GET", &format!("/v1/ai/voices/{VOICE}"), None).await
}

#[test]
fn non_owner_full_scope_slip_cannot_read_the_voice_bank() {
    run_on_engine_stack("owner-acts-h4-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let caller = non_owner(&fx, class);
            let (status, body) = view_voice(&fx, &caller).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip reads the owner's voice bank: {body}"
            );
        }
    });
}

#[test]
fn owner_credentials_read_the_voice_bank() {
    run_on_engine_stack("owner-acts-h4-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            let (status, body) = view_voice(&fx, &caller).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{name}: {body}");
            assert!(
                body.to_string().contains("unknown_voice"),
                "{name} reads the bank, which holds nothing of the voice: {body}"
            );
        }
    });
}

// H5: who administers an organization is the owner's to fix.

/// A policy naming a fresh organization and one administrator.
fn org_policy(fx: &Fixture) -> OrgAdminPolicy {
    OrgAdminPolicy::new(
        EntityId::now(),
        BTreeSet::from([person(&fx.vault)]),
        BTreeSet::from([OrgAdminPower::AddMember]),
    )
    .expect("an organization policy")
}

async fn configure_org(fx: &Fixture, caller: &Caller, policy: &OrgAdminPolicy) -> StatusCode {
    let uri = format!("/v1/core/org-admin/{}/policy", policy.org_ref().to_hex());
    let body = serde_json::to_value(policy).expect("policy json");
    let (status, body) = send(fx, caller, "POST", &uri, Some(body)).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::FORBIDDEN,
        "{status} {body}"
    );
    status
}

#[test]
fn non_owner_full_scope_slip_cannot_configure_an_organization() {
    run_on_engine_stack("owner-acts-h5-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let caller = non_owner(&fx, class);
            let policy = org_policy(&fx);
            let status = configure_org(&fx, &caller, &policy).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip configures an organization"
            );
            assert!(
                fx.vault.org_admin_policy(policy.org_ref()).is_err(),
                "a non-owner {class} fixed who administers an organization"
            );
        }
    });
}

#[test]
fn owner_credentials_configure_an_organization() {
    run_on_engine_stack("owner-acts-h5-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            let policy = org_policy(&fx);
            let status = configure_org(&fx, &caller, &policy).await;
            assert_eq!(status, StatusCode::OK, "{name}");
            assert_eq!(
                fx.vault.org_admin_policy(policy.org_ref()).ok(),
                Some(policy),
                "{name} configures the organization"
            );
        }
    });
}

// H6: a pairing link mints a slip, so only the owner makes one.

async fn pairing_link(fx: &Fixture, caller: &Caller) -> (StatusCode, Value) {
    let holder = person(&fx.vault);
    let body = json!({
        "scope": Scope::top(),
        "lifetime_secs": 600,
        "principal": { "holder_ref": holder.to_hex(), "actor_class": "human" },
    });
    send(fx, caller, "POST", "/v1/core/pairing/links", Some(body)).await
}

#[test]
fn non_owner_full_scope_slip_cannot_make_a_pairing_link() {
    run_on_engine_stack("owner-acts-h6-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let caller = non_owner(&fx, class);
            let (status, body) = pairing_link(&fx, &caller).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip makes a pairing link: {body}"
            );
            assert!(
                body.get("code").is_none(),
                "a non-owner {class} got a pairing code: {body}"
            );
        }
    });
}

#[test]
fn owner_credentials_make_a_pairing_link() {
    run_on_engine_stack("owner-acts-h6-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            let (status, body) = pairing_link(&fx, &caller).await;
            assert_eq!(status, StatusCode::OK, "{name}: {body}");
            assert!(
                body["code"].is_string(),
                "{name} gets a pairing code: {body}"
            );
        }
    });
}

// H7: revoking a slip is the owner's act.

/// A live full-vault slip of another person: the slip a revocation targets.
fn target_slip(fx: &Fixture) -> [u8; 32] {
    let target = full_slip(fx, person(&fx.vault), "human")
        .slip
        .claims
        .slip_id;
    assert!(live(fx, &target), "the target slip is live");
    target
}

fn live(fx: &Fixture, slip_id: &[u8; 32]) -> bool {
    fx.vault
        .capability_slip_id_is_live(slip_id)
        .expect("slip liveness")
}

async fn revoke(fx: &Fixture, caller: &Caller, slip_id: &[u8; 32]) -> (StatusCode, Value) {
    send(
        fx,
        caller,
        "POST",
        "/v1/core/slips/revoke",
        Some(json!({ "slip_id": slip_id })),
    )
    .await
}

#[test]
fn non_owner_full_scope_slip_cannot_revoke_a_slip() {
    run_on_engine_stack("owner-acts-h7-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let target = target_slip(&fx);
            let caller = non_owner(&fx, class);
            let (status, body) = revoke(&fx, &caller, &target).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip revokes a slip: {body}"
            );
            assert!(
                live(&fx, &target),
                "a non-owner {class} revoked another person's slip"
            );
        }
    });
}

#[test]
fn owner_credentials_revoke_a_slip() {
    run_on_engine_stack("owner-acts-h7-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            let target = target_slip(&fx);
            let (status, body) = revoke(&fx, &caller, &target).await;
            assert_eq!(status, StatusCode::OK, "{name}: {body}");
            assert!(!live(&fx, &target), "{name} revokes the slip");
        }
    });
}

// H8: full replication over `/ws` is the owner's.

/// Upgrades `/ws` (no MCP subprotocol) as `caller` on a loopback port that
/// serves the fixture's router: `Ok` when the upgrade is taken, else the
/// HTTP status it is refused with.
async fn upgrade_sync_socket(fx: &Fixture, caller: &Caller) -> Result<(), u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("the loopback address");
    let app = fx.app.clone();
    let serving = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve the router");
    });
    let mut request = format!("ws://{address}/ws")
        .into_client_request()
        .expect("upgrade request");
    request.headers_mut().insert(
        "authorization",
        caller.bearer().parse().expect("authorization header"),
    );
    request.headers_mut().insert(
        "x-oneiron-binding",
        caller.binding(fx).parse().expect("binding header"),
    );
    let outcome = match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _response)) => {
            drop(socket);
            Ok(())
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Err(response.status().as_u16())
        }
        Err(other) => panic!("the upgrade failed below HTTP: {other}"),
    };
    serving.abort();
    outcome
}

#[test]
fn non_owner_full_scope_slip_cannot_open_full_replication() {
    run_on_engine_stack("owner-acts-h8-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let caller = non_owner(&fx, class);
            assert_eq!(
                upgrade_sync_socket(&fx, &caller).await,
                Err(StatusCode::FORBIDDEN.as_u16()),
                "a non-owner {class}'s full-vault slip opens full replication"
            );
        }
    });
}

#[test]
fn owner_credentials_open_full_replication() {
    run_on_engine_stack("owner-acts-h8-owner", || async {
        let fx = setup().await;
        for (name, caller) in owner_callers(&fx) {
            assert_eq!(
                upgrade_sync_socket(&fx, &caller).await,
                Ok(()),
                "{name} opens full replication"
            );
        }
    });
}
