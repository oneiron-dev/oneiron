//! The connectors doors a vault serves without any admission chain (PR-A):
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps). The doors are
//! `vault.connectors.subscriptions.*`, `vault.connectors.read_grants.*`,
//! `vault.connectors.slates.redraft`, `connector.outbound.schedule`,
//! `connector.list`, `connector.status`, `vault.connectors.web.usage`, and
//! the refusal rows of every owner verb plus the caller/plain reads.
//!
//! The promises: a subscription put lists standing until revoked, and a
//! repeat revoke is idempotent; a witness-read grant flips `changed` on
//! grant and revoke and answers `changed: false` on repeats; a re-draft on
//! a host with no slate drafter answers `unavailable` and leaves the
//! slate's revision unchanged; an outbound schedule with a selection and a
//! counterparty class answers a held receipt with its gate pending (the
//! no-send half is traced by reading, not asserted: the schedule-only sink
//! fails closed); a fresh vault lists exactly the web builtin, reads an
//! unknown connector as null, and shows an empty web usage page; and every
//! owner verb refuses a person and a narrowed host-holder on the owner's own
//! credential check, while malformed bodies, unknown ids, stranger reads,
//! an unknown answer handle, a narrow on an unknown key and a verb-stripped
//! slip are each refused at their own layer.
//!
//! No admission chain runs here: no `register_connector`, no slate stamp,
//! no attestation, no tool consent. The rest moves to PR-B: `approve_once`
//! on a real Held call (no admission-free seed reaches a Held row: an
//! unregistered name is refused before governance), a holder narrow, the
//! proxy rows, a retry on a real failed reply, registered-pending
//! connectors, and the scope-signal verbs' success paths. They wait on the
//! open connector stacks (#7972 / #7975 rewrite the slate, grant and
//! admission files; #7981 / #8115 / #8116 the call and scope paths), so
//! this file asserts nothing those PRs rewrite.
//!
//! Canon `oneiron/gate/oneiron-arch-0072-foreign-actor-admission-grants-v1.md`
//! (llms-full.txt:367507) "Owner-asked re-draft | The owner asks the agent
//! to widen or tighten a connector | The drafter re-runs with the owner's
//! instruction plus its memory of past rulings and presents the delta
//! slate; one tap lands it": the re-draft test proves the contrast, that
//! with no drafter the door answers `unavailable` and the slate is
//! unchanged. Canon (llms-full.txt:367423) "Only the accepted slate grants
//! authority; a memory of past consent never widens it by itself": the
//! refusal table proves the doors around that authority grant nothing to
//! non-owners. Canon (llms-full.txt:367482) "The tap does not switch
//! anything on by itself" and (:367583) drift expansions re-ask: context
//! only; their door proofs (qualification, drift) move to PR-B with the
//! admission chain.
//!
//! The vault's keystore is a `MemoryKeystore`, which `oneiron/test-support`
//! forwards (`oneiron-keystore/test-keystore`); no cfg door is used.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_connectors_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::connector_key::{SlateToolManifest, draft_connector_slate};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
    agent: EntityId,
    agent_slip: CapabilitySlip,
    agent_token: String,
    narrowed_host_slip: CapabilitySlip,
    narrowed_host_token: String,
    readonly_slip: CapabilitySlip,
    readonly_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every holder-bound credential here binds; the holder proves it
/// per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x43; 32])
}

/// A live PERSON entity, as `graduation_demote_holder_door.rs` places one.
fn seed_person(vault: &Vault) -> EntityId {
    let who = EntityId::now();
    vault
        .put_entity(
            &who,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    who
}

/// A human credential this host mints `who`, holding `read` and `write`:
/// a person's own slip, not owner-grade.
fn mint_person_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

/// An agent credential this host mints `agent`, holding `read` and `write`.
fn mint_agent_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    agent: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("an agent credential")
}

/// A narrowed host-holder slip: holder `host`, verbs `read` + `write`, no
/// principal and no actor class. The owner root is the full host slip; this
/// narrowed child names no person, so `facade_actor` refuses it on caller
/// rows and the owner check refuses it on owner rows.
fn mint_narrowed_host_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = "host".to_owned();
    claims.actor_class = None;
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a narrowed host credential")
}

/// A read-only human credential holding `read` only: the write verbs need
/// `Write`, so the scope guard refuses it before the body decodes.
fn mint_readonly_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a read-only credential")
}

/// An enabled agent the owner creates and gives one conferring Grant, as
/// `delete_authority_served_door.rs` mints its grants.
fn agent_with_grant(vault: &Vault, owner_actor: EntityId, agent_id: &str) -> EntityId {
    let agent = EntityId::now();
    let real_proof = vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("an owner proof");
    create_agent_definition_as(
        vault,
        &real_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Connectors door test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        vault,
        &real_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    agent
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-connectors-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let who = seed_person(&vault);
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who);
    let person_token = person_slip.to_token().expect("person slip token");
    let owner_actor = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let agent = agent_with_grant(&vault, owner_actor, "connectors_door_agent");
    let agent_slip = mint_agent_credential(&owner_slip, &vault, &issuer, agent);
    let agent_token = agent_slip.to_token().expect("agent slip token");
    let narrowed_host_slip = mint_narrowed_host_credential(&owner_slip, &vault, &issuer);
    let narrowed_host_token = narrowed_host_slip.to_token().expect("narrowed host token");
    let readonly_slip = mint_readonly_credential(&owner_slip, &vault, &issuer, who);
    let readonly_token = readonly_slip.to_token().expect("read-only token");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: who,
        person_slip,
        person_token,
        agent,
        agent_slip,
        agent_token,
        narrowed_host_slip,
        narrowed_host_token,
        readonly_slip,
        readonly_token,
    }
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn person_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.person_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("holder proof")
    .to_string()
}

fn agent_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.agent_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("agent holder proof")
    .to_string()
}

fn narrowed_host_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.narrowed_host_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("narrowed host proof")
    .to_string()
}

fn readonly_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.readonly_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("read-only holder proof")
    .to_string()
}

/// One facade POST under `token` with `binding`. Every POST carries a fresh
/// `x-oneiron-invocation`: a repeat with the same one never reaches the
/// door, the facade replays the first kept reply instead.
async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let invocation = EntityId::now().to_hex();
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("x-oneiron-invocation", invocation)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post(fixture, path, &token, person_binding(fixture), body).await
}

async fn post_as_agent(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.agent_token.clone();
    post(fixture, path, &token, agent_binding(fixture), body).await
}

async fn post_as_narrowed_host(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.narrowed_host_token.clone();
    post(fixture, path, &token, narrowed_host_binding(fixture), body).await
}

async fn post_as_readonly(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.readonly_token.clone();
    post(fixture, path, &token, readonly_binding(fixture), body).await
}

/// A channel subscription put lists standing until revoked, and a repeat
/// revoke is idempotent: put answers a fresh subscription, list shows it
/// standing, revoke stops it, list shows it revoked, and revoking again
/// still answers the same subscription.
#[test]
fn subscriptions_put_list_revoke_round_trip() {
    run_on_engine_stack("connectors-subscriptions", || async {
        let fixture = setup().await;
        let agent_hex = fixture.agent.to_hex();

        let (status, put) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.subscriptions.put",
            json!({"agent": agent_hex.clone(), "channel": "slack"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner puts the subscription: {put}");
        assert_eq!(
            put["existing"].as_bool(),
            Some(false),
            "the first put is fresh: {put}"
        );
        assert_eq!(
            put["agent"].as_str(),
            Some(agent_hex.as_str()),
            "the put answers the agent: {put}"
        );
        assert_eq!(
            put["connector"].as_str(),
            Some("slack"),
            "the put answers the channel: {put}"
        );
        let subscription_hex = put["subscription"]
            .as_str()
            .expect("the put answers a subscription")
            .to_owned();
        assert!(
            !subscription_hex.is_empty(),
            "the subscription id is not empty: {put}"
        );
        let key_hex = put["connector_key"]
            .as_str()
            .expect("the put answers a connector key")
            .to_owned();
        assert!(
            !key_hex.is_empty(),
            "the connector key id is not empty: {put}"
        );

        let (status, listed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.subscriptions.list",
            json!({"agent": agent_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner lists the subscriptions: {listed}"
        );
        assert_eq!(
            listed["agent"].as_str(),
            Some(agent_hex.as_str()),
            "the list answers the agent: {listed}"
        );
        let rows = listed["subscriptions"]
            .as_array()
            .expect("the list answers subscriptions");
        assert_eq!(rows.len(), 1, "the put lists exactly once: {listed}");
        assert_eq!(
            rows[0]["subscription"].as_str(),
            Some(subscription_hex.as_str()),
            "the list shows the put subscription: {listed}"
        );
        assert_eq!(
            rows[0]["connector_key"].as_str(),
            Some(key_hex.as_str()),
            "the list shows the put key: {listed}"
        );
        assert_eq!(
            rows[0]["active"].as_bool(),
            Some(true),
            "the put subscription stands: {listed}"
        );

        let (status, revoked) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.subscriptions.revoke",
            json!({"subscription": subscription_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner revokes the subscription: {revoked}"
        );
        assert_eq!(
            revoked["subscription"].as_str(),
            Some(subscription_hex.as_str()),
            "the revoke answers the subscription: {revoked}"
        );

        let (status, listed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.subscriptions.list",
            json!({"agent": agent_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner lists after the revoke: {listed}"
        );
        let rows = listed["subscriptions"]
            .as_array()
            .expect("the list answers subscriptions");
        assert_eq!(rows.len(), 1, "the revoked row still lists: {listed}");
        assert_eq!(
            rows[0]["active"].as_bool(),
            Some(false),
            "the revoked subscription no longer stands: {listed}"
        );

        let (status, revoked_again) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.subscriptions.revoke",
            json!({"subscription": subscription_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a repeat revoke still answers: {revoked_again}"
        );
        assert_eq!(
            revoked_again["subscription"].as_str(),
            Some(subscription_hex.as_str()),
            "the repeat revoke answers the same subscription: {revoked_again}"
        );
    });
}

/// The msgpack body of a connector CONVERSATION row, as the witness-grant
/// check reads it: a map whose `import_source` is `connector`.
fn connector_conversation_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("import_source"),
            rmpv::Value::from("connector"),
        )]),
    )
    .expect("a connector conversation body encodes");
    body
}

/// A witness-read grant flips `changed` on grant and revoke and answers
/// `changed: false` on repeats: grant answers a fresh grant, a repeat
/// answers it unchanged, revoke answers it revoked, and a repeat answers
/// it unchanged.
#[test]
fn read_grants_grant_revoke_round_trip() {
    run_on_engine_stack("connectors-read-grants", || async {
        let fixture = setup().await;
        let agent_hex = fixture.agent.to_hex();
        let conversation = EntityId::now();
        fixture
            .vault
            .put_entity(
                &conversation,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 1, end: 1 },
                1,
                &connector_conversation_body(),
            )
            .expect("a live connector conversation");
        let conversation_hex = conversation.to_hex();

        let (status, granted) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.read_grants.grant",
            json!({"agent": agent_hex.clone(), "conversation": conversation_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner grants the read: {granted}");
        assert_eq!(
            granted["changed"].as_bool(),
            Some(true),
            "the first grant changes: {granted}"
        );
        let grant_hex = granted["grant_ref"]
            .as_str()
            .expect("the grant answers a grant ref")
            .to_owned();
        assert!(
            !grant_hex.is_empty(),
            "the grant ref is not empty: {granted}"
        );
        assert_eq!(
            granted["agent"].as_str(),
            Some(agent_hex.as_str()),
            "the grant answers the agent: {granted}"
        );
        assert_eq!(
            granted["conversation"].as_str(),
            Some(conversation_hex.as_str()),
            "the grant answers the conversation: {granted}"
        );
        assert_eq!(
            granted["reason"].as_str(),
            Some("connector_witness_read"),
            "the grant answers its reason: {granted}"
        );

        let (status, granted_again) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.read_grants.grant",
            json!({"agent": agent_hex.clone(), "conversation": conversation_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a repeat grant still answers: {granted_again}"
        );
        assert_eq!(
            granted_again["changed"].as_bool(),
            Some(false),
            "the repeat grant changes nothing: {granted_again}"
        );
        assert_eq!(
            granted_again["grant_ref"].as_str(),
            Some(grant_hex.as_str()),
            "the repeat grant answers the same ref: {granted_again}"
        );

        let (status, revoked) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.read_grants.revoke",
            json!({"grant_ref": grant_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner revokes the read: {revoked}");
        assert_eq!(
            revoked["changed"].as_bool(),
            Some(true),
            "the revoke changes: {revoked}"
        );
        assert_eq!(
            revoked["grant_ref"].as_str(),
            Some(grant_hex.as_str()),
            "the revoke answers the grant: {revoked}"
        );

        let (status, revoked_again) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.read_grants.revoke",
            json!({"grant_ref": grant_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a repeat revoke still answers: {revoked_again}"
        );
        assert_eq!(
            revoked_again["changed"].as_bool(),
            Some(false),
            "the repeat revoke changes nothing: {revoked_again}"
        );
    });
}

/// A re-draft on a host with no slate drafter answers `unavailable` and
/// leaves the slate's revision unchanged: the stored slate reads back at
/// the same revision after the door answers.
///
/// Canon `oneiron/gate/oneiron-arch-0072-foreign-actor-admission-grants-v1.md`
/// (llms-full.txt:367507) "Owner-asked re-draft | The owner asks the agent
/// to widen or tighten a connector | The drafter re-runs with the owner's
/// instruction plus its memory of past rulings and presents the delta
/// slate; one tap lands it".
#[test]
fn redraft_without_a_drafter_answers_unavailable() {
    run_on_engine_stack("connectors-redraft", || async {
        let fixture = setup().await;
        let manifest_row: SlateToolManifest = serde_json::from_value(json!({
            "name": "read",
            "data_class": "personal",
            "header_parameters": [],
            "resolved_input_schema": {"type": "object"},
            "destroys": false,
            "spends": false,
            "sends_outward": false,
            "legacy_ask": false,
            "read_only": true,
            "idempotent": true,
        }))
        .expect("a typed manifest row from JSON");
        let manifest = vec![manifest_row];
        let draft = draft_connector_slate(&manifest);
        let slate_id = fixture
            .vault
            .store_connector_slate(
                &manifest,
                &serde_json::to_string(&draft).expect("draft JSON"),
            )
            .expect("a stored slate");
        let before = fixture
            .vault
            .connector_slate(slate_id)
            .expect("read the slate")
            .expect("the stored slate")
            .revision();
        assert_eq!(before, 0, "a fresh slate stands at revision 0");

        let (status, reply) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.slates.redraft",
            json!({
                "slate_ref": slate_id.to_hex(),
                "expected_revision": before,
                "instruction": "Always ask before the read tool runs.",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the drafterless re-draft answers: {reply}"
        );
        assert_eq!(
            reply["status"].as_str(),
            Some("unavailable"),
            "with no drafter the re-draft is unavailable: {reply}"
        );

        let after = fixture
            .vault
            .connector_slate(slate_id)
            .expect("read the slate back")
            .expect("the stored slate")
            .revision();
        assert_eq!(
            after, before,
            "the unavailable re-draft keeps the slate revision"
        );
    });
}

/// An outbound schedule with a selection and a counterparty class answers
/// a held receipt: the agent's full body answers a non-empty intent ref,
/// the held outcome and a pending gate. The no-send half is traced by
/// reading, not asserted: the facade dispatches under the schedule-only
/// Hold window, whose sink fails closed with no channel adapter.
#[test]
fn outbound_schedule_answers_held_receipt() {
    run_on_engine_stack("connectors-schedule", || async {
        let fixture = setup().await;
        let candidate_hex = EntityId::now().to_hex();
        let (status, receipt) = post_as_agent(
            &fixture,
            "/v1/core/facade/connector.outbound.schedule",
            json!({
                "verb": "send",
                "channel": "email",
                "target": "transport:shared-inbox",
                "trigger": "agent_immediate",
                "trigger_ref": "session:connectors-doors-outbound",
                "selection": {
                    "relationship": "work_deal",
                    "candidates": [
                        {"identity_ref": candidate_hex, "face": "agent_named_address"},
                    ],
                },
                "counterparty_class": "customer",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the agent's schedule answers: {receipt}"
        );
        let intent_ref = receipt["intent_ref"].as_str().unwrap_or_default();
        assert!(
            intent_ref.starts_with("intent:"),
            "the receipt names an intent ref: {receipt}"
        );
        assert_eq!(
            receipt["outcome"].as_str(),
            Some("held"),
            "the schedule-only surface holds the send: {receipt}"
        );
        assert_eq!(
            receipt["deduped"].as_bool(),
            Some(false),
            "the fresh schedule is not a dedupe: {receipt}"
        );
        assert_eq!(
            receipt["gate_outcome"].as_str(),
            Some("pending"),
            "the ungranted send waits on the owner: {receipt}"
        );
        assert!(
            receipt["gate_decision_ref"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "the receipt names its gate decision: {receipt}"
        );
    });
}

/// A fresh vault lists exactly the web builtin, reads an unknown connector
/// as null, and shows an empty web usage page with zero totals.
#[test]
fn list_status_and_usage_on_a_fresh_vault() {
    run_on_engine_stack("connectors-list-status-usage", || async {
        let fixture = setup().await;

        let (status, listed) =
            post_as_owner(&fixture, "/v1/core/facade/connector.list", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner lists connectors: {listed}");
        let entries = listed.as_array().expect("the list answers entries");
        assert_eq!(entries.len(), 1, "a fresh vault lists one entry: {listed}");
        assert_eq!(
            entries[0]["source"].as_str(),
            Some("builtin"),
            "the entry is a builtin: {listed}"
        );
        assert_eq!(
            entries[0]["name"].as_str(),
            Some("web"),
            "the entry is the web connector: {listed}"
        );
        assert_eq!(
            entries[0]["connector"].as_str(),
            Some("web"),
            "the entry names its connector: {listed}"
        );
        assert_eq!(
            entries[0]["summary"].as_str(),
            Some("Web search and page fetch through the configured provider."),
            "the entry carries its summary: {listed}"
        );
        assert_eq!(
            entries[0]["verbs"],
            json!(["search", "fetch"]),
            "the entry carries its tools: {listed}"
        );

        let (status, described) = post_as_owner(
            &fixture,
            "/v1/core/facade/connector.status",
            json!({"name": "nope"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unknown connector reads back: {described}"
        );
        assert!(
            described.is_null(),
            "an unknown connector reads back null: {described}"
        );

        let (status, usage) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.web.usage",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the web usage: {usage}");
        assert_eq!(
            usage["rows"],
            json!([]),
            "a fresh vault shows no usage rows: {usage}"
        );
        assert_eq!(
            usage["total_cost_micro_usd"].as_u64(),
            Some(0),
            "a fresh vault shows zero cost: {usage}"
        );
        assert_eq!(
            usage["unpriced"].as_u64(),
            Some(0),
            "a fresh vault shows zero unpriced rows: {usage}"
        );
    });
}

/// The connectors refusal table: a person and a narrowed host-holder are
/// refused on every owner verb; malformed bodies are refused before any
/// owner check; unknown ids are not found; a stranger reads no call; an
/// unknown answer handle and an unknown narrow key are not found; a
/// verb-stripped slip lacks the scope; and `host` is never an actor class.
///
/// Canon `oneiron/gate/oneiron-arch-0072-foreign-actor-admission-grants-v1.md`
/// (llms-full.txt:367423) "Only the accepted slate grants authority; a
/// memory of past consent never widens it by itself".
#[test]
fn connectors_refusal_table() {
    run_on_engine_stack("connectors-refusals", || async {
        let fixture = setup().await;
        assert_eq!(
            fixture.person_slip.claims.holder_ref,
            fixture.person.to_hex(),
            "the person's credential binds the person"
        );
        assert_eq!(
            fixture.agent_slip.claims.holder_ref,
            fixture.agent.to_hex(),
            "the agent's credential binds the agent"
        );
        assert_eq!(
            fixture.narrowed_host_slip.claims.holder_ref, "host",
            "the narrowed slip still names the host holder"
        );

        let unknown_hex = EntityId::now().to_hex();
        let other_hex = EntityId::now().to_hex();
        let digest_hex = "11".repeat(32);
        let owner_rows: Vec<(&str, Value)> = vec![
            (
                "vault.connectors.calls.approve_once",
                json!({"call_ref": unknown_hex.clone(), "approval_digest": digest_hex.clone()}),
            ),
            (
                "vault.connectors.proxy.admit",
                json!({"actor": unknown_hex.clone()}),
            ),
            (
                "vault.connectors.proxy.revoke_write",
                json!({"actor": unknown_hex.clone(), "key": other_hex.clone(), "revision": 0}),
            ),
            (
                "vault.connectors.read_grants.grant",
                json!({"agent": unknown_hex.clone(), "conversation": other_hex.clone()}),
            ),
            (
                "vault.connectors.read_grants.revoke",
                json!({"grant_ref": unknown_hex.clone()}),
            ),
            (
                "vault.connectors.replies.retry_failed",
                json!({"attempt_ref": unknown_hex.clone()}),
            ),
            (
                "vault.connectors.slates.accept_revision",
                json!({"slate_ref": unknown_hex.clone(), "expected_revision": 0}),
            ),
            (
                "vault.connectors.slates.defer_revision",
                json!({"signal_ref": unknown_hex.clone(), "deferral": "not_now"}),
            ),
            (
                "vault.connectors.slates.reask_issuer",
                json!({
                    "connector": "nope",
                    "slot": "route",
                    "issuer": "issuer-now",
                    "credential_ref": "cred-now",
                    "expected_generation": 0,
                    "witness": "observed at the door",
                }),
            ),
            (
                "vault.connectors.slates.redraft",
                json!({
                    "slate_ref": unknown_hex.clone(),
                    "expected_revision": 0,
                    "instruction": "tighten",
                }),
            ),
            ("vault.connectors.slates.revision_offers", json!({})),
            (
                "vault.connectors.slates.scope_outcome",
                json!({
                    "signal_ref": unknown_hex.clone(),
                    "linked_ruling": "ruling",
                    "outcome": "rejected",
                }),
            ),
            (
                "vault.connectors.subscriptions.put",
                json!({"agent": unknown_hex.clone(), "channel": "slack"}),
            ),
            (
                "vault.connectors.subscriptions.list",
                json!({"agent": unknown_hex.clone()}),
            ),
            (
                "vault.connectors.subscriptions.revoke",
                json!({"subscription": unknown_hex.clone()}),
            ),
            ("vault.connectors.web.usage", json!({})),
        ];
        for (verb, input) in &owner_rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status_person, refused_person) =
                post_as_person(&fixture, &path, input.clone()).await;
            assert_eq!(
                status_person,
                StatusCode::FORBIDDEN,
                "a person is refused {verb}: {refused_person}"
            );
            assert_eq!(
                refused_person["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused_person}"
            );
            assert_eq!(
                refused_person["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the refusal names the owner: {refused_person}"
            );

            let (status_narrowed, refused_narrowed) =
                post_as_narrowed_host(&fixture, &path, input.clone()).await;
            assert_eq!(
                status_narrowed,
                StatusCode::FORBIDDEN,
                "a narrowed host-holder is refused {verb}: {refused_narrowed}"
            );
            assert_eq!(
                refused_narrowed["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused_narrowed}"
            );
            assert_eq!(
                refused_narrowed["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the refusal names the owner: {refused_narrowed}"
            );
        }

        let malformed_rows: Vec<(&str, Value)> = vec![
            ("vault.connectors.subscriptions.put", json!({})),
            (
                "vault.connectors.calls.approve_once",
                json!({"call_ref": unknown_hex.clone()}),
            ),
            ("vault.connectors.slates.narrow", json!({})),
        ];
        for (verb, input) in &malformed_rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_person(&fixture, &path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a malformed body is refused on {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {refused}"
            );
            assert!(
                refused["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with("invalid SDK request: ")),
                "the refusal names the undecodable body: {refused}"
            );
        }

        let missing_rows: Vec<(&str, Value)> = vec![
            (
                "vault.connectors.read_grants.grant",
                json!({"agent": unknown_hex.clone(), "conversation": other_hex.clone()}),
            ),
            (
                "vault.connectors.read_grants.revoke",
                json!({"grant_ref": unknown_hex.clone()}),
            ),
            (
                "vault.connectors.replies.retry_failed",
                json!({"attempt_ref": unknown_hex.clone()}),
            ),
            (
                "vault.connectors.slates.accept_revision",
                json!({"slate_ref": unknown_hex.clone(), "expected_revision": 0}),
            ),
            (
                "vault.connectors.slates.defer_revision",
                json!({"signal_ref": unknown_hex.clone(), "deferral": "not_now"}),
            ),
            (
                "vault.connectors.slates.scope_outcome",
                json!({
                    "signal_ref": unknown_hex.clone(),
                    "linked_ruling": "ruling",
                    "outcome": "rejected",
                }),
            ),
            (
                "vault.connectors.slates.redraft",
                json!({
                    "slate_ref": unknown_hex.clone(),
                    "expected_revision": 0,
                    "instruction": "tighten",
                }),
            ),
        ];
        for (verb, input) in &missing_rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status, missing) = post_as_owner(&fixture, &path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "an unknown id is not found on {verb}: {missing}"
            );
            assert_eq!(
                missing["error"]["code"].as_str(),
                Some("NOT_FOUND"),
                "the refusal names its code: {missing}"
            );
            assert_eq!(
                missing["error"]["message"].as_str(),
                Some("entity not found"),
                "the refusal names the missing row: {missing}"
            );
        }

        let (status, not_held) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.calls.approve_once",
            json!({"call_ref": unknown_hex.clone(), "approval_digest": digest_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unheld call is not approved: {not_held}"
        );
        assert_eq!(
            not_held["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {not_held}"
        );
        assert_eq!(
            not_held["error"]["message"].as_str(),
            Some("connector call is not held"),
            "the refusal names the unheld call: {not_held}"
        );

        for verb in ["connector.call_status", "connector.call_source_rows"] {
            let path = format!("/v1/core/facade/{verb}");
            let (status, stranger) =
                post_as_person(&fixture, &path, json!({"call_ref": unknown_hex.clone()})).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "a stranger reads no call on {verb}: {stranger}"
            );
            assert_eq!(
                stranger["error"]["code"].as_str(),
                Some("NOT_FOUND"),
                "the refusal names its code: {stranger}"
            );
            assert_eq!(
                stranger["error"]["message"].as_str(),
                Some("no connector call with this ref is yours to read"),
                "the refusal hides the ref: {stranger}"
            );
        }

        let (status, answer) = post_as_person(
            &fixture,
            "/v1/core/facade/connector.answer",
            json!({"handle": "no-such-handle", "answers": []}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unknown answer handle is not found: {answer}"
        );
        assert_eq!(
            answer["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {answer}"
        );
        assert_eq!(
            answer["error"]["message"].as_str(),
            Some("no live connector question with this handle is yours to answer"),
            "the refusal names the missing round: {answer}"
        );

        let (status, narrow) = post_as_agent(
            &fixture,
            "/v1/core/facade/vault.connectors.slates.narrow",
            json!({
                "key_ref": unknown_hex.clone(),
                "expected_revision": 0,
                "narrows": {"read": "always_ask"},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a narrow on an unknown key is not found: {narrow}"
        );
        assert_eq!(
            narrow["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {narrow}"
        );
        assert_eq!(
            narrow["error"]["message"].as_str(),
            Some("entity not found"),
            "the refusal names the missing key: {narrow}"
        );

        let (status, scoped) = post_as_readonly(
            &fixture,
            "/v1/core/facade/vault.connectors.subscriptions.put",
            json!({"agent": unknown_hex.clone(), "channel": "slack"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a verb-stripped slip is refused the write: {scoped}"
        );
        assert_eq!(
            scoped["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {scoped}"
        );
        assert_eq!(
            scoped["error"]["message"].as_str(),
            Some("request does not have the required scope"),
            "the refusal names the missing scope: {scoped}"
        );

        let (status, offers) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.connectors.slates.revision_offers",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists no waiting revisions: {offers}"
        );
        assert_eq!(
            offers["offers"],
            json!([]),
            "a fresh vault holds no revision offers: {offers}"
        );

        let mut host_claims = fixture.owner_slip.claims.clone();
        host_claims.slip_id = next_slip_id();
        host_claims.parent_id = None;
        host_claims.holder_ref = fixture.person.to_hex();
        host_claims.actor_class = Some("host".to_owned());
        host_claims.binding_key = holder_key().verifying_key().to_bytes();
        let host_mint = fixture
            .vault
            .mint_capability_slip(&fixture.issuer, host_claims);
        assert!(
            host_mint.is_err(),
            "`host` is never an actor class, so its mint fails"
        );
    });
}
