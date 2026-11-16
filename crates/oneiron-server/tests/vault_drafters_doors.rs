//! The vault's own drafters (ARCH-0053), entered as the SDK enters them:
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps). The doors are the owner's
//! `vault.drafters.list`, `.status`, `.policy.set` and `.revert`, and the
//! agent's `.list_as` and `.revert_as`, each under the agent's own live
//! Grant naming the act (`drafter_read` / `drafter_revert`).
//!
//! The promise this file proves (P3): the training data never leaves the
//! vault. The owner's list and status answers carry ids, states, counts and
//! times only, never conversation text, tokens, weights or keys
//! (`crates/oneiron/src/drafter/types.rs:1-4`), and the drafter events are
//! content-free (`types.rs:196`). Test 2 proves it at the door: exact key
//! sets on both answers, the policy echoing its excluded worlds and its
//! recipe as data, and no text/token/tokens/prompt/content/weights/key
//! member anywhere in either answer.
//!
//! Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:359`
//! (mirror `llms-full.txt:345891`): "the training data never leaves the
//! vault".
//!
//! P1 (a new drafter activates itself only on a held-out win) and P2 (any
//! slowdown rolls it back; earlier drafters stay available for revert) stay
//! unproven here: no door verb activates or observes, and no seeder mints
//! the qualified retained versions a revert needs (FIX-LIST row DRAFTER-DOOR-SEEDER).
//!
//! Each test owns a fresh vault; agents are owner-created definitions with
//! owner-minted Grants, calling on their own agent-class slips.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_drafters_doors`.
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
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
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

/// The six drafter verbs, as the facade routes them.
const LIST: &str = "vault.drafters.list";
const LIST_AS: &str = "vault.drafters.list_as";
const POLICY_SET: &str = "vault.drafters.policy.set";
const REVERT: &str = "vault.drafters.revert";
const REVERT_AS: &str = "vault.drafters.revert_as";
const STATUS: &str = "vault.drafters.status";

/// `facade_actor`'s refusal for a slip that names no principal.
const PRINCIPAL_MESSAGE: &str = "facade routes bind writes to an authenticated principal";
/// `admit_in_txn`'s refusal for an agent with no live Grant naming the act.
const NO_GRANT_MESSAGE: &str = "no live Grant from a live owner names this agent and lists the act";
/// `ApiError::forbidden_scope`'s fixed text, for scope and record scope alike.
const SCOPE_MESSAGE: &str = "request does not have the required scope";
/// `facade_json`'s refusal for a body that is not JSON.
const MALFORMED_MESSAGE: &str = "invalid JSON request body";
/// `validate_input`'s decode refusal, before the path it names.
const DECODE_PREFIX: &str = "invalid SDK request: ";
/// The policy write's refusal of a set at a moved revision.
const STALE_POLICY_MESSAGE: &str = "the drafter policy moved since it was read";
/// The revert's refusal of a version the vault never held.
const UNKNOWN_VERSION_MESSAGE: &str = "entity not found";

/// The record bound that narrows the record-narrowed slip.
const NARROW_RECORD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The owner doors' common refusal: `verb` is the vault owner's.
fn owner_message(verb: &str) -> String {
    format!("{verb} is the vault owner's")
}

/// `agent_of`'s refusal for a caller that is no agent.
fn no_agent_message(verb: &str, grant: &str) -> String {
    format!("{verb} takes an agent's own live Grant naming {grant}: the caller is no agent")
}

/// A device vault, its server and app, and the owner, its proof and a person.
struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    person: EntityId,
}

/// One minted slip with its holder key and presented token.
struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
    token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key one credential binds; its holder proves it per request.
fn holder_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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
                auth_secret: Some("vault-drafters-doors".into()),
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
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
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
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner,
        owner_proof,
        person,
    }
}

/// An enabled agent definition the owner creates; its id, grantless.
fn seed_agent_definition(fixture: &Fixture, agent_id: &str) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "drafters door test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    agent
}

/// The owner's live Grant for `agent` naming `verbs`; it confers.
fn seed_agent_grant(fixture: &Fixture, agent: EntityId, agent_id: &str, verbs: &[&str]) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
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
}

/// A credential this host mints: the root's claims narrowed to `holder`,
/// `actor`, `verbs` and `records`, proved by the key `seed` names.
fn mint_credential(
    fixture: &Fixture,
    holder: &str,
    actor: Option<&str>,
    verbs: BTreeSet<String>,
    records: BTreeSet<String>,
    seed: u8,
) -> Credential {
    let key = holder_key(seed);
    let mut claims = fixture.owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_owned();
    claims.actor_class = actor.map(str::to_owned);
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(verbs);
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("a credential token");
    Credential { slip, key, token }
}

fn read_write_verbs() -> BTreeSet<String> {
    BTreeSet::from(["read".to_owned(), "write".to_owned()])
}

fn read_only_verbs() -> BTreeSet<String> {
    BTreeSet::from(["read".to_owned()])
}

/// The person's own human slip, holding `read` and `write`.
fn person_credential(fixture: &Fixture) -> Credential {
    mint_credential(
        fixture,
        &fixture.person.to_hex(),
        Some("human"),
        read_write_verbs(),
        BTreeSet::new(),
        0x5B,
    )
}

/// An agent's own slip for `agent`, holding `read` and `write`.
fn agent_credential(fixture: &Fixture, agent: EntityId, seed: u8) -> Credential {
    mint_credential(
        fixture,
        &agent.to_hex(),
        Some("agent"),
        read_write_verbs(),
        BTreeSet::new(),
        seed,
    )
}

/// A slip with no principal and no actor class, holding `read` and `write`.
fn unbound_credential(fixture: &Fixture) -> Credential {
    mint_credential(
        fixture,
        "host",
        None,
        read_write_verbs(),
        BTreeSet::new(),
        0x1D,
    )
}

/// A human slip whose holder names no row in the vault.
fn stranger_credential(fixture: &Fixture) -> Credential {
    mint_credential(
        fixture,
        &EntityId::now().to_hex(),
        Some("human"),
        read_write_verbs(),
        BTreeSet::new(),
        0x2A,
    )
}

/// The person's own human slip, holding `read` alone.
fn read_only_credential(fixture: &Fixture) -> Credential {
    mint_credential(
        fixture,
        &fixture.person.to_hex(),
        Some("human"),
        read_only_verbs(),
        BTreeSet::new(),
        0x5C,
    )
}

/// The person's own human slip, narrowed to one record it never reads here.
fn narrowed_credential(fixture: &Fixture) -> Credential {
    mint_credential(
        fixture,
        &fixture.person.to_hex(),
        Some("human"),
        read_write_verbs(),
        BTreeSet::from([NARROW_RECORD.to_owned()]),
        0x5D,
    )
}

/// A revert body that decodes: `unknown` at binding generation 0.
fn revert_body(unknown: &str) -> Value {
    json!({"version": unknown, "expected_binding_generation": 0})
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

fn slip_binding(fixture: &Fixture, slip: &CapabilitySlip, key: &SigningKey) -> String {
    holder_proof(slip, key, fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
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
    let answer: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, answer)
}

async fn post_raw(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    raw: &str,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(raw.to_owned()))
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
    let answer: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, answer)
}

async fn post_as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let binding = owner_binding(fixture);
    let path = format!("/v1/core/facade/{verb}");
    let token = fixture.owner_token.clone();
    post(fixture, &path, &token, binding, body).await
}

async fn post_as_credential(
    fixture: &Fixture,
    verb: &str,
    body: Value,
    credential: &Credential,
) -> (StatusCode, Value) {
    let binding = slip_binding(fixture, &credential.slip, &credential.key);
    let path = format!("/v1/core/facade/{verb}");
    post(fixture, &path, &credential.token, binding, body).await
}

async fn post_raw_as_owner(fixture: &Fixture, verb: &str, raw: &str) -> (StatusCode, Value) {
    let binding = owner_binding(fixture);
    let path = format!("/v1/core/facade/{verb}");
    let token = fixture.owner_token.clone();
    post_raw(fixture, &path, &token, binding, raw).await
}

fn assert_refusal(
    status: StatusCode,
    answer: &Value,
    expected_status: StatusCode,
    expected_code: &str,
    expected_message: &str,
    what: &str,
) {
    assert_eq!(status, expected_status, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some(expected_code),
        "{what}: {answer}"
    );
    assert_eq!(
        answer["error"]["message"].as_str(),
        Some(expected_message),
        "{what}: {answer}"
    );
}

fn assert_decode_refusal(status: StatusCode, answer: &Value, field: &str, what: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some("BAD_REQUEST"),
        "{what}: {answer}"
    );
    let message = answer["error"]["message"]
        .as_str()
        .expect("a decode refusal names its shape");
    assert!(message.starts_with(DECODE_PREFIX), "{what}: {answer}");
    assert!(message.contains(field), "{what}: {answer}");
}

/// The answer is an object with exactly `keys`.
fn assert_keys(answer: &Value, keys: &[&str], what: &str) {
    let object = answer
        .as_object()
        .unwrap_or_else(|| panic!("{what} answers an object: {answer}"));
    let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut wanted: Vec<&str> = keys.to_vec();
    wanted.sort_unstable();
    assert_eq!(actual, wanted, "{what} answers exactly its keys: {answer}");
}

/// The answer carries no training member at any depth: no `text`, `token`,
/// `tokens`, `prompt`, `content`, `weights` or `key` member. Names match
/// exactly, so `tokenizer` is not `token`.
fn assert_no_training_members(answer: &Value, what: &str) {
    const FORBIDDEN: [&str; 7] = [
        "text", "token", "tokens", "prompt", "content", "weights", "key",
    ];
    fn walk(node: &Value, trail: String, answer: &Value, what: &str) {
        match node {
            Value::Object(map) => {
                for (name, member) in map {
                    assert!(
                        !FORBIDDEN.contains(&name.as_str()),
                        "{what} carries no training member, but {trail}.{name} does: {answer}"
                    );
                    walk(member, format!("{trail}.{name}"), answer, what);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, format!("{trail}[{index}]"), answer, what);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    walk(answer, "$".to_owned(), answer, what);
}

/// The policy round-trips at its revision, and a set at a revision the
/// vault left behind is refused and changes nothing.
#[test]
fn policy_set_round_trip_and_revision_guards() {
    run_on_engine_stack("drafters-policy-round-trip", || async {
        let fixture = setup().await;
        let (status, before) = post_as_owner(&fixture, STATUS, json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the fresh status: {before}"
        );
        assert_keys(
            &before,
            &["policy", "bindings", "served", "events"],
            "the fresh status",
        );
        assert_keys(
            &before["policy"],
            &[
                "enabled",
                "excluded_worlds",
                "recipe",
                "revision",
                "set_by",
                "set_at",
            ],
            "the default policy",
        );
        assert_eq!(
            before["policy"]["enabled"].as_bool(),
            Some(true),
            "the default policy is on: {before}"
        );
        assert_eq!(
            before["policy"]["revision"].as_u64(),
            Some(0),
            "the default policy is revision 0: {before}"
        );
        assert_eq!(
            before["policy"]["excluded_worlds"],
            json!([]),
            "the default policy excludes nothing: {before}"
        );
        assert!(
            before["policy"]["recipe"].is_null(),
            "the default policy names no recipe: {before}"
        );
        assert!(
            before["policy"]["set_by"].is_null(),
            "the default policy names no setter: {before}"
        );
        assert!(
            before["policy"]["set_at"].is_null(),
            "the default policy names no set time: {before}"
        );
        assert_eq!(
            before["bindings"],
            json!([]),
            "no bindings without versions: {before}"
        );
        assert_eq!(
            before["served"],
            json!([]),
            "nothing serves without versions: {before}"
        );
        assert_eq!(
            before["events"],
            json!([]),
            "no events before the first set: {before}"
        );

        let (status, policy) = post_as_owner(
            &fixture,
            POLICY_SET,
            json!({"expected_revision": 0, "enabled": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner sets the policy: {policy}");
        assert_eq!(
            policy["revision"].as_u64(),
            Some(1),
            "the set moves the revision: {policy}"
        );
        assert_eq!(
            policy["enabled"].as_bool(),
            Some(true),
            "the set keeps the switch on: {policy}"
        );
        assert_eq!(
            policy["set_by"],
            json!({"owner": fixture.owner.to_hex()}),
            "the set names the owner: {policy}"
        );
        assert!(
            policy["set_at"].is_u64(),
            "the set names its time: {policy}"
        );

        let (status, after) = post_as_owner(&fixture, STATUS, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads it back: {after}");
        assert_eq!(
            after["policy"], policy,
            "status shows the set policy: {after}"
        );
        assert_eq!(
            after["events"].as_array().map(Vec::len),
            Some(1),
            "the set records one event: {after}"
        );

        let (status, refused) = post_as_owner(
            &fixture,
            POLICY_SET,
            json!({"expected_revision": 0, "enabled": false}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            STALE_POLICY_MESSAGE,
            "a set at the old revision is refused",
        );

        let (status, same) = post_as_owner(&fixture, STATUS, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads it back: {same}");
        assert_eq!(
            same["policy"], policy,
            "the refused set changes nothing: {same}"
        );
        assert_eq!(
            same["events"].as_array().map(Vec::len),
            Some(1),
            "the refused set records nothing: {same}"
        );
    });
}

/// The owner's list and status answers on a vault with no drafter versions
/// never carry the training: exact key sets, the policy echoing its excluded
/// worlds and its recipe as data, and no training member anywhere in either
/// answer. The list, binding and served row shapes are not door-proven here:
/// with no versions there are no rows, only their exact emptiness.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:359`
/// (mirror `llms-full.txt:345891`): "the training data never leaves the
/// vault".
#[test]
fn owner_list_and_status_are_content_free_without_versions() {
    run_on_engine_stack("drafters-content-free", || async {
        let fixture = setup().await;
        let world = EntityId::now().to_hex();
        let recipe = json!({
            "id": "nightly-test",
            "revision": {"repository": "example.com/drafters", "revision": "abc123"},
            "settings": {"epochs": 3},
            "gpu_seconds": 3600,
            "device_memory_mib": 8192,
        });
        let (status, policy) = post_as_owner(
            &fixture,
            POLICY_SET,
            json!({
                "expected_revision": 0,
                "enabled": true,
                "excluded_worlds": [world.clone()],
                "recipe": recipe.clone(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner sets worlds and recipe: {policy}"
        );
        assert_eq!(
            policy["excluded_worlds"],
            json!([world]),
            "the policy keeps the excluded world: {policy}"
        );
        assert_eq!(
            policy["recipe"], recipe,
            "the policy keeps the recipe as data: {policy}"
        );
        assert_keys(
            &policy,
            &[
                "enabled",
                "excluded_worlds",
                "recipe",
                "revision",
                "set_by",
                "set_at",
            ],
            "the set policy",
        );
        assert_keys(
            &policy["recipe"],
            &[
                "id",
                "revision",
                "settings",
                "gpu_seconds",
                "device_memory_mib",
            ],
            "the recipe as data",
        );
        assert_keys(
            &policy["recipe"]["revision"],
            &["repository", "revision"],
            "the recipe revision",
        );

        let (status, listed) = post_as_owner(&fixture, LIST, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner lists versions: {listed}");
        assert_eq!(
            listed,
            json!([]),
            "no version rows on a fresh vault: {listed}"
        );

        let (status, current) = post_as_owner(&fixture, STATUS, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the status: {current}");
        assert_keys(
            &current,
            &["policy", "bindings", "served", "events"],
            "the status",
        );
        assert_eq!(
            current["policy"], policy,
            "status shows the set policy: {current}"
        );
        let events = current["events"]
            .as_array()
            .expect("status answers its events");
        assert_eq!(events.len(), 1, "the set records one event: {current}");
        assert_keys(
            &events[0],
            &["id", "at", "by", "kind", "change"],
            "the policy event",
        );

        assert_no_training_members(&listed, "list");
        assert_no_training_members(&current, "status");
    });
}

/// The agent doors open only under a live Grant naming the act: the
/// owner's own credential and a person are no agent, a grantless agent
/// names no Grant, and a grant for the other act is none for this one.
/// Person legs run first: under the red branch's class-gate fault this
/// test fails at its first leg.
#[test]
fn agent_doors_need_a_grant_naming_the_act() {
    run_on_engine_stack("drafters-agent-grant", || async {
        let fixture = setup().await;
        let person_cred = person_credential(&fixture);
        let unbound_cred = unbound_credential(&fixture);
        let bare = seed_agent_definition(&fixture, "drafters-bare-agent");
        let bare_cred = agent_credential(&fixture, bare, 0xB1);
        let reader = seed_agent_definition(&fixture, "drafters-reader");
        seed_agent_grant(
            &fixture,
            reader,
            "drafters-reader",
            &["read", "drafter_read"],
        );
        let reader_cred = agent_credential(&fixture, reader, 0xB2);
        let reverter = seed_agent_definition(&fixture, "drafters-reverter");
        seed_agent_grant(
            &fixture,
            reverter,
            "drafters-reverter",
            &["read", "drafter_revert"],
        );
        let reverter_cred = agent_credential(&fixture, reverter, 0xB3);
        let unknown = EntityId::now().to_hex();
        let agent_verbs = [(LIST_AS, "drafter_read"), (REVERT_AS, "drafter_revert")];

        for (verb, grant) in agent_verbs {
            let body = if verb == LIST_AS {
                json!({})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) = post_as_credential(&fixture, verb, body, &person_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &no_agent_message(verb, grant),
                &format!("a person is no agent on {verb}"),
            );
        }
        for (verb, grant) in agent_verbs {
            let body = if verb == LIST_AS {
                json!({})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) = post_as_owner(&fixture, verb, body).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &no_agent_message(verb, grant),
                &format!("the owner's own credential is no agent on {verb}"),
            );
        }
        for (verb, _) in agent_verbs {
            let body = if verb == LIST_AS {
                json!({})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) = post_as_credential(&fixture, verb, body, &unbound_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                PRINCIPAL_MESSAGE,
                &format!("an unbound slip is refused {verb}"),
            );
        }
        for (verb, _) in agent_verbs {
            let body = if verb == LIST_AS {
                json!({})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) = post_as_credential(&fixture, verb, body, &bare_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                NO_GRANT_MESSAGE,
                &format!("a grantless agent is refused {verb}"),
            );
        }

        let (status, refused) =
            post_as_credential(&fixture, REVERT_AS, revert_body(&unknown), &reader_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            NO_GRANT_MESSAGE,
            "a read grant is no revert grant",
        );
        let (status, refused) =
            post_as_credential(&fixture, LIST_AS, json!({}), &reverter_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            NO_GRANT_MESSAGE,
            "a revert grant is no read grant",
        );

        let (status, listed) = post_as_credential(&fixture, LIST_AS, json!({}), &reader_cred).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a read-granted agent lists: {listed}"
        );
        assert_eq!(
            listed,
            json!([]),
            "no version rows on a fresh vault: {listed}"
        );
        let (status, refused) =
            post_as_credential(&fixture, REVERT_AS, revert_body(&unknown), &reverter_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            UNKNOWN_VERSION_MESSAGE,
            "a revert-granted agent reaches the unknown version",
        );
    });
}

/// A revert of a version the vault never held is not found, for the owner
/// and the granted agent alike, and records nothing.
#[test]
fn revert_refuses_unknown_version() {
    run_on_engine_stack("drafters-revert-unknown", || async {
        let fixture = setup().await;
        let reverter = seed_agent_definition(&fixture, "drafters-revert-unknown");
        seed_agent_grant(
            &fixture,
            reverter,
            "drafters-revert-unknown",
            &["read", "drafter_revert"],
        );
        let reverter_cred = agent_credential(&fixture, reverter, 0xB4);
        let unknown = EntityId::now().to_hex();

        let (status, refused) = post_as_owner(&fixture, REVERT, revert_body(&unknown)).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            UNKNOWN_VERSION_MESSAGE,
            "the owner finds no unknown version",
        );
        let (status, refused) =
            post_as_credential(&fixture, REVERT_AS, revert_body(&unknown), &reverter_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            UNKNOWN_VERSION_MESSAGE,
            "a revert-granted agent finds no unknown version",
        );

        let (status, current) = post_as_owner(&fixture, STATUS, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the status: {current}");
        assert_eq!(
            current["events"],
            json!([]),
            "the refused reverts record nothing: {current}"
        );
    });
}

/// The status lists each set as one policy event, oldest first, and the
/// cursor keeps only the events after it; with no versions there is
/// nothing bound and nothing served.
#[test]
fn status_lists_bindings_served_events_and_honours_the_cursor() {
    run_on_engine_stack("drafters-status-cursor", || async {
        let fixture = setup().await;
        let owner_hex = fixture.owner.to_hex();
        let (status, first_policy) = post_as_owner(
            &fixture,
            POLICY_SET,
            json!({"expected_revision": 0, "enabled": true}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner sets revision 1: {first_policy}"
        );
        assert_eq!(
            first_policy["revision"].as_u64(),
            Some(1),
            "the first set moves the revision: {first_policy}"
        );
        let (status, second_policy) = post_as_owner(
            &fixture,
            POLICY_SET,
            json!({"expected_revision": 1, "enabled": false}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner sets revision 2: {second_policy}"
        );

        let (status, current) = post_as_owner(&fixture, STATUS, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner reads the status: {current}");
        assert_eq!(
            current["policy"], second_policy,
            "status shows the second set: {current}"
        );
        assert_eq!(
            current["bindings"],
            json!([]),
            "no bindings without versions: {current}"
        );
        assert_eq!(
            current["served"],
            json!([]),
            "nothing serves without versions: {current}"
        );
        let events = current["events"]
            .as_array()
            .expect("status answers its events");
        assert_eq!(events.len(), 2, "two sets, two events: {current}");
        for (event, revision) in events.iter().zip([1, 2]) {
            assert_keys(
                event,
                &["id", "at", "by", "kind", "change"],
                "a policy event",
            );
            assert_eq!(
                event["by"],
                json!({"owner": owner_hex.clone()}),
                "the event names the owner: {current}"
            );
            assert_eq!(
                event["kind"],
                json!({"policy": {"revision": revision}}),
                "the event names its revision, oldest first: {current}"
            );
            assert!(
                event["change"].is_null(),
                "a set that moves no binding changes none: {current}"
            );
        }

        let first_id = events[0]["id"]
            .as_str()
            .expect("the first event id")
            .to_owned();
        let (status, tail) =
            post_as_owner(&fixture, STATUS, json!({"events_after": first_id})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads after the cursor: {tail}"
        );
        let tail_events = tail["events"].as_array().expect("cursor answers events");
        assert_eq!(
            tail_events.len(),
            1,
            "the cursor keeps only the second: {tail}"
        );
        assert_eq!(
            tail_events[0]["id"], events[1]["id"],
            "the cursor keeps the second event: {tail}"
        );
    });
}

/// Every fresh-vault refusal of the six doors from the layer that owns it: the owner
/// precheck, the credential's own actor, the agent's class and Grant, the
/// unknown version, the moved policy, the body's shape and the slip's
/// scope. Owner rows run first: under the red branch's owner-message fault
/// this table fails at its first row, before any crossed row.
#[test]
fn table_refusals_fresh_vault() {
    run_on_engine_stack("drafters-refusal-table", || async {
        let fixture = setup().await;
        let person_cred = person_credential(&fixture);
        let unbound_cred = unbound_credential(&fixture);
        let stranger_cred = stranger_credential(&fixture);
        let read_only_cred = read_only_credential(&fixture);
        let narrowed_cred = narrowed_credential(&fixture);
        let bare = seed_agent_definition(&fixture, "drafters-table-bare");
        let bare_cred = agent_credential(&fixture, bare, 0xB5);
        let reader = seed_agent_definition(&fixture, "drafters-table-reader");
        seed_agent_grant(
            &fixture,
            reader,
            "drafters-table-reader",
            &["read", "drafter_read"],
        );
        let reader_cred = agent_credential(&fixture, reader, 0xB6);
        let reverter = seed_agent_definition(&fixture, "drafters-table-reverter");
        seed_agent_grant(
            &fixture,
            reverter,
            "drafters-table-reverter",
            &["read", "drafter_revert"],
        );
        let reverter_cred = agent_credential(&fixture, reverter, 0xB7);
        let unknown = EntityId::now().to_hex();

        // The owner precheck refuses every non-owner: a person on all four
        // owner doors, then one bare agent, one stranger and one agent per
        // grant. Every body decodes, so each 403 is the precheck's.
        let owner_rows: Vec<(&str, Value)> = vec![
            (LIST, json!({})),
            (STATUS, json!({})),
            (POLICY_SET, json!({"expected_revision": 0, "enabled": true})),
            (REVERT, revert_body(&unknown)),
        ];
        for (verb, body) in owner_rows {
            let (status, refused) = post_as_credential(&fixture, verb, body, &person_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &owner_message(verb),
                &format!("a person is refused {verb}"),
            );
        }
        let (status, refused) = post_as_credential(&fixture, LIST, json!({}), &bare_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &owner_message(LIST),
            "a grantless agent is refused vault.drafters.list",
        );
        let (status, refused) =
            post_as_credential(&fixture, STATUS, json!({}), &stranger_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &owner_message(STATUS),
            "a stranger is refused vault.drafters.status",
        );
        let (status, refused) =
            post_as_credential(&fixture, REVERT, revert_body(&unknown), &reader_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &owner_message(REVERT),
            "a read-granted agent is refused vault.drafters.revert",
        );
        let (status, refused) = post_as_credential(
            &fixture,
            POLICY_SET,
            json!({"expected_revision": 0, "enabled": true}),
            &reverter_cred,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &owner_message(POLICY_SET),
            "a revert-granted agent is refused vault.drafters.policy.set",
        );

        // The agent doors: an unbound slip names no principal; the owner's
        // own credential acts as the owner-human and is still no agent, as
        // is a person; a grantless agent names no Grant.
        let agent_verbs = [(LIST_AS, "drafter_read"), (REVERT_AS, "drafter_revert")];
        for (verb, grant) in agent_verbs {
            let body = if verb == LIST_AS {
                json!({})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) =
                post_as_credential(&fixture, verb, body.clone(), &unbound_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                PRINCIPAL_MESSAGE,
                &format!("an unbound slip is refused {verb}"),
            );
            let (status, refused) = post_as_owner(&fixture, verb, body.clone()).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &no_agent_message(verb, grant),
                &format!("the owner's own credential is no agent on {verb}"),
            );
            let (status, refused) =
                post_as_credential(&fixture, verb, body.clone(), &person_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &no_agent_message(verb, grant),
                &format!("a person is no agent on {verb}"),
            );
            let (status, refused) = post_as_credential(&fixture, verb, body, &bare_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                NO_GRANT_MESSAGE,
                &format!("a grantless agent is refused {verb}"),
            );
        }
        let (status, refused) =
            post_as_credential(&fixture, REVERT_AS, revert_body(&unknown), &reader_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            NO_GRANT_MESSAGE,
            "a read grant is no revert grant",
        );
        let (status, refused) =
            post_as_credential(&fixture, LIST_AS, json!({}), &reverter_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            NO_GRANT_MESSAGE,
            "a revert grant is no read grant",
        );

        // An unknown version is not found, for the owner and the granted
        // agent alike; a set past the policy's revision is refused.
        let (status, refused) = post_as_owner(&fixture, REVERT, revert_body(&unknown)).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            UNKNOWN_VERSION_MESSAGE,
            "the owner finds no unknown version",
        );
        let (status, refused) =
            post_as_credential(&fixture, REVERT_AS, revert_body(&unknown), &reverter_cred).await;
        assert_refusal(
            status,
            &refused,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            UNKNOWN_VERSION_MESSAGE,
            "a revert-granted agent finds no unknown version",
        );
        let (status, refused) = post_as_owner(
            &fixture,
            POLICY_SET,
            json!({"expected_revision": 7, "enabled": false}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            STALE_POLICY_MESSAGE,
            "a set seven revisions ahead is refused",
        );

        // Bodies that do not decode are refused before any precheck or door.
        let (status, refused) = post_as_owner(&fixture, LIST, json!({"target": "x"})).await;
        assert_decode_refusal(status, &refused, "target", "a mistyped list target");
        let (status, refused) = post_as_owner(&fixture, LIST, json!({"bogus": true})).await;
        assert_decode_refusal(status, &refused, "bogus", "an extra list key");
        let (status, refused) = post_as_owner(&fixture, STATUS, json!({"events_after": 42})).await;
        assert_decode_refusal(status, &refused, "events_after", "a mistyped status cursor");
        let (status, refused) = post_as_owner(&fixture, POLICY_SET, json!({})).await;
        assert_decode_refusal(status, &refused, "expected_revision", "an empty policy set");
        let (status, refused) = post_as_owner(
            &fixture,
            REVERT,
            json!({"version": "zzz", "expected_binding_generation": 0}),
        )
        .await;
        assert_decode_refusal(status, &refused, "version", "a non-hex revert version");
        let (status, refused) =
            post_as_owner(&fixture, REVERT, json!({"expected_binding_generation": 0})).await;
        assert_decode_refusal(status, &refused, "version", "a revert without a version");
        let (status, refused) =
            post_as_credential(&fixture, LIST_AS, json!({"target": 1}), &reader_cred).await;
        assert_decode_refusal(status, &refused, "target", "a mistyped agent list target");
        let (status, refused) = post_as_credential(
            &fixture,
            REVERT_AS,
            json!({"version": "zzz", "expected_binding_generation": 0}),
            &reverter_cred,
        )
        .await;
        assert_decode_refusal(
            status,
            &refused,
            "version",
            "a non-hex agent revert version",
        );

        // A read-only slip writes nothing; a record-narrowed slip reads
        // nothing here. Every body decodes, so each 403 is the scope's.
        for verb in [POLICY_SET, REVERT, REVERT_AS] {
            let body = if verb == POLICY_SET {
                json!({"expected_revision": 0, "enabled": true})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) = post_as_credential(&fixture, verb, body, &read_only_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                SCOPE_MESSAGE,
                &format!("a read-only slip is refused {verb}"),
            );
        }
        for verb in [LIST, STATUS, POLICY_SET, REVERT, LIST_AS, REVERT_AS] {
            let body = if verb == LIST || verb == STATUS || verb == LIST_AS {
                json!({})
            } else if verb == POLICY_SET {
                json!({"expected_revision": 0, "enabled": true})
            } else {
                revert_body(&unknown)
            };
            let (status, refused) = post_as_credential(&fixture, verb, body, &narrowed_cred).await;
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                SCOPE_MESSAGE,
                &format!("a record-narrowed slip is refused {verb}"),
            );
        }

        // A body that is not JSON is refused where the row reads it.
        let (status, refused) = post_raw_as_owner(&fixture, LIST, "{oops").await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            MALFORMED_MESSAGE,
            "a malformed body",
        );
    });
}
