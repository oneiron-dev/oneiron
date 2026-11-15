//! The saved-workflow doors (ARCH-0053), entered as the SDK enters them:
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps). The doors are `vault.workflows.save`,
//! `.get`, `.update`, `.dispatch`, `.dispatch_bound` and `.status`.
//!
//! The promises (canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md`,
//! mirrored in `generated/llms-full.txt`):
//! P1 (arch-0053:41; llms-full.txt:345573) "The row must be Active, approved
//! (Auto or Approved) and enabled." — to run / dispatch: `dispatch` admits
//! only steps whose live `AGENT_DEF` stands so, and answers the run once
//! enqueued with no model, runner or live run.
//! P2 (arch-0053:41; llms-full.txt:345573) "Otherwise the agent holds at
//! Proposed, as a deleted definition does." — proven only as the
//! deleted-definition hold of a successor step, surfaced as the run's
//! `release_refusal`.
//! P3 (arch-0053:18; llms-full.txt:345550) "An `AGENT_DEF` is a skill hub with
//! a persona hole" — not this family's surface: listed unproven, no test.
//!
//! Each test owns a fresh vault. Agent definitions are seeded through the
//! engine's typed create (good standing) or by editing the pub fields of the
//! seeded default the engine returned and storing through `put_agent_definition`
//! (bad standing). TASKs for bound dispatch are watch TASKs (standard, idle,
//! runner lane, no live try) the member owns. Every test is a plain `#[test]`
//! driven by `run_on_engine_stack`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_workflows_doors`.
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
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    ConsultPayload, ConsultPayloadRef, TaskAssignee, TaskCreateSpec, TaskKind, TaskResultInput,
    TaskTerminalDisposition, TaskTtl,
};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
    agent_slip: CapabilitySlip,
    agent_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every person and agent credential here binds; each holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
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

/// An agent credential this host mints `who` (an `AGENT_DEF` id), holding
/// `read` and `write`: an agent's own slip, not owner-grade and not a member's.
fn mint_agent_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("an agent credential")
}

/// A good-standing agent definition the owner creates through the typed door:
/// Approved, Active and enabled. Returns its id.
fn seed_good_agent(vault: &Vault, proof: &AuthenticatedOwner, name: &str) -> EntityId {
    let id = EntityId::now();
    create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": name,
                "desc": "vault workflows doors test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates a good agent definition");
    id
}

/// A bad-standing agent definition stored through the entity door: the
/// seeded default's row with a fresh id, no logical id, no skills and one
/// standing flip. Returns its id.
fn seed_bad_agent(
    vault: &Vault,
    seed: &oneiron::agent_def::AgentDefinition,
    agent_id: &str,
    flip: impl FnOnce(&mut oneiron::agent_def::AgentDefinition),
) -> EntityId {
    let mut bad = seed.clone();
    bad.logical_id = None;
    bad.agent_id = agent_id.to_owned();
    bad.skills.clear();
    flip(&mut bad);
    let id = EntityId::now();
    vault
        .put_agent_definition(&id, &bad, TimeRange { start: 1, end: 1 }, 1)
        .expect("a bad-standing definition lands");
    id
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
                auth_secret: Some("vault-workflows-doors".into()),
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
    let who = seed_person(&vault);
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who);
    let person_token = person_slip.to_token().expect("person slip token");
    let agent = seed_good_agent(&vault, &owner_proof, "test.workflows.caller");
    let mut granted = Scope::top();
    granted.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: granted,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a grant");
    let agent_slip = mint_agent_credential(&owner_slip, &vault, &issuer, agent);
    let agent_token = agent_slip.to_token().expect("agent slip token");
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner,
        owner_proof,
        person: who,
        person_slip,
        person_token,
        agent_slip,
        agent_token,
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

/// The owner saves a two-step workflow, reads it back, edits exactly the
/// revision read (same steps, so the revision alone moves), and a stale edit
/// is refused.
///
/// Canon P1's standing is not at stake here; the door discipline is: save
/// answers revision 1 with no lineage, update assigns the next revision and
/// keeps lineage, and a concurrent edit loses.
#[test]
fn save_get_update_round_trip() {
    run_on_engine_stack("workflows-round-trip", || async {
        let fixture = setup().await;
        let first = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.trip.a",
        );
        let second = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.trip.b",
        );
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let first_hex = first.to_hex();
        let second_hex = second.to_hex();

        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-trip",
                "steps": [first_hex.clone(), second_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the workflow: {saved}");
        assert_eq!(
            saved["workflow_ref"].as_str(),
            Some(workflow_hex.as_str()),
            "save answers the id: {saved}"
        );
        assert_eq!(
            saved["name"].as_str(),
            Some("leg-s30-trip"),
            "save keeps the name: {saved}"
        );
        assert_eq!(
            saved["revision"].as_u64(),
            Some(1),
            "save lands revision 1: {saved}"
        );
        assert!(
            saved["forked_from"].is_null(),
            "a save has no lineage: {saved}"
        );
        assert_eq!(
            saved["steps"],
            json!([first_hex.clone(), second_hex.clone()]),
            "save keeps the steps: {saved}"
        );

        let (status, read) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.get",
            json!({"workflow_ref": workflow_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads it back: {read}");
        assert_eq!(
            read["revision"].as_u64(),
            Some(1),
            "get shows revision 1: {read}"
        );
        assert_eq!(read["steps"], saved["steps"], "get keeps the steps: {read}");

        let (status, edited) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.update",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "expected_revision": 1,
                "name": "leg-s30-trip",
                "steps": [first_hex.clone(), second_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner edits revision 1: {edited}");
        assert_eq!(
            edited["revision"].as_u64(),
            Some(2),
            "update assigns revision 2: {edited}"
        );
        assert!(
            edited["forked_from"].is_null(),
            "update keeps the lineage: {edited}"
        );

        let (status, reread) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.get",
            json!({"workflow_ref": workflow_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads revision 2: {reread}");
        assert_eq!(
            reread["revision"].as_u64(),
            Some(2),
            "get shows revision 2: {reread}"
        );

        let (status, stale) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.update",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "expected_revision": 1,
                "name": "leg-s30-trip-stale",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "a stale edit loses: {stale}");
        assert_eq!(
            stale["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {stale}"
        );
        assert_eq!(
            stale["error"]["message"].as_str(),
            Some("concurrent write detected: workflow revision changed"),
            "the refusal names the concurrent edit: {stale}"
        );
    });
}

/// An occupied id is never an implicit edit: saving again at the same id,
/// or at an id another entity holds, is refused and the saved row stands.
///
/// Canon P1's standing is not at stake here; the id discipline is.
#[test]
fn save_refuses_an_occupied_id() {
    run_on_engine_stack("workflows-occupied", || async {
        let fixture = setup().await;
        let first = seed_good_agent(&fixture.vault, &fixture.owner_proof, "test.workflows.occ.a");
        let first_hex = first.to_hex();
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();

        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-occupied",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the workflow: {saved}");

        let (status, again) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-occupied-again",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "saving again at the id is refused: {again}"
        );
        assert_eq!(
            again["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {again}"
        );
        assert_eq!(
            again["error"]["message"].as_str(),
            Some("concurrent write detected: workflow id is already occupied"),
            "the refusal names the occupied id: {again}"
        );

        let (status, squat) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": first_hex.clone(),
                "name": "leg-s30-squat",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "saving at an agent's id is refused: {squat}"
        );
        assert_eq!(
            squat["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {squat}"
        );
        assert_eq!(
            squat["error"]["message"].as_str(),
            Some("concurrent write detected: workflow id is already occupied"),
            "the refusal names the occupied id: {squat}"
        );

        let (status, read) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.get",
            json!({"workflow_ref": workflow_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the saved row stands: {read}");
        assert_eq!(
            read["name"].as_str(),
            Some("leg-s30-occupied"),
            "the refusals keep the name: {read}"
        );
    });
}

/// Dispatch answers the run once enqueued, with no model, runner or live run:
/// the answer carries the root, the active step, the captured steps and an
/// empty result list with no refusal, and status echoes it.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:41`
/// (llms-full.txt:345573) "The row must be Active, approved (Auto or Approved)
/// and enabled." — the positive half: an all-good composition dispatches.
#[test]
fn dispatch_answers_once_enqueued_without_a_model() {
    run_on_engine_stack("workflows-dispatch", || async {
        let fixture = setup().await;
        let first = seed_good_agent(&fixture.vault, &fixture.owner_proof, "test.workflows.run.a");
        let second = seed_good_agent(&fixture.vault, &fixture.owner_proof, "test.workflows.run.b");
        let first_hex = first.to_hex();
        let second_hex = second.to_hex();
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-run",
                "steps": [first_hex.clone(), second_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the workflow: {saved}");

        // No model, no runner, no live run anywhere in this fixture: the
        // dispatch below answers from the enqueue alone.
        let (status, run) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-dispatch-once",
                "briefing": "prove P1 without a model",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner dispatches the run: {run}");
        let root_hex = run["root_attempt_ref"]
            .as_str()
            .expect("root ref")
            .to_owned();
        let active_hex = run["active_attempt_ref"]
            .as_str()
            .expect("active ref")
            .to_owned();
        assert_ne!(root_hex, workflow_hex, "the root is a new attempt: {run}");
        assert_ne!(
            active_hex, root_hex,
            "the active step is its own attempt: {run}"
        );
        assert_eq!(
            run["workflow_ref"].as_str(),
            Some(workflow_hex.as_str()),
            "the run names its workflow: {run}"
        );
        assert_eq!(
            run["workflow_revision"].as_u64(),
            Some(1),
            "the run pins revision 1: {run}"
        );
        assert_eq!(
            run["steps"].as_array().map(Vec::len),
            Some(2),
            "two steps: {run}"
        );
        assert_eq!(
            run["steps"][0]["agent_def_ref"].as_str(),
            Some(first_hex.as_str()),
            "the first step seats the first agent: {run}"
        );
        assert_eq!(
            run["steps"][1]["agent_def_ref"].as_str(),
            Some(second_hex.as_str()),
            "the second step seats the second agent: {run}"
        );
        assert_eq!(run["results"], json!([]), "no step has settled: {run}");
        assert!(
            run["release_refusal"].is_null(),
            "nothing refuses the fresh run: {run}"
        );
        assert!(
            run["task_ref"].is_null(),
            "a TASK-less run binds none: {run}"
        );

        let (status, echoed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.status",
            json!({"root_attempt_ref": root_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the run: {echoed}");
        assert_eq!(
            echoed["root_attempt_ref"].as_str(),
            Some(root_hex.as_str()),
            "status echoes the root: {echoed}"
        );
        assert_eq!(
            echoed["active_attempt_ref"].as_str(),
            Some(active_hex.as_str()),
            "status echoes the active step: {echoed}"
        );
        assert!(
            echoed["release_refusal"].is_null(),
            "status shows no refusal: {echoed}"
        );
    });
}

/// Dispatch refuses a step whose definition does not stand Active, approved
/// and enabled, or is missing; an all-good control dispatches.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:41`
/// (llms-full.txt:345573) "The row must be Active, approved (Auto or Approved)
/// and enabled." — the negative half.
#[test]
fn dispatch_refuses_unrunnable_steps() {
    run_on_engine_stack("workflows-standing", || async {
        let fixture = setup().await;
        let (_, seed) = fixture
            .vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("seeded default")
            .expect("the default agent is seeded");

        let inactive_id = seed_bad_agent(
            &fixture.vault,
            &seed,
            "test.workflows.bad.inactive",
            |bad| {
                bad.lifecycle_status = oneiron::claim::ClaimLifecycleStatus::Superseded;
            },
        );
        let inactive_hex = inactive_id.to_hex();

        let unapproved_id = seed_bad_agent(
            &fixture.vault,
            &seed,
            "test.workflows.bad.unapproved",
            |bad| {
                bad.approval_status = oneiron::claim::ClaimApprovalStatus::Proposed;
            },
        );
        let unapproved_hex = unapproved_id.to_hex();

        let switched_off_id = seed_bad_agent(
            &fixture.vault,
            &seed,
            "test.workflows.bad.disabled",
            |bad| {
                bad.enabled = false;
            },
        );
        let switched_off_hex = switched_off_id.to_hex();

        let victim = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.bad.victim",
        );
        let victim_hex = victim.to_hex();

        let good = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.stand.ok",
        );
        let good_hex = good.to_hex();

        // The owned message for the id-bearing refusal.
        let disabled_message = format!("agent definition disabled: {switched_off_hex}");
        let wants: Vec<(&str, String, String)> = vec![
            (
                "inactive",
                inactive_hex,
                "agent not dispatchable: agent definition is not active".to_owned(),
            ),
            (
                "unapproved",
                unapproved_hex,
                "agent not dispatchable: agent definition is not approved".to_owned(),
            ),
            ("disabled", switched_off_hex, disabled_message),
        ];
        for (label, step_hex, want) in wants {
            let workflow = EntityId::now();
            let workflow_hex = workflow.to_hex();
            let (status, saved) = post_as_owner(
                &fixture,
                "/v1/core/facade/vault.workflows.save",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "name": format!("leg-s30-bad-{label}"),
                    "steps": [step_hex.clone()],
                }),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "owner saves the {label} workflow: {saved}"
            );
            let (status, refused) = post_as_owner(
                &fixture,
                "/v1/core/facade/vault.workflows.dispatch",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "intent_key": format!("leg-s30-bad-{label}"),
                    "briefing": format!("a {label} step never runs"),
                }),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a {label} step is refused: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(want.as_str()),
                "the refusal names the standing: {refused}"
            );
        }

        // Missing: save names a live row, then the row is deleted, so dispatch
        // meets a deleted shell (a save naming nothing 404s at the batch gate).
        let missing_workflow = EntityId::now().to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": missing_workflow.clone(),
                "name": "leg-s30-bad-missing",
                "steps": [victim_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner saves the missing workflow: {saved}"
        );
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.delete",
            json!({"entity_ref": victim_hex.clone(), "reason": "user_delete"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner deletes the step");
        let missing_message = format!("agent definition not found: {victim_hex}");
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": missing_workflow,
                "intent_key": "leg-s30-bad-missing",
                "briefing": "a missing step never runs",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a missing step is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(missing_message.as_str()),
            "the refusal names the missing row: {refused}"
        );

        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-stand-control",
                "steps": [good_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the control: {saved}");
        let (status, run) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-stand-control",
                "briefing": "the control runs",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the good control dispatches: {run}");
        assert_eq!(
            run["steps"][0]["agent_def_ref"].as_str(),
            Some(good_hex.as_str()),
            "the control seats its agent: {run}"
        );
    });
}

/// A retried intent key returns the same run; the same key with another
/// briefing is another intent and is refused.
#[test]
fn dispatch_dedupe_returns_the_same_run() {
    run_on_engine_stack("workflows-dedupe", || async {
        let fixture = setup().await;
        let first = seed_good_agent(&fixture.vault, &fixture.owner_proof, "test.workflows.dd.a");
        let first_hex = first.to_hex();
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-dedupe",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the workflow: {saved}");

        let (status, once) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-dedupe-key",
                "briefing": "the first intent",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner dispatches once: {once}");
        let root_hex = once["root_attempt_ref"].as_str().expect("root").to_owned();

        let (status, twice) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-dedupe-key",
                "briefing": "the first intent",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the retry answers: {twice}");
        assert_eq!(
            twice["root_attempt_ref"].as_str(),
            Some(root_hex.as_str()),
            "the retry returns the same run: {twice}"
        );

        let (status, other) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-dedupe-key",
                "briefing": "another intent",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "another intent under the key is refused: {other}"
        );
        assert_eq!(
            other["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {other}"
        );
        assert_eq!(
            other["error"]["message"].as_str(),
            Some("invalid agent dispatch input: workflow dedupe key names a different intent"),
            "the refusal names the intent: {other}"
        );
    });
}

/// A member binds one run to an idle standard TASK they own, as themselves:
/// the run records their TASK, the owner reads it back so, the owner binds
/// their own the same way, an agent binds nothing, and an unfunded bind fails.
///
/// The BIND is the `task_ref` the run records and status shows; the payer the
/// member funds (their root spend scope) is engine-internal beside it.
#[test]
fn dispatch_bound_binds_the_members_task() {
    run_on_engine_stack("workflows-bound", || async {
        let fixture = setup().await;
        let first = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.bind.a",
        );
        let first_hex = first.to_hex();
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-bound",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the workflow: {saved}");

        let due_at = fixture.vault.now_recorded_at() + 1_000_000;
        let member_task = fixture
            .vault
            .memory(fixture.person, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("leg-s30 bound work"),
                    Some("leg-s30 bound".to_owned()),
                    Some(fixture.person),
                    None,
                )
                .with_due_at(due_at)
                .with_watch(true),
            )
            .expect("member mints an idle watch TASK")
            .task_ref
            .expect("the TASK mints, not parks");
        let member_hex = member_task.to_hex();
        let shown_at_ms = fixture.vault.now_recorded_at() * 1000;

        let (status, bound) = post_as_person(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-bound-member",
                "briefing": "the member binds",
                "task_ref": member_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member binds their TASK: {bound}"
        );
        assert_eq!(
            bound["task_ref"].as_str(),
            Some(member_hex.as_str()),
            "the run records the bound TASK: {bound}"
        );
        let root_hex = bound["root_attempt_ref"].as_str().expect("root").to_owned();

        let (status, echoed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.status",
            json!({"root_attempt_ref": root_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the bound run: {echoed}"
        );
        assert_eq!(
            echoed["task_ref"].as_str(),
            Some(member_hex.as_str()),
            "status shows the bound TASK: {echoed}"
        );

        let owner_task = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("leg-s30 owner bound work"),
                    Some("leg-s30 owner bound".to_owned()),
                    Some(fixture.owner),
                    None,
                )
                .with_due_at(due_at)
                .with_watch(true),
            )
            .expect("owner mints an idle watch TASK")
            .task_ref
            .expect("the owner TASK mints");
        let owner_hex = owner_task.to_hex();
        let (status, owner_bound) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-bound-owner",
                "briefing": "the owner binds",
                "task_ref": owner_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner binds their TASK: {owner_bound}"
        );
        assert_eq!(
            owner_bound["task_ref"].as_str(),
            Some(owner_hex.as_str()),
            "the owner run records its TASK: {owner_bound}"
        );

        let (status, refused) = post_as_agent(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-bound-agent",
                "briefing": "an agent binds nothing",
                "task_ref": member_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an agent binds nothing: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {refused}"
        );

        let (status, unfunded) = post_as_person(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-bound-broke",
                "briefing": "no cap, no run",
                "task_ref": member_hex.clone(),
                "cap_units": 0,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unfunded bind fails: {unfunded}"
        );
        assert_eq!(
            unfunded["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {unfunded}"
        );
        let cap_want = concat!(
            "cap_units must be more than zero: ",
            "set the most this run may spend, as you were shown it"
        );
        assert_eq!(
            unfunded["error"]["message"].as_str(),
            Some(cap_want),
            "the refusal names the missing cap: {unfunded}"
        );
    });
}

/// A successor whose definition is deleted after admission holds: the pump
/// keeps the completed step and parks the wrapper with the refusal, which
/// status shows.
///
/// Canon `oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:41`
/// (llms-full.txt:345573) "Otherwise the agent holds at Proposed, as a deleted
/// definition does." — the door-visible hold is `release_refusal`.
#[cfg(oneiron_test_support)]
#[test]
fn successor_hold_surfaces_as_release_refusal() {
    run_on_engine_stack("workflows-hold", || async {
        let fixture = setup().await;
        let first = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.hold.a",
        );
        let second = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.hold.b",
        );
        let first_hex = first.to_hex();
        let second_hex = second.to_hex();
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-hold",
                "steps": [first_hex.clone(), second_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves two steps: {saved}");

        let (status, run) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-hold-run",
                "briefing": "the successor holds",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner dispatches: {run}");
        let root_hex = run["root_attempt_ref"].as_str().expect("root").to_owned();
        let root_id = oneiron::attempt_queue::AttemptId::from_bytes(
            EntityId::from_hex(&root_hex).expect("root hex").as_bytes(),
        )
        .expect("root attempt");

        let now = fixture.vault.now_recorded_at();
        let held =
            oneiron_server::test_doors::workflow_park::claim_step(&fixture.vault, root_id, now, 0)
                .expect("claim the first step")
                .expect("the first step runs");
        oneiron::attempt_queue::AttemptQueue::new(&fixture.vault)
            .set_result(oneiron::attempt_queue::SetAttemptResult {
                id: held.leaf,
                lease_owner: "workflow-park-door".to_owned(),
                attempt_count: held.lease_count,
                result_ref: oneiron::attempt_queue::AttemptResultRef::new("leg-s30-step-1-result")
                    .expect("result ref"),
                now,
            })
            .expect("the step pins its result");
        oneiron::attempt_queue::AttemptQueue::new(&fixture.vault)
            .complete(oneiron::attempt_queue::CompleteAttempt {
                id: held.leaf,
                lease_owner: "workflow-park-door".to_owned(),
                attempt_count: held.lease_count,
                now,
            })
            .expect("the step completes");

        let (status, gone) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.delete",
            json!({"entity_ref": second_hex.clone(), "reason": "user_delete"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner deletes the successor: {gone}"
        );

        oneiron::agent_dispatch::AgentDispatcher::new(&fixture.vault)
            .advance_workflow(root_id, now + 1)
            .expect("the pump advances");

        let (status, held_run) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.status",
            json!({"root_attempt_ref": root_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the held run: {held_run}"
        );
        let refusal = held_run["release_refusal"].as_str().expect("a refusal");
        assert!(
            refusal.contains("agent definition not found"),
            "the hold names the deleted definition: {held_run}"
        );
        assert!(
            refusal.contains(&second_hex),
            "the hold names the successor: {held_run}"
        );
        assert_eq!(
            held_run["results"].as_array().map(Vec::len),
            Some(1),
            "the completed step is kept: {held_run}"
        );
        assert_eq!(
            held_run["results"][0]["result_ref"].as_str(),
            Some("leg-s30-step-1-result"),
            "the kept step keeps its result: {held_run}"
        );
    });
}

/// Every refusal the six doors answer: owner-only rows refuse a person and an
/// agent with a body that decodes, the member row refuses an agent while an
/// invitee holds no scope to reach it, funding, lane and TASK gates refuse
/// with their reasons, unknown ids miss, bad steps fail, and malformed
/// bodies never decode.
#[test]
fn refusals_table() {
    run_on_engine_stack("workflows-refusals", || async {
        let fixture = setup().await;
        let first = seed_good_agent(&fixture.vault, &fixture.owner_proof, "test.workflows.ref.a");
        let first_hex = first.to_hex();
        let workflow = EntityId::now();
        let workflow_hex = workflow.to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "name": "leg-s30-refusals",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the workflow: {saved}");

        // The member refusal first: it is this test's seeded message, and it
        // must fail before any standing refusal below could.
        let bound_body = json!({
            "workflow_ref": workflow_hex.clone(),
            "intent_key": "leg-s30-ref-member",
            "briefing": "an agent binds nothing",
            "task_ref": EntityId::now().to_hex(),
            "cap_units": 1000,
            "unit": "tokens",
            "shown_at_ms": 1,
        });
        let (status, refused) = post_as_agent(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            bound_body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "dispatch_bound refuses an agent: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("vault.workflows.dispatch_bound is a live person's own act"),
            "the refusal names the member's act: {refused}"
        );

        // Owner-only rows, as a person and as an agent, each with a body that
        // decodes so the refusal is the owner's, not the shape's.
        let fresh_hex = EntityId::now().to_hex();
        let owner_rows: Vec<(&str, Value)> = vec![
            (
                "vault.workflows.save",
                json!({
                    "workflow_ref": fresh_hex.clone(),
                    "name": "leg-s30-ref-save",
                    "steps": [first_hex.clone()],
                }),
            ),
            (
                "vault.workflows.update",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "expected_revision": 1,
                    "name": "leg-s30-ref-update",
                    "steps": [first_hex.clone()],
                }),
            ),
            (
                "vault.workflows.get",
                json!({"workflow_ref": workflow_hex.clone()}),
            ),
            (
                "vault.workflows.dispatch",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "intent_key": "leg-s30-ref-dispatch",
                    "briefing": "refused",
                }),
            ),
            (
                "vault.workflows.status",
                json!({"root_attempt_ref": EntityId::now().to_hex()}),
            ),
        ];
        for (verb, input) in &owner_rows {
            let path = format!("/v1/core/facade/{verb}");
            let want = format!("{verb} is the vault owner's");
            let (status, refused) = post_as_person(&fixture, &path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a person is refused {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(want.as_str()),
                "the refusal names the owner: {refused}"
            );
            let (status, refused) = post_as_agent(&fixture, &path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "an agent is refused {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(want.as_str()),
                "the refusal names the owner: {refused}"
            );
        }

        // Funding: no cap, and a unit no lease names.
        let (status, unfunded) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-broke",
                "briefing": "no cap",
                "task_ref": EntityId::now().to_hex(),
                "cap_units": 0,
                "unit": "tokens",
                "shown_at_ms": 1,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "no cap is refused: {unfunded}"
        );
        assert_eq!(
            unfunded["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {unfunded}"
        );
        let cap_want = concat!(
            "cap_units must be more than zero: ",
            "set the most this run may spend, as you were shown it"
        );
        assert_eq!(
            unfunded["error"]["message"].as_str(),
            Some(cap_want),
            "the refusal names the missing cap: {unfunded}"
        );
        let (status, bad_unit) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-unit",
                "briefing": "bad unit",
                "task_ref": EntityId::now().to_hex(),
                "cap_units": 1000,
                "unit": "BAD UNIT!",
                "shown_at_ms": 1,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a bad unit is refused: {bad_unit}"
        );
        assert_eq!(
            bad_unit["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {bad_unit}"
        );
        assert_eq!(
            bad_unit["error"]["message"].as_str(),
            Some("unit must name a lease unit: lowercase ASCII letters, digits, `_` and `-`"),
            "the refusal names the unit: {bad_unit}"
        );

        // TASK gates: the bound door reads its TASK on the caller's lane
        // before the bind gate, so a missing TASK is unreadable there; the
        // owner's dispatch names no lane, so a missing TASK misses at the
        // gate, as does a TASK the caller is no party to. Consult, terminal,
        // peer lane and live-try TASKs are refused with their reasons.
        let due_at = fixture.vault.now_recorded_at() + 1_000_000;
        let shown_at_ms = fixture.vault.now_recorded_at() * 1000;
        let missing_task = EntityId::now().to_hex();
        let (status, missing) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-missing-task",
                "briefing": "no such TASK",
                "task_ref": missing_task,
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a missing TASK is unreadable on the lane: {missing}"
        );
        assert_eq!(
            missing["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {missing}"
        );
        let lane_want = concat!(
            "vault.workflows.dispatch_bound reads its TASK, its workflow and ",
            "each step's definition on your own credential's lane, and one ",
            "is not readable there"
        );
        assert_eq!(
            missing["error"]["message"].as_str(),
            Some(lane_want),
            "the refusal names the unreadable TASK: {missing}"
        );

        let (status, ghost_task) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-ghost-task",
                "briefing": "no such TASK",
                "task_ref": EntityId::now().to_hex(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a missing TASK misses at the gate: {ghost_task}"
        );
        assert_eq!(
            ghost_task["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {ghost_task}"
        );
        assert_eq!(
            ghost_task["error"]["message"].as_str(),
            Some("entity not found"),
            "the refusal names the miss: {ghost_task}"
        );

        let foreign_task = fixture
            .vault
            .memory(fixture.person, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("leg-s30 foreign work"),
                    Some("leg-s30 foreign".to_owned()),
                    Some(fixture.person),
                    None,
                )
                .with_due_at(due_at)
                .with_watch(true),
            )
            .expect("member mints a TASK")
            .task_ref
            .expect("the foreign TASK mints");
        let foreign_hex = foreign_task.to_hex();
        let (status, foreign) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-foreign",
                "briefing": "not the owner's TASK",
                "task_ref": foreign_hex.clone(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a TASK the caller is no party to is not found: {foreign}"
        );
        assert_eq!(
            foreign["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {foreign}"
        );
        assert_eq!(
            foreign["error"]["message"].as_str(),
            Some("entity not found"),
            "the refusal names the miss: {foreign}"
        );

        let question = EntityId::now();
        fixture
            .vault
            .put_entity(
                &question,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"a consult question",
            )
            .expect("a question TURN");
        let consult_task = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::Nil,
                    Some("leg-s30 consult".to_owned()),
                    Some(fixture.owner),
                    None,
                )
                .with_kind(TaskKind::Consult)
                .with_consult(ConsultPayload::question(
                    ConsultPayloadRef::Turn(question),
                    vec![],
                    EntityId::now(),
                ))
                .with_assignee(TaskAssignee::Peer {
                    actor_ref: fixture.person,
                })
                .with_ttl(TaskTtl::at(due_at + 1_000_000)),
            )
            .expect("owner mints a consult")
            .task_ref
            .expect("the consult mints");
        let consult_hex = consult_task.to_hex();
        let (status, consult) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-consult",
                "briefing": "no consult runs",
                "task_ref": consult_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a consult is refused: {consult}"
        );
        assert_eq!(
            consult["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {consult}"
        );
        let consult_want = format!(
            "TASK {consult_hex} is a consult or reconciliation task; {}",
            "a workflow realizes only a standard task"
        );
        assert_eq!(
            consult["error"]["message"].as_str(),
            Some(consult_want.as_str()),
            "the refusal names the kind: {consult}"
        );

        let ended_task = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("leg-s30 ended work"),
                    Some("leg-s30 ended".to_owned()),
                    Some(fixture.owner),
                    None,
                )
                .with_due_at(due_at)
                .with_watch(true),
            )
            .expect("owner mints a TASK to end")
            .task_ref
            .expect("the ended TASK mints");
        let ended_hex = ended_task.to_hex();
        let outcome = EntityId::now();
        fixture
            .vault
            .put_entity(
                &outcome,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"a durable outcome",
            )
            .expect("an outcome TURN");
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .land_task_result(
                ended_task,
                &TaskResultInput {
                    result_ref: outcome,
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: fixture.vault.now_recorded_at(),
                },
            )
            .expect("the TASK settles completed");
        let (status, ended) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-ended",
                "briefing": "no ended TASK runs",
                "task_ref": ended_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "an ended TASK is refused: {ended}"
        );
        assert_eq!(
            ended["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {ended}"
        );
        assert_eq!(
            ended["error"]["message"].as_str(),
            Some(
                format!(
                    "TASK {ended_hex} is already completed; a terminal task takes no more work"
                )
                .as_str()
            ),
            "the refusal names the terminal state: {ended}"
        );

        let peer_task = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::Nil,
                    Some("leg-s30 peer".to_owned()),
                    Some(fixture.owner),
                    None,
                )
                .with_assignee(TaskAssignee::Peer {
                    actor_ref: fixture.person,
                }),
            )
            .expect("owner mints a peer TASK")
            .task_ref
            .expect("the peer TASK mints");
        let peer_hex = peer_task.to_hex();
        let (status, peer) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-peer",
                "briefing": "no peer TASK runs",
                "task_ref": peer_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a peer TASK is refused: {peer}"
        );
        assert_eq!(
            peer["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {peer}"
        );
        let peer_want = format!(
            "TASK {peer_hex} is addressed to a peer, a child or a person; {}",
            "a workflow realizes only a task the engine's runner takes"
        );
        assert_eq!(
            peer["error"]["message"].as_str(),
            Some(peer_want.as_str()),
            "the refusal names the lane: {peer}"
        );

        let busy_task = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("leg-s30 busy work"),
                Some("leg-s30 busy".to_owned()),
                Some(fixture.owner),
                None,
            ))
            .expect("owner mints a Dreamer TASK")
            .task_ref
            .expect("the busy TASK mints");
        let busy_hex = busy_task.to_hex();
        let (status, busy) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-busy",
                "briefing": "no busy TASK runs",
                "task_ref": busy_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a busy TASK is refused: {busy}"
        );
        assert_eq!(
            busy["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {busy}"
        );
        let busy_message = busy["error"]["message"].as_str().expect("a message");
        assert!(
            busy_message.contains(&format!("TASK {busy_hex} already has a live try")),
            "the refusal names the live try: {busy}"
        );

        // Save and update discipline: occupied, empty, stale and unknown.
        let taken = EntityId::now().to_hex();
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": taken.clone(),
                "name": "leg-s30-ref-taken",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner saves the taken id");
        let (status, occupied) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": taken,
                "name": "leg-s30-ref-taken-again",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "an occupied id is refused: {occupied}"
        );
        assert_eq!(
            occupied["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {occupied}"
        );
        assert_eq!(
            occupied["error"]["message"].as_str(),
            Some("concurrent write detected: workflow id is already occupied"),
            "the refusal names the id: {occupied}"
        );
        let (status, empty_name) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": EntityId::now().to_hex(),
                "name": "",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an empty name is refused: {empty_name}"
        );
        assert_eq!(
            empty_name["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {empty_name}"
        );
        assert_eq!(
            empty_name["error"]["message"].as_str(),
            Some("invalid config: invalid workflow definition"),
            "the refusal names the shape: {empty_name}"
        );
        let (status, empty_steps) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": EntityId::now().to_hex(),
                "name": "leg-s30-ref-no-steps",
                "steps": [],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "empty steps are refused: {empty_steps}"
        );
        assert_eq!(
            empty_steps["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {empty_steps}"
        );
        assert_eq!(
            empty_steps["error"]["message"].as_str(),
            Some("invalid config: invalid workflow definition"),
            "the refusal names the shape: {empty_steps}"
        );

        let (status, edited) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.update",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "expected_revision": 1,
                "name": "leg-s30-refusals-v2",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner edits to revision 2: {edited}"
        );
        let (status, stale) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.update",
            json!({
                "workflow_ref": workflow_hex.clone(),
                "expected_revision": 1,
                "name": "leg-s30-ref-stale",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a stale edit is refused: {stale}"
        );
        assert_eq!(
            stale["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {stale}"
        );
        assert_eq!(
            stale["error"]["message"].as_str(),
            Some("concurrent write detected: workflow revision changed"),
            "the refusal names the edit: {stale}"
        );
        let unknown_hex = EntityId::now().to_hex();
        let (status, unknown_update) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.update",
            json!({
                "workflow_ref": unknown_hex.clone(),
                "expected_revision": 1,
                "name": "leg-s30-ref-ghost",
                "steps": [first_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unknown update misses: {unknown_update}"
        );
        assert_eq!(
            unknown_update["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {unknown_update}"
        );
        assert_eq!(
            unknown_update["error"]["message"].as_str(),
            Some("entity not found"),
            "the refusal names the miss: {unknown_update}"
        );
        let (status, unknown_get) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.get",
            json!({"workflow_ref": unknown_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unknown get misses: {unknown_get}"
        );
        assert_eq!(
            unknown_get["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {unknown_get}"
        );
        assert_eq!(
            unknown_get["error"]["message"].as_str(),
            Some("workflow not found"),
            "the refusal names the miss: {unknown_get}"
        );

        // Dispatch and status misses.
        let (status, ghost_run) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": unknown_hex.clone(),
                "intent_key": "leg-s30-ref-ghost-run",
                "briefing": "no such workflow",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a ghost dispatch fails: {ghost_run}"
        );
        assert_eq!(
            ghost_run["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {ghost_run}"
        );
        assert_eq!(
            ghost_run["error"]["message"].as_str(),
            Some("invalid agent dispatch input: saved workflow is missing or inactive"),
            "the refusal names the miss: {ghost_run}"
        );
        let (status, ghost_status) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.status",
            json!({"root_attempt_ref": EntityId::now().to_hex()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a ghost status fails: {ghost_status}"
        );
        assert_eq!(
            ghost_status["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {ghost_status}"
        );
        assert_eq!(
            ghost_status["error"]["message"].as_str(),
            Some("invalid agent dispatch input: workflow root is missing"),
            "the refusal names the miss: {ghost_status}"
        );

        // Bad steps: inactive, unapproved, disabled and missing.
        let (_, seed) = fixture
            .vault
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .expect("seeded default")
            .expect("the default agent is seeded");
        let inactive_id = seed_bad_agent(
            &fixture.vault,
            &seed,
            "test.workflows.ref.inactive",
            |bad| {
                bad.lifecycle_status = oneiron::claim::ClaimLifecycleStatus::Superseded;
            },
        );
        let unapproved_id = seed_bad_agent(
            &fixture.vault,
            &seed,
            "test.workflows.ref.unapproved",
            |bad| {
                bad.approval_status = oneiron::claim::ClaimApprovalStatus::Proposed;
            },
        );
        let switched_off_id = seed_bad_agent(
            &fixture.vault,
            &seed,
            "test.workflows.ref.disabled",
            |bad| {
                bad.enabled = false;
            },
        );
        let switched_off_hex = switched_off_id.to_hex();
        let victim = seed_good_agent(
            &fixture.vault,
            &fixture.owner_proof,
            "test.workflows.ref.victim",
        );
        let victim_hex = victim.to_hex();
        let bad_steps: Vec<(String, String)> = vec![
            (
                inactive_id.to_hex(),
                "agent not dispatchable: agent definition is not active".to_owned(),
            ),
            (
                unapproved_id.to_hex(),
                "agent not dispatchable: agent definition is not approved".to_owned(),
            ),
            (
                switched_off_hex.clone(),
                format!("agent definition disabled: {switched_off_hex}"),
            ),
        ];
        for (step_hex, want) in bad_steps {
            let bad_workflow = EntityId::now().to_hex();
            let (status, saved) = post_as_owner(
                &fixture,
                "/v1/core/facade/vault.workflows.save",
                json!({
                    "workflow_ref": bad_workflow.clone(),
                    "name": "leg-s30-ref-bad-step",
                    "steps": [step_hex.clone()],
                }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "owner saves a bad step: {saved}");
            let (status, refused) = post_as_owner(
                &fixture,
                "/v1/core/facade/vault.workflows.dispatch",
                json!({
                    "workflow_ref": bad_workflow,
                    "intent_key": format!("leg-s30-ref-bad-{step_hex}"),
                    "briefing": "a bad step never runs",
                }),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a bad step is refused: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(want.as_str()),
                "the refusal names the standing: {refused}"
            );
        }
        let missing_workflow = EntityId::now().to_hex();
        let (status, saved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.save",
            json!({
                "workflow_ref": missing_workflow.clone(),
                "name": "leg-s30-ref-bad-missing",
                "steps": [victim_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner saves the missing step: {saved}"
        );
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.delete",
            json!({"entity_ref": victim_hex.clone(), "reason": "user_delete"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner deletes the step");
        let missing_want = format!("agent definition not found: {victim_hex}");
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch",
            json!({
                "workflow_ref": missing_workflow,
                "intent_key": "leg-s30-ref-bad-missing",
                "briefing": "a missing step never runs",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a missing step is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(missing_want.as_str()),
            "the refusal names the missing row: {refused}"
        );

        // Malformed bodies never decode, on all six verbs.
        let malformed: Vec<(&str, Value)> = vec![
            ("vault.workflows.save", json!({})),
            (
                "vault.workflows.save",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "name": "x",
                    "steps": [first_hex.clone()],
                    "extra": 1,
                }),
            ),
            (
                "vault.workflows.update",
                json!({"workflow_ref": workflow_hex.clone()}),
            ),
            (
                "vault.workflows.update",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "expected_revision": 1,
                    "name": "x",
                    "steps": [first_hex.clone()],
                    "extra": 1,
                }),
            ),
            ("vault.workflows.get", json!({})),
            (
                "vault.workflows.get",
                json!({"workflow_ref": workflow_hex.clone(), "extra": 1}),
            ),
            (
                "vault.workflows.dispatch",
                json!({"workflow_ref": workflow_hex.clone()}),
            ),
            (
                "vault.workflows.dispatch",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "intent_key": "k",
                    "briefing": "b",
                    "extra": 1,
                }),
            ),
            (
                "vault.workflows.dispatch_bound",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "intent_key": "k",
                    "briefing": "b",
                    "cap_units": 1000,
                    "unit": "tokens",
                    "shown_at_ms": 1,
                }),
            ),
            (
                "vault.workflows.dispatch_bound",
                json!({
                    "workflow_ref": workflow_hex.clone(),
                    "intent_key": "k",
                    "briefing": "b",
                    "task_ref": EntityId::now().to_hex(),
                    "cap_units": 1000,
                    "unit": "tokens",
                    "shown_at_ms": 1,
                    "extra": 1,
                }),
            ),
            ("vault.workflows.status", json!({})),
            (
                "vault.workflows.status",
                json!({"root_attempt_ref": EntityId::now().to_hex(), "extra": 1}),
            ),
        ];
        for (verb, input) in malformed {
            let path = format!("/v1/core/facade/{verb}");
            let (status, malformed) = post_as_owner(&fixture, &path, input).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a malformed {verb} never decodes: {malformed}"
            );
            assert_eq!(
                malformed["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {malformed}"
            );
            let message = malformed["error"]["message"].as_str().expect("a message");
            assert!(
                message.starts_with("invalid SDK request: "),
                "the refusal names the shape: {malformed}"
            );
        }

        // An invitee's slip binds nothing: it carries no scope outside its
        // invitation's doors, so the scope guard refuses it before any door.
        let mut invitee_claims = fixture.person_slip.claims.clone();
        invitee_claims.slip_id = next_slip_id();
        invitee_claims.invitation_ref = Some(EntityId::now().to_hex());
        let invitee_slip = fixture
            .vault
            .mint_capability_slip(&fixture.issuer, invitee_claims)
            .expect("an invitee slip");
        let invitee_token = invitee_slip.to_token().expect("invitee token");
        let invitee_binding = holder_proof(
            &invitee_slip,
            &holder_key(),
            fixture.vault.now_recorded_at(),
        )
        .expect("invitee proof")
        .to_string();
        let (status, invitee) = post(
            &fixture,
            "/v1/core/facade/vault.workflows.dispatch_bound",
            &invitee_token,
            invitee_binding,
            json!({
                "workflow_ref": workflow_hex.clone(),
                "intent_key": "leg-s30-ref-invitee",
                "briefing": "an invitee binds nothing",
                "task_ref": foreign_hex.clone(),
                "cap_units": 1000,
                "unit": "tokens",
                "shown_at_ms": shown_at_ms,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an invitee binds nothing: {invitee}"
        );
        assert_eq!(
            invitee["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {invitee}"
        );
        assert_eq!(
            invitee["error"]["message"].as_str(),
            Some("request does not have the required scope"),
            "the refusal names the missing scope: {invitee}"
        );

        // A working TASK that is not idle is not seeded here: taking a TASK
        // needs its runner's host binding, which no pub path from outside the
        // engine mints. The same `admit_in_txn` gate is proven by the live-try
        // and terminal rows above.
    });
}
