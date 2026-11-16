//! Plan mode: an approved plan's run is a sub-session off the approving turn.
//!
//! Canon (agent-runtime-v1.md:342): execute-on-approve spawns the plan's run
//! as an ARCH-0006a sub-session hung off the approving turn (a `spawned_by`
//! edge, retained, mergeable), and the approving thread records that
//! `sub_session_id`. The owner approves from a conversation TURN
//! (`approving_turn_ref`) and an anchored review thread on the plan-doc
//! (`approving_thread_ref`): the approval lands the run's derived SESSION
//! off the turn, and the thread's head records the session. A revision
//! approved again keeps its first session; an approval naming no turn lands
//! the run with no session; a thread on another plan, a rejection naming a
//! turn, and a ref that is no turn are all refused with nothing written.
//!
//! Every verdict request is built from JSON and every new settlement field
//! is read back through JSON, so this file compiles on a tree without the
//! refs and fails there on assertions, never on a compile error.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test plan_mode_subsession`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::anchored_annotation::{AnnotationThreadOpenRequest, AnnotationThreadRequest};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{Memory, MemoryResult};
use oneiron::note::{
    PlanDocProposeRequest, PlanDocRequest, PlanDocSettlementView, PlanDocState,
    PlanDocVerdictRequest, PlanDocView, approve_plan_doc_as, reject_plan_doc_as,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    _dir: tempfile::TempDir,
}

/// A rooted vault with its install enrolled, its embedded owner, and an agent
/// definition with an owner Grant of base reach: the brief's reference check
/// reads the pinned plan with the poster's own key.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = define_agent(&vault, "tide-planner").expect("agent");
    let fixture = Fixture {
        vault,
        owner,
        agent,
        _dir: dir,
    };
    grant_base_reach(&fixture);
    fixture
}

fn owner_proof(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

fn grant_base_reach(fixture: &Fixture) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: fixture.agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

fn agent(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.agent, EdgeActorClass::Agent)
}

fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

const TITLE: &str = "Tidy the tide log";
const STEPS: [&str; 2] = [
    "Read the last week of tide entries",
    "Merge the duplicate dawn readings",
];
const SCOPE: &str = "notes tagged tide";
const BUDGET: u64 = 400;

/// The agent's propose request, with `extra` fields beside the plan. Built
/// from JSON, so it reads on a tree whose request lacks a field it names.
fn propose_request(extra: Value) -> PlanDocProposeRequest {
    let mut request = json!({
        "plan": {"title": TITLE, "steps": STEPS, "scope_asked": [SCOPE], "budget": BUDGET},
    });
    if let (Some(fields), Value::Object(extra)) = (request.as_object_mut(), extra) {
        fields.extend(extra);
    }
    serde_json::from_value(request).expect("a propose request")
}

/// The agent proposes its plan naming agent definition `runner` to run it.
fn propose_run_by(fixture: &Fixture, runner: EntityId) -> MemoryResult<PlanDocView> {
    agent(fixture).propose_plan_doc(&propose_request(json!({"agent_def_ref": runner.to_hex()})))
}

/// Plan-doc `plan` as the owner reads it now.
fn read(fixture: &Fixture, plan: EntityId) -> PlanDocView {
    owner(fixture)
        .read_plan_doc(&PlanDocRequest { plan_ref: plan })
        .expect("the owner reads the plan")
        .value
        .expect("the plan-doc")
}

/// The Unicode scalar span of `needle` in `haystack`.
fn char_span(haystack: &str, needle: &str) -> (u64, u64) {
    let byte = haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} is in {haystack:?}"));
    let start = haystack[..byte].chars().count() as u64;
    (start, start + needle.chars().count() as u64)
}

/// The owner opens a fresh conversation and speaks one TURN on it: the turn
/// an approval hangs its run off. Each call makes a new conversation.
fn turn(fixture: &Fixture) -> EntityId {
    let created = owner(fixture)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "v": 1,
                "kind": "group",
                "member_ids": [fixture.owner.to_hex()],
                "title": "plan approval room",
            }),
            text: None,
        })
        .expect("the owner opens a conversation");
    let room = EntityId::from_hex(&created.id).expect("the conversation id");
    let writer = owner(fixture);
    let now = fixture.vault.now_recorded_at();
    fixture
        .vault
        .append_dag_record(
            &writer,
            &AppendRecord {
                conversation: room,
                parent: fixture.vault.head(&room).expect("the room's head"),
                reply_to: None,
                quote: None,
                address: AddressMode::Broadcast,
                recipients: vec![],
                advance: true,
                kind: ENTITY_TYPE_TURN,
                containing_turn: None,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: rmp_serde::to_vec_named(&json!({ "txt": "the owner approves here" }))
                    .expect("the turn's body encodes"),
                text: Vec::new(),
                session: None,
                actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
                thread_audience: None,
            },
        )
        .expect("the owner's TURN lands")
        .id
}

/// The owner opens an anchored thread on the plan's second step.
fn open_thread(fixture: &Fixture, plan: &PlanDocView) -> EntityId {
    let (start, end) = char_span(&plan.markdown, STEPS[1]);
    let input: AnnotationThreadOpenRequest = serde_json::from_value(json!({
        "artifact_ref": plan.plan_ref.to_hex(),
        "version": 0,
        "locator": {"format": "text", "char_start": start, "char_end": end},
        "text": "Use the harbour gauge's readings for this step.",
    }))
    .expect("a thread open request");
    owner(fixture)
        .artifacts_threads_open(&input)
        .expect("the owner opens a thread on the plan")
        .thread_id
}

/// The owner's read of the thread, as JSON.
fn read_thread_json(fixture: &Fixture, plan: &PlanDocView, thread: EntityId) -> Value {
    let input = AnnotationThreadRequest {
        artifact_ref: plan.plan_ref.to_hex(),
        thread_ref: thread.to_hex(),
    };
    let view = owner(fixture)
        .artifacts_threads_read(&input)
        .expect("the owner reads the thread")
        .expect("the thread reads back");
    serde_json::to_value(&view).expect("a thread view encodes")
}

/// The owner approves the plan at `revision`, naming `extra` beside the
/// verdict. A request the tree refuses to parse and a verdict the door
/// refuses both come back as `Err`.
fn approve_with(
    fixture: &Fixture,
    plan: EntityId,
    revision: &str,
    extra: Value,
) -> Result<PlanDocSettlementView, String> {
    let mut request = json!({
        "plan_ref": plan.to_hex(),
        "expected_revision": revision,
    });
    if let (Some(fields), Value::Object(extra)) = (request.as_object_mut(), extra) {
        fields.extend(extra);
    }
    let input: PlanDocVerdictRequest =
        serde_json::from_value(request).map_err(|error| format!("{error}"))?;
    approve_plan_doc_as(&fixture.vault, &owner_proof(fixture), input)
        .map_err(|error| format!("{error:?}"))
}

/// The owner rejects the plan at `revision`, naming `extra` beside the
/// verdict. Parse and refusal errors both come back as `Err`.
fn reject_with(
    fixture: &Fixture,
    plan: EntityId,
    revision: &str,
    extra: Value,
) -> Result<PlanDocSettlementView, String> {
    let mut request = json!({
        "plan_ref": plan.to_hex(),
        "expected_revision": revision,
    });
    if let (Some(fields), Value::Object(extra)) = (request.as_object_mut(), extra) {
        fields.extend(extra);
    }
    let input: PlanDocVerdictRequest =
        serde_json::from_value(request).map_err(|error| format!("{error}"))?;
    reject_plan_doc_as(&fixture.vault, &owner_proof(fixture), input)
        .map_err(|error| format!("{error:?}"))
}

/// The run a verdict landed, read from its wire shape: `Err` when the
/// settlement names no run field at all.
fn run_of(settled: &PlanDocSettlementView) -> Result<Option<EntityId>, String> {
    let wire = serde_json::to_value(settled).expect("a settlement encodes");
    match wire.get("run_task_ref") {
        None => Err(format!("the settlement names no run: {wire}")),
        Some(Value::Null) => Ok(None),
        Some(run) => Ok(Some(
            serde_json::from_value(run.clone()).expect("a run TASK id"),
        )),
    }
}

/// The sub-session a verdict hung its run off, read from its wire shape:
/// absent and null both mean none.
fn sub_session_of(settled: &PlanDocSettlementView) -> Option<EntityId> {
    let wire = serde_json::to_value(settled).expect("a settlement encodes");
    match wire.get("sub_session_id") {
        None | Some(Value::Null) => None,
        Some(session) => {
            Some(serde_json::from_value(session.clone()).expect("a sub-session id reads"))
        }
    }
}

#[test]
fn approved_plan_executes_as_subsession_off_approving_turn() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let turn = turn(&fixture);
    let settled = approve_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({"approving_turn_ref": turn.to_hex()}),
    )
    .expect("the approval naming the turn lands");
    let run = run_of(&settled)
        .expect("the settlement names its run")
        .expect("the approval lands the plan's run");
    let session = sub_session_of(&settled).expect("the approval hangs the run off the turn");
    assert_ne!(session, run, "the sub-session is not the run TASK");
    assert_ne!(session, turn, "the sub-session is not the approving turn");
    assert_eq!(
        fixture
            .vault
            .sub_sessions(&turn)
            .expect("the turn's sub-sessions read"),
        vec![session],
        "the run hangs off the approving turn alone"
    );
}

#[test]
fn approving_thread_records_the_sub_session_id() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let thread = open_thread(&fixture, &plan);
    let before = read_thread_json(&fixture, &plan, thread);
    let state = before
        .pointer("/state")
        .cloned()
        .expect("the thread has a state");
    let turn = turn(&fixture);
    let settled = approve_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({
            "approving_turn_ref": turn.to_hex(),
            "approving_thread_ref": thread.to_hex(),
        }),
    )
    .expect("the approval naming the turn and the thread lands");
    let session = sub_session_of(&settled).expect("the approval hangs the run off the turn");
    let after = read_thread_json(&fixture, &plan, thread);
    assert_eq!(
        after.pointer("/sub_session_id").and_then(Value::as_str),
        Some(session.to_hex()).as_deref(),
        "the review thread records the run's sub-session: {after}"
    );
    assert_eq!(
        after.pointer("/state"),
        Some(&state),
        "recording the sub-session keeps the thread's state"
    );
}

#[test]
fn a_revision_approved_again_keeps_its_sub_session() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let first_turn = turn(&fixture);
    let first = approve_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({"approving_turn_ref": first_turn.to_hex()}),
    )
    .expect("the first approval lands");
    let second_turn = turn(&fixture);
    let second = approve_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({"approving_turn_ref": second_turn.to_hex()}),
    )
    .expect("the same revision approved again lands");
    assert_eq!(
        run_of(&second),
        run_of(&first),
        "the revision approved again keeps its first run"
    );
    assert_eq!(
        sub_session_of(&second),
        sub_session_of(&first),
        "the revision approved again keeps its first sub-session"
    );
    let session = sub_session_of(&first).expect("the first approval hangs the run off its turn");
    assert_eq!(
        fixture
            .vault
            .sub_sessions(&first_turn)
            .expect("the first turn's sub-sessions read"),
        vec![session],
        "the run hangs off the first approving turn"
    );
    assert!(
        fixture
            .vault
            .sub_sessions(&second_turn)
            .expect("the second turn's sub-sessions read")
            .is_empty(),
        "the later approval naming another turn never re-parents the run"
    );
}

#[test]
fn an_approval_naming_no_turn_lands_the_run_without_a_sub_session() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let settled = approve_with(&fixture, plan.plan_ref, &plan.revision, json!({}))
        .expect("the approval lands");
    assert!(
        run_of(&settled)
            .expect("the settlement names its run")
            .is_some(),
        "the approval lands the plan's run"
    );
    assert_eq!(
        sub_session_of(&settled),
        None,
        "an approval naming no turn hangs no sub-session"
    );
}

#[test]
fn a_thread_on_another_plan_is_refused_and_lands_nothing() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its plan");
    let other = propose_run_by(&fixture, fixture.agent).expect("the agent proposes another plan");
    let thread = open_thread(&fixture, &other);
    let turn = turn(&fixture);
    let refused = approve_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({
            "approving_turn_ref": turn.to_hex(),
            "approving_thread_ref": thread.to_hex(),
        }),
    );
    assert!(
        refused.is_err(),
        "a thread on another plan refuses the approval: {refused:?}"
    );
    assert_eq!(
        read(&fixture, plan.plan_ref).state,
        PlanDocState::InReview,
        "the refused verdict leaves the plan in review"
    );
    assert!(
        fixture
            .vault
            .sub_sessions(&turn)
            .expect("the turn's sub-sessions read")
            .is_empty(),
        "the refused approval hangs no sub-session"
    );
}

#[test]
fn a_rejection_naming_a_turn_is_refused() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let turn = turn(&fixture);
    let refused = reject_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({"approving_turn_ref": turn.to_hex()}),
    );
    assert!(
        refused.is_err(),
        "a rejection naming a turn is refused: {refused:?}"
    );
    assert_eq!(
        read(&fixture, plan.plan_ref).state,
        PlanDocState::InReview,
        "the refused rejection leaves the plan in review"
    );
}

#[test]
fn a_ref_that_is_no_turn_is_refused() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let refused = approve_with(
        &fixture,
        plan.plan_ref,
        &plan.revision,
        json!({"approving_turn_ref": plan.plan_ref.to_hex()}),
    );
    assert!(
        refused.is_err(),
        "an approving ref that is no turn is refused: {refused:?}"
    );
    assert_eq!(
        read(&fixture, plan.plan_ref).state,
        PlanDocState::InReview,
        "the refused verdict leaves the plan in review"
    );
}
