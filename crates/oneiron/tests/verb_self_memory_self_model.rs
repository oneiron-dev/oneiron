//! `self.memory.self_model` through the generated verb dispatch (`oneiron::task_verb::sdk::invoke`),
//! as a client calls it: JSON in, JSON out, on the caller's own `Memory`.
//! An agent with no live Grant listing the verb is refused FORBIDDEN; the holder reads its own
//! Dreamer-composed self-model with a live 16-byte revision, another agent's readable self-model
//! answers not_own with never its text, and a revoked Grant is refused again: the check is live.
//! The holder fixture seeds two independent self-model SUMMARYs through the public Dreamer path
//! (`request_scope_summary_for` with purpose `self_model`, Micro admit, `ScopeSummaryExecutor`
//! with a scripted backend, complete), each requested by its own agent over its own
//! owner-written conversation, on a `ManualClock` fixed at `T0`: no wall time, no sleeps.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_self_memory_self_model`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::dreamer_consolidation::ScopeSummaryExecutor;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
    DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission,
    DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, ReplyAssertions};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::registry::ENTITY_TYPE_SUMMARY;
use oneiron::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerAttemptExecution, DreamerAttemptExecutor, EdgeActorClass, EntityId, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, Vault, VaultConfig, WakeAttemptContext,
    WakePassDeadline, WriteActor,
};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

/// The vault clock's fixed time for every test here (cf. `feeds.rs`): admit, complete and
/// attempt-context nows derive from it, never from the wall.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A rooted vault with its install enrolled, its embedded owner and proof.
/// The owner's Grant acts on `ThisInstall` need the full five-step install first.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
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
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

/// An enabled, active agent definition the owner creates as `[seed; 16]`.
fn create_agent(fixture: &Fixture, seed: u8, agent_id: &str) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "self-model read fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the agent");
    id
}

/// The owner's live Grant naming `read` and `self.memory.self_model` for `agent`.
/// Returns the grant's row.
fn grant_self_model(fixture: &Fixture, agent: EntityId) -> EntityId {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "self.memory.self_model".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints the self-model Grant");
    assert!(
        minted.grant.confers,
        "the self-model Grant confers for agent {agent:?}"
    );
    minted.grant.grant_ref
}

// --- Self-model SUMMARY producer fixture: the public Dreamer path, no placeholders ---
//
// Each summary is declared with purpose `self_model` and its own agent as requester, admitted
// on the Micro lane, composed by `ScopeSummaryExecutor` with a scripted backend answering one
// `{"text", "keep"}` reply, then completed; the new SUMMARY id is the pre/post set diff. Two
// summaries use separate owner-written conversations and distinct instructions, so neither the
// declaration coalesces nor the composition memo reuses the other's work.

/// The executor's fallback for non-summary attempts, which this fixture never admits.
struct NoInner;

impl DreamerAttemptExecutor for NoInner {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!("only scope summaries run here")
    }
}

/// The scripted backend: one composed reply, no network.
struct ScriptedBackend {
    next: Mutex<Option<LlmResponse>>,
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let response = self.next.lock().expect("script").take().expect("one call");
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::LlmError::Fatal(
            oneiron::FatalLlmError::InvalidRequest,
        ))
    }
}

/// The one reply the scripted backend gives: exactly `text` and `keep`, text non-blank.
fn summary_response(text: &str) -> LlmResponse {
    let body = json!({"text": text, "keep": ""}).to_string();
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: body,
                signature: None,
            }],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
        reply_assertions: ReplyAssertions::default(),
        token_scores: None,
    }
}

/// Drives an immediately-ready future with a noop waker: no runtime, no sleep.
fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("executor unexpectedly pending"),
    }
}

/// The host egress the OwnServer extraction runs under: every fixture call permitted.
fn allow_egress(_: &LlmRequest) -> bool {
    true
}

/// One trunk TURN carrying `text` as its user line.
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

/// A conversation the owner writes with two trunk TURNs; returns its id.
fn seed_conversation(vault: &Vault, owner: EntityId, first: &str, second: &str) -> EntityId {
    let host = vault.memory(owner, EdgeActorClass::Human);
    let conversation = EntityId::from_hex(
        &host
            .conversations_create(&ConversationCreateInput {
                id: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: json!({}),
                text: None,
            })
            .expect("owner creates the conversation")
            .id,
    )
    .expect("conversation id");
    let first = host
        .conversations_records_append(&trunk_record(conversation, None, first))
        .expect("first turn");
    host.conversations_records_append(&trunk_record(conversation, Some(&first.id), second))
        .expect("second turn");
    conversation
}

/// Widens the vault's inference defaults so the OwnServer extraction is admitted.
fn widen_inference(vault: &Vault) {
    let mut table = vault.purpose_default_table().expect("default table");
    table.extraction_max_locality = ModelLocality::OwnServer;
    table
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .expect("extraction row")
        .locality = ModelLocality::OwnServer;
    vault
        .set_purpose_default_table(&table)
        .expect("widened table");
}

/// Composes one self-model SUMMARY for `requester` over `conversation` with words `text`,
/// following `instruction`, at queue time `now` (from `T0`, never the wall). Returns the new
/// SUMMARY's id, the pre/post set diff, after completing its attempt.
fn seed_one_summary(
    vault: &Vault,
    requester: EntityId,
    conversation: EntityId,
    text: &str,
    instruction: &str,
    now: u64,
) -> EntityId {
    let before: std::collections::BTreeSet<EntityId> = vault
        .entities_by_type(ENTITY_TYPE_SUMMARY)
        .expect("list summaries")
        .into_iter()
        .collect();
    let scope = ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: false,
    };
    let queued = vault
        .request_scope_summary_for(
            &ScopeSummaryRequest {
                target: ScopeSummaryTarget::Scope {
                    scope,
                    land_on: None,
                    as_record: false,
                },
                requester: WriteActor::new(requester, EdgeActorClass::Agent),
            },
            "self_model",
        )
        .expect("declare self-model summary");
    assert!(
        !queued.coalesced,
        "each declaration admits its own work for requester {requester:?}"
    );
    let store = DreamerRunnerStore::new(vault);
    let admitted = match store
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "fixture".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit micro attempt")
    {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => *admitted,
        other => panic!("scope-summary attempt was not admitted: {other:?}"),
    };
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let backend = ScriptedBackend {
        next: Mutex::new(Some(summary_response(text))),
    };
    let model = ModelId::new("test/model@r1").expect("model");
    let host = HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: model.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        },
        extraction_egress: Some(&allow_egress),
    };
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0u64));
    let mut executor = ScopeSummaryExecutor::new(
        NoInner,
        &backend,
        &guard,
        vault.dreamer_authority().expect("dreamer authority"),
        model,
        host,
        Some(instruction),
    );
    let mut ctx = WakeAttemptContext {
        vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "wake",
        now_ms: now.saturating_mul(1000),
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let outcome = block_on_ready(executor.execute(&admitted, &mut ctx)).expect("execute summary");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "summary did not complete: {outcome:?}"
    );
    let _ = store
        .complete(CompleteDreamerAttempt {
            id: admitted.status.attempt.id,
            lease_owner: "fixture".to_owned(),
            attempt_count: admitted.status.attempt.attempt_count,
            now: now.saturating_add(1),
        })
        .expect("complete attempt");
    let after: Vec<EntityId> = vault
        .entities_by_type(ENTITY_TYPE_SUMMARY)
        .expect("list summaries");
    let fresh: Vec<EntityId> = after
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect();
    assert_eq!(
        fresh.len(),
        1,
        "one new SUMMARY for requester {requester:?}"
    );
    let summary = fresh[0];
    assert_eq!(
        vault
            .scope_summary_metadata(&summary)
            .expect("summary doc")
            .purpose
            .id,
        "self_model",
        "the new SUMMARY carries purpose self_model"
    );
    summary
}

/// An agent with no Grant is refused FORBIDDEN, not unknown-verb BAD_REQUEST.
/// On main the verb is unknown, so the code is BAD_REQUEST and this fails.
#[test]
fn agent_with_no_grant_is_refused_forbidden() {
    let fixture = rooted_vault();
    let agent = create_agent(&fixture, 0x60, "owen");
    let memory = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let missing = EntityId::from_bytes([0x62; 16])
        .expect("summary id")
        .to_hex();
    let err = invoke(
        &memory,
        "self.memory.self_model",
        json!({"summary_ref": missing}),
    )
    .expect_err("an agent with no Grant is refused");
    assert_eq!(
        err.code, MEMORY_CODE_FORBIDDEN,
        "a no-grant refusal is FORBIDDEN, not unknown-verb BAD_REQUEST: {err:?}"
    );
}

/// The holder reads its own lane with a live revision; another agent's readable self-model
/// answers not_own, never its text; and that other self-model reads for its own holder.
/// Each SUMMARY is Dreamer-composed for its own agent requester. On main the fixture seeds
/// (all public doors) and the first invoke fails as unknown verb, as required.
#[test]
fn holder_reads_own_lane_with_live_revision() {
    let fixture = rooted_vault();
    let owen = create_agent(&fixture, 0x60, "owen");
    let yuki = create_agent(&fixture, 0x61, "yuki");
    grant_self_model(&fixture, owen);
    grant_self_model(&fixture, yuki);
    widen_inference(&fixture.vault);
    let owen_conv = seed_conversation(&fixture.vault, fixture.owner, "the plan", "the first step");
    let yuki_conv = seed_conversation(
        &fixture.vault,
        fixture.owner,
        "the sketch",
        "the second step",
    );
    assert!(
        fixture
            .vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .expect("list summaries")
            .is_empty(),
        "no SUMMARY before the fixture seeds"
    );
    let owen_summary = seed_one_summary(
        &fixture.vault,
        owen,
        owen_conv,
        "owen is steady",
        "Summarize these records for owen.",
        T0,
    );
    let yuki_summary = seed_one_summary(
        &fixture.vault,
        yuki,
        yuki_conv,
        "yuki is bright",
        "Summarize these records for yuki.",
        T0.saturating_add(2),
    );
    let memory = fixture.vault.memory(owen, EdgeActorClass::Agent);
    let own = invoke(
        &memory,
        "self.memory.self_model",
        json!({"summary_ref": owen_summary.to_hex()}),
    )
    .expect("the holder reads its own self-model");
    assert_eq!(
        own["value"]["state"],
        json!("read"),
        "the holder's own self-model reads: {own}"
    );
    assert_eq!(
        own["value"]["text"],
        json!("owen is steady"),
        "the Read carries the holder's own words: {own}"
    );
    assert!(
        own["value"]["revision"]
            .as_array()
            .is_some_and(|bytes| bytes.len() == 16),
        "the Read carries its live 16-byte revision, never null: {own}"
    );
    assert!(
        own.get("narrowing").is_some(),
        "the serving receipt travels: {own}"
    );
    let other = invoke(
        &memory,
        "self.memory.self_model",
        json!({"summary_ref": yuki_summary.to_hex()}),
    )
    .expect("another agent's self-model answers Absent, never refused");
    assert_eq!(
        other["value"]["state"],
        json!("absent"),
        "another agent's self-model is Absent: {other}"
    );
    assert_eq!(
        other["value"]["why"],
        json!("not_own"),
        "another agent's readable self-model answers not_own: {other}"
    );
    assert!(
        other["value"].get("text").is_none(),
        "another agent's text is never served: {other}"
    );
    let yuki_memory = fixture.vault.memory(yuki, EdgeActorClass::Agent);
    let yuki_own = invoke(
        &yuki_memory,
        "self.memory.self_model",
        json!({"summary_ref": yuki_summary.to_hex()}),
    )
    .expect("the other holder reads its own self-model");
    assert_eq!(
        yuki_own["value"]["state"],
        json!("read"),
        "the other's self-model reads for its holder: {yuki_own}"
    );
    assert_eq!(
        yuki_own["value"]["text"],
        json!("yuki is bright"),
        "the other's Read carries its own words: {yuki_own}"
    );
}

/// The Grant revoked, the same call is refused again: the verb-standing check is live.
/// Before revoke the holder reads Absent (the SUMMARY is missing, not refused); after
/// revoke the same input is FORBIDDEN. On main the first invoke is unknown verb and fails.
#[test]
fn revoked_grant_is_refused_again_live() {
    let fixture = rooted_vault();
    let agent = create_agent(&fixture, 0x60, "owen");
    let grant = grant_self_model(&fixture, agent);
    let memory = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let missing = EntityId::from_bytes([0x62; 16])
        .expect("summary id")
        .to_hex();
    let before = invoke(
        &memory,
        "self.memory.self_model",
        json!({"summary_ref": missing}),
    )
    .expect("the holder reads before revoke");
    assert_eq!(
        before["value"]["state"],
        json!("absent"),
        "a missing SUMMARY answers Absent, not refused: {before}"
    );
    assert_eq!(
        before["value"]["why"],
        json!("unreadable"),
        "a missing SUMMARY is unreadable: {before}"
    );
    assert!(
        before.get("narrowing").is_some(),
        "the serving receipt travels: {before}"
    );
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: grant,
            seen: None,
        },
    )
    .expect("owner revokes the Grant");
    assert!(revoked.changed, "the revoke lands");
    let err = invoke(
        &memory,
        "self.memory.self_model",
        json!({"summary_ref": missing}),
    )
    .expect_err("the revoked Grant is refused again");
    assert_eq!(
        err.code, MEMORY_CODE_FORBIDDEN,
        "a revoked Grant is FORBIDDEN, not unknown-verb BAD_REQUEST: {err:?}"
    );
}
