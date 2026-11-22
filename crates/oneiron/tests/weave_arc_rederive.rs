//! ARCH-0053 (canon mirror generated/llms-full.txt:346026): "The weave
//! re-derives arcs from retained spans. An arc is the thread that runs across
//! sessions." The code keeps two mechanisms (SUMMARY-SOURCE = A, mirror:343370):
//! the Weave recipe queues a Scope summary of each retained conversation,
//! bound to its receipt; an Arc derives from its closed sittings' summary
//! lines through the Arc gate, with the shared Nightly/Timer sweep as its
//! backstop. FIX [WEAVE-ARC-REDERIVE-CANON-VS-SUMMARY-SOURCE].
//!
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test weave_arc_rederive
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::dreamer_consolidation::{DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE, ScopeSummaryExecutor};
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
    DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptStatus,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use oneiron::dreamer_wake::{WakeIdleState, WakePolicyDecision, WakeRecipe};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::session_lifecycle::{SessionClosePredicate, SessionEndWake, SessionMintOutcome};
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::turn_sitting::join_turn_to_sitting;
use oneiron::test_doors::weave_arc_rederive::sweep_due_arcs;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerWakeDriver, EdgeActorClass, EntityId,
    FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, RunWakePass, Vault,
    VaultConfig, WakeAttemptContext, WakeCancellation, WakePassDeadline, WakeTrigger, WriteActor,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;
use serde_json::json;

const T0: u64 = 1_790_000_000;
const OLD_LINE: &str = "The copper plan is ready.";
const NEW_LINE: &str = "The violet route replaces the copper plan.";
const OTHER_LINE: &str = "The silver bridge is open.";
const RAW_ONE: &str = "raw source alpha, not a sitting summary";
const RAW_TWO: &str = "raw source beta, not a sitting summary";
const BUDGET: &str = "weave-arc-proof";
const WORKER: &str = "weave-arc-proof-worker";

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: temporary vault directory");
        let clock = ManualClock::new(T0);
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("FIXTURE: owned vault");
        let owner = vault.ensure_embedded_owner_actor().expect("FIXTURE: owner");
        let issuer = provision_engine_machines(&vault);
        bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: bound owner");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: authenticated owner");
        let mut defaults = vault
            .purpose_default_table()
            .expect("FIXTURE: inference defaults");
        defaults.extraction_max_locality = ModelLocality::OwnServer;
        defaults
            .purposes
            .get_mut(&CallPurpose::Extraction)
            .expect("FIXTURE: extraction row")
            .locality = ModelLocality::OwnServer;
        vault
            .set_purpose_default_table(&defaults)
            .expect("FIXTURE: scripted inference allowed");
        Self {
            vault,
            clock,
            owner,
            proof,
            _dir: dir,
        }
    }

    fn now(&self) -> u64 {
        self.vault.now_recorded_at()
    }

    fn owner_actor(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    fn slow_arc_threshold(&self) {
        let mut recipe = self
            .vault
            .dreamer_recipe_policy()
            .expect("FIXTURE: recipe policy");
        recipe.arc_min_new_statements = 64;
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.proof),
                SetSetting::vault_value(
                    "dreamer.wake.recipe_policy",
                    serde_json::to_value(&recipe).unwrap(),
                ),
            )
            .expect("FIXTURE: owner sets Arc threshold");
        assert_eq!(
            self.vault
                .dreamer_recipe_policy()
                .unwrap()
                .arc_min_new_statements,
            64,
            "FIXTURE: a single new statement is below the Arc threshold"
        );
    }

    fn say(&self, conversation: EntityId, words: &str) -> EntityId {
        let turn = self.vault.new_entity_id().expect("FIXTURE: TURN id");
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                project: None,
                messages: vec![WitnessMessage {
                    id: Some(self.vault.new_entity_id().unwrap().to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: words.to_owned(),
                    parts: None,
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: self.now(),
                assertions: WitnessAssertions::default(),
            })
            .expect("FIXTURE: witness public source words");
        turn
    }

    fn close_sitting(
        &self,
        conversation: EntityId,
        words: &str,
    ) -> (EntityId, EntityId, AttemptId) {
        let key = self
            .vault
            .local_session_key(self.owner)
            .expect("FIXTURE: local sitting key");
        let session = match self
            .vault
            .mint_session(key, self.now())
            .expect("FIXTURE: mint sitting")
        {
            SessionMintOutcome::Minted(id) => id,
            other => panic!("FIXTURE: no prior open sitting: {other:?}"),
        };
        let turn = self.say(conversation, words);
        assert_eq!(
            join_turn_to_sitting(&self.vault, &turn, &session).unwrap(),
            Some(session),
            "FIXTURE: source TURN belongs to this sitting"
        );
        let ended = self
            .vault
            .end_session_with_wake(
                &session,
                SessionClosePredicate::Explicit,
                self.now(),
                &SessionEndWake::none(session, 0),
            )
            .expect("FIXTURE: close sitting");
        assert!(ended.is_some(), "FIXTURE: the sitting really closed");
        let record = self
            .vault
            .session_lifecycle_record(&session)
            .unwrap()
            .unwrap();
        let attempt = AttemptId::from_bytes(
            &record
                .summary_attempt
                .expect("FIXTURE: close queued summary"),
        )
        .expect("FIXTURE: summary attempt id");
        (session, turn, attempt)
    }

    fn summaries(&self) -> Vec<DreamerAttemptStatus> {
        let store = DreamerRunnerStore::new(&self.vault);
        AttemptQueue::new(&self.vault)
            .list()
            .unwrap()
            .into_iter()
            .filter(|row| row.kind == DreamerConsolidationScope::Micro.attempt_kind())
            .map(|row| store.status(row.id).unwrap().unwrap())
            .filter(|row| row.payload.attempt_type == DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE)
            .collect()
    }

    fn pending_arcs(&self) -> Vec<DreamerAttemptStatus> {
        self.summaries()
            .into_iter()
            .filter(|row| {
                field(&row.payload.input, "arc").is_some() && !row.attempt.state.is_terminal()
            })
            .collect()
    }

    fn one_pending_arc(&self, message: &str) -> DreamerAttemptStatus {
        let mut rows = self.pending_arcs();
        assert_eq!(rows.len(), 1, "{message}");
        rows.remove(0)
    }

    fn compose(
        &self,
        expected: AttemptId,
        reply: serde_json::Value,
        instruction: &str,
    ) -> (EntityId, serde_json::Value) {
        let store = DreamerRunnerStore::new(&self.vault);
        let admitted = match store
            .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
                scope: DreamerConsolidationScope::Micro,
                local_node_id: 1,
                claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
                admission: AdmitDreamerAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: self.now(),
                    budget_id: BUDGET.to_owned(),
                    budget_total_units: 100_000,
                    reserve_units: 100,
                    started_milestone: None,
                },
            })
            .expect("FIXTURE: admit summary")
        {
            DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
                a,
            )) => *a,
            other => panic!("FIXTURE: summary not admitted: {other:?}"),
        };
        assert_eq!(
            admitted.status.attempt.id, expected,
            "FIXTURE: run the requested summary, not unrelated queued work"
        );
        let backend = RecordingReply {
            reply: Mutex::new(Some(reply.to_string())),
            users: Mutex::new(Vec::new()),
        };
        let guard =
            BudgetGuard::with_reserve_units(BUDGET, 100_000, 100, BudgetExhaustionPolicy::Suspend);
        let model = ModelId::new("test/weave-arc@1").unwrap();
        let inference = HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model: model.clone(),
                locality: ModelLocality::OwnServer,
                keyless: false,
            },
            extraction_egress: Some(&allow_egress),
        };
        let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
        let mut executor = ScopeSummaryExecutor::new(
            NoInner,
            &backend,
            &guard,
            self.vault.dreamer_authority().unwrap(),
            model,
            inference,
            Some(instruction),
        )
        .with_window_tokens(Some(0)); // Unknown window: deliberately exercise the one-call path.
        let mut ctx = WakeAttemptContext {
            vault: &self.vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: BUDGET,
            now_ms: self.now() * 1000,
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        };
        let outcome =
            ready(executor.execute(&admitted, &mut ctx)).expect("FIXTURE: compose summary");
        assert!(
            matches!(outcome, DreamerAttemptExecution::Completed { .. }),
            "FIXTURE: summary completed rather than parked: {outcome:?}"
        );
        store
            .complete(CompleteDreamerAttempt {
                id: expected,
                lease_owner: WORKER.to_owned(),
                attempt_count: admitted.status.attempt.attempt_count,
                now: self.now(),
            })
            .expect("FIXTURE: complete the leased attempt");
        let status = self.vault.scope_summary_status(expected).unwrap();
        assert_eq!(
            status.state, "completed",
            "LANDING: the summary status reports completion"
        );
        let summary =
            EntityId::from_hex(&status.result.expect("LANDING: model result landed").summary)
                .unwrap();
        let users = backend.users.lock().unwrap();
        assert_eq!(
            users.len(),
            1,
            "MODEL: exactly one scripted narrative input was read"
        );
        (
            summary,
            serde_json::from_str(&users[0]).expect("MODEL: structured summary input"),
        )
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

fn canonical(conversation: EntityId) -> ScopeSelector {
    ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: true,
    }
}

fn session_reply(text: &str) -> serde_json::Value {
    json!({"lines": [{"text": text, "turn_refs": ["T1"]}], "keep": ""})
}

fn arc_reply(text: &str, refs: &[&str]) -> serde_json::Value {
    json!({"lines": [{"text": text, "turn_refs": refs}], "keep": "", "open_turns": []})
}

struct NoInner;
impl DreamerAttemptExecutor for NoInner {
    async fn execute(
        &mut self,
        _: &DreamerAdmittedAttempt,
        _: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!("FIXTURE: only scope-summary attempts reach this executor")
    }
}

struct DeferModelWork;
impl DreamerAttemptExecutor for DeferModelWork {
    async fn execute(
        &mut self,
        _: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        Ok(DreamerAttemptExecution::Deferred {
            completed_units: 0,
            retry_at: ctx.now_ms / 1000 + 1,
            step_bindings: Vec::new(),
        })
    }
}

struct RecordingReply {
    reply: Mutex<Option<String>>,
    users: Mutex<Vec<String>>,
}
impl LlmBackend for RecordingReply {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        let user = request
            .messages
            .iter()
            .filter(|m| matches!(m.role, LlmMessageRole::User))
            .flat_map(|m| &m.content)
            .filter_map(|part| match part {
                ContentPart::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        self.users.lock().unwrap().push(user);
        let text = self
            .reply
            .lock()
            .unwrap()
            .take()
            .expect("MODEL: one scripted reply only");
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text,
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }
    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::LlmError::Fatal(
            oneiron::FatalLlmError::InvalidRequest,
        ))
    }
}

fn allow_egress(_: &LlmRequest) -> bool {
    true
}

fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => {} // Driver yields at attempt boundaries; no I/O in this fixture.
        }
    }
}

/// ARCH-0053 (mirror:346026): the implemented Weave queues a Scope summary
/// for every retained conversation; this is not a cross-session Arc request.
#[test]
fn weave_queues_each_retained_conversation_summary_bound_to_its_receipt() {
    let f = Fixture::new();
    let conversations = [
        f.vault.new_entity_id().unwrap(),
        f.vault.new_entity_id().unwrap(),
    ];
    for conversation in conversations {
        let turn = f.say(conversation, "Alice returns tomorrow with a project note.");
        assert!(
            f.vault
                .resolve_dag_scope(&canonical(conversation))
                .unwrap()
                .records
                .contains(&turn),
            "FIXTURE: each conversation has a retained canonical DAG"
        );
    }
    let mut policy = f.vault.dreamer_wake_policy().unwrap();
    policy.wake_grain_turns = 100;
    policy.new_records = 1;
    f.vault.set_dreamer_wake_policy(&f.proof, policy).unwrap();
    while f.vault.sieve_pass(f.now()).unwrap().more {}
    f.clock.set(T0 + policy.quiet_weave_secs + policy.idle_secs);
    let wake = f
        .vault
        .enqueue_due_dreamer_wake(
            WakeIdleState {
                running_turns: false,
                live_background_work: false,
                compute_available: true,
                last_inbound_at: T0,
            },
            f.now(),
        )
        .unwrap();
    assert_eq!(
        wake.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave
        },
        "FIXTURE: public wake policy selected the Weave recipe, not Continuous or Nightly"
    );
    let receipt = match wake.attempt.expect("FIXTURE: wake receipt") {
        EnqueueDreamerAttemptOutcome::Enqueued(row)
        | EnqueueDreamerAttemptOutcome::Existing(row) => row.attempt.id,
        other => panic!("FIXTURE: unknown enqueue outcome: {other:?}"),
    };
    let mut driver = DreamerWakeDriver::new(
        &f.vault,
        BUDGET,
        WakePassDeadline::with_clock(180_000, Arc::new(|| 0)),
    );
    ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: WORKER.to_owned(),
            budget_total_units: 100_000,
            reserve_units: 100,
            now: f.now(),
            host_scope: None,
            destination_bound: None,
        },
        &mut DeferModelWork,
        &WakeCancellation::new(),
    ))
    .expect("FIXTURE: run Weave receipt without a model");
    assert_eq!(
        DreamerRunnerStore::new(&f.vault)
            .status(receipt)
            .unwrap()
            .unwrap()
            .attempt
            .state,
        AttemptState::Completed,
        "WEAVE: the recipe receipt completed"
    );
    assert!(
        f.vault
            .dreamer_wake_recipe_inputs()
            .unwrap()
            .iter()
            .all(|t| t.recipe != WakeRecipe::Weave),
        "WEAVE: the completed receipt consumed its durable recipe input"
    );
    let rows = f.summaries();
    let requested: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| {
            field(&row.payload.input, "scope")
                .and_then(|scope| field(scope, "conversation"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        requested,
        conversations
            .into_iter()
            .map(|id| id.to_hex())
            .collect::<BTreeSet<_>>(),
        "WEAVE_SCOPE: every retained conversation has its own queued Scope summary"
    );
    assert_eq!(
        rows.len(),
        2,
        "WEAVE_SCOPE: exactly one Scope child per retained conversation"
    );
    for row in rows {
        assert_eq!(
            row.payload.parent_attempt,
            Some(receipt),
            "WEAVE_LINEAGE: each conversation summary is bound to the Weave receipt"
        );
        assert_eq!(
            DreamerRunnerStore::new(&f.vault)
                .run_tree(row.attempt.id)
                .unwrap()
                .unwrap()
                .parent_attempt,
            Some(receipt),
            "WEAVE_LINEAGE: durable run-tree lineage names that receipt"
        );
        let scope = field(&row.payload.input, "scope").unwrap();
        assert_eq!(
            field(scope, "path").and_then(Value::as_str),
            Some("canonical"),
            "WEAVE_SCOPE: summary reads the retained canonical path"
        );
        assert_eq!(
            field(scope, "include_forks").and_then(Value::as_bool),
            Some(true),
            "WEAVE_SCOPE: the conversation summary includes retained forks"
        );
        assert!(
            field(&row.payload.input, "arc").is_none(),
            "WEAVE_SCOPE: Weave requested Scope, not Arc"
        );
        assert!(
            f.vault
                .scope_summary_status(row.attempt.id)
                .unwrap()
                .result
                .is_none(),
            "WEAVE_QUEUE: queuing a Scope child requires no model or landed prose"
        );
    }
}

/// ARCH-0053 (mirror:346026), refined by SUMMARY-SOURCE = A (mirror:343370):
/// an Arc crosses closed sittings and reads their generated summary lines.
#[test]
fn arc_gate_composes_from_two_closed_sittings_summary_lines_and_lands_exact_covers() {
    let f = Fixture::new();
    let conversation = f.vault.new_entity_id().unwrap();
    let (_, turn_one, one) = f.close_sitting(conversation, RAW_ONE);
    f.clock.set(T0 + 1);
    let (_, turn_two, two) = f.close_sitting(conversation, RAW_TWO);
    let (lower_one, _) = f.compose(one, session_reply(OLD_LINE), "Summarize the sitting.");
    let (lower_two, _) = f.compose(two, session_reply(OTHER_LINE), "Summarize the sitting.");
    let arc = f.one_pending_arc("ARC_GATE: both closed sitting summaries make the first Arc due");
    let (summary, input) = f.compose(
        arc.attempt.id,
        arc_reply("The two plans span sittings.", &["T1", "T2"]),
        "Summarize the closed sittings.",
    );
    let sittings = input["sittings"].as_str().unwrap();
    assert!(
        sittings.contains(OLD_LINE) && sittings.contains(OTHER_LINE),
        "ARC_LINES: the actual model input contains both closed sittings' generated lines"
    );
    assert_eq!(
        input["turns"], "",
        "ARC_LINES: whole sitting lines do not expand raw TURN words"
    );
    assert!(
        !input.to_string().contains(RAW_ONE) && !input.to_string().contains(RAW_TWO),
        "ARC_LINES: the narrative call reads summary lines, not raw source prose"
    );
    assert!(
        input["editor_text"].is_null(),
        "ARC_SOURCE: no earlier Arc body is model input"
    );
    let covers: BTreeSet<_> = f
        .vault
        .scope_summary_covers(&summary)
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        covers,
        BTreeSet::from([turn_one, turn_two]),
        "ARC_COVERS: landed Arc covers the cited TURNs across both sittings"
    );
    let meta = f.vault.scope_summary_metadata(&summary).unwrap();
    assert_eq!(
        meta.purpose.id, "milestone_arc_narrative",
        "ARC_LANDING: landed projection is an Arc"
    );
    for lower in [lower_one, lower_two] {
        assert!(
            meta.derivation
                .sources
                .iter()
                .any(|pin| pin.id == lower.to_hex()),
            "ARC_PINS: the landed Arc pins each source sitting summary"
        );
    }
}

/// ARCH-0053 (mirror:346026), SUMMARY-SOURCE = A (mirror:343370): a newly
/// generated sitting line replaces the old line in the next Arc generation.
/// This is regeneration, NOT an editor patch (which rereads cited TURNs).
#[test]
fn replacing_a_generated_sitting_line_rederives_the_arc_from_the_new_line() {
    let f = Fixture::new();
    f.slow_arc_threshold();
    let conversation = f.vault.new_entity_id().unwrap();
    let (_, turn, session_attempt) = f.close_sitting(conversation, RAW_ONE);
    let (old_lower, _) = f.compose(
        session_attempt,
        session_reply(OLD_LINE),
        "Summarize the sitting.",
    );
    let first = f.one_pending_arc("FIXTURE: first Arc queued");
    let (old_arc, _) = f.compose(
        first.attempt.id,
        arc_reply("Old Arc prose.", &["T1"]),
        "Summarize the closed sittings.",
    );
    f.clock.set(T0 + 1);
    let remake = f
        .vault
        .rederive_scope_summary(old_lower, f.owner_actor())
        .unwrap();
    // Changing the host instruction changes the composition parameters, so this
    // legitimate regeneration cannot hit the old sitting's exact-reuse memo.
    let (new_lower, _) = f.compose(
        remake.attempt,
        session_reply(NEW_LINE),
        "Regenerate the sitting in a new wording.",
    );
    assert_ne!(
        new_lower, old_lower,
        "FIXTURE: a new sitting summary actually landed"
    );
    let next = f.one_pending_arc("ARC_REDERIVE: replacing a sitting's old line makes its Arc stale and immediately queued below the novelty threshold");
    assert_eq!(
        field(&next.payload.input, "previous").and_then(Value::as_str),
        Some(old_arc.to_hex().as_str()),
        "ARC_PROJECTION: the gate advances the existing Arc, not a parallel declaration"
    );
    let (new_arc, input) = f.compose(
        next.attempt.id,
        arc_reply("New Arc prose.", &["T1"]),
        "Summarize the closed sittings.",
    );
    assert_ne!(
        new_arc, old_arc,
        "ARC_REDERIVE: the Arc landed a new generation"
    );
    let sittings = input["sittings"].as_str().unwrap();
    assert!(
        sittings.contains(NEW_LINE) && !sittings.contains(OLD_LINE),
        "ARC_NEW_LINE: the new Arc model input reads the replacement sitting line, not the old one"
    );
    assert!(
        input["editor_text"].is_null() && !input.to_string().contains("Old Arc prose."),
        "ARC_SOURCE: an Arc is not composed from its earlier prose"
    );
    let meta = f.vault.scope_summary_metadata(&new_arc).unwrap();
    assert!(
        meta.derivation
            .sources
            .iter()
            .any(|pin| pin.id == new_lower.to_hex())
            && !meta
                .derivation
                .sources
                .iter()
                .any(|pin| pin.id == old_lower.to_hex()),
        "ARC_NEW_PIN: the new Arc pins the replacement sitting summary only"
    );
    assert_eq!(
        f.vault.scope_summary_covers(&new_arc).unwrap(),
        vec![turn],
        "ARC_REDERIVE: replacement prose preserves the exact retained TURN cover"
    );
}

/// ARCH-0053 (mirror:346026), SUMMARY-SOURCE = A (mirror:343370): an Arc
/// owed below its threshold is queued by the shared Nightly/Timer backstop.
#[test]
fn arc_backstop_rederives_an_owed_arc_at_the_nightly_cadence() {
    let f = Fixture::new();
    f.slow_arc_threshold();
    let conversation = f.vault.new_entity_id().unwrap();
    let (_, _, first_session) = f.close_sitting(conversation, RAW_ONE);
    f.compose(
        first_session,
        session_reply(OLD_LINE),
        "Summarize the sitting.",
    );
    let first = f.one_pending_arc("FIXTURE: first Arc queued");
    let (old_arc, _) = f.compose(
        first.attempt.id,
        arc_reply("First Arc prose.", &["T1"]),
        "Summarize the closed sittings.",
    );
    f.clock.set(T0 + 1);
    let (_, _, second_session) = f.close_sitting(conversation, RAW_TWO);
    f.compose(
        second_session,
        session_reply(OTHER_LINE),
        "Summarize the sitting.",
    );
    assert!(
        f.pending_arcs().is_empty(),
        "ARC_OWED: one added statement below threshold does not queue early"
    );
    let due = f
        .vault
        .next_arc_due_at()
        .unwrap()
        .expect("ARC_OWED: backstop due time is armed");
    assert_eq!(
        due,
        f.now() + f.vault.dreamer_wake_policy().unwrap().nightly_secs,
        "ARC_CADENCE: due time comes from the live nightly_secs policy row"
    );
    f.clock.set(due - 1);
    sweep_due_arcs(&f.vault, f.now()).unwrap();
    assert!(
        f.pending_arcs().is_empty(),
        "ARC_BACKSTOP: the sweep does not run an unaged Arc early"
    );
    f.clock.set(due);
    sweep_due_arcs(&f.vault, f.now()).unwrap();
    let next = f.one_pending_arc(
        "ARC_BACKSTOP: the shared sweep queues the owed Arc when its nightly cadence is reached",
    );
    assert_eq!(
        field(&next.payload.input, "previous").and_then(Value::as_str),
        Some(old_arc.to_hex().as_str()),
        "ARC_BACKSTOP: the due work continues the standing Arc projection"
    );
    let (summary, input) = f.compose(
        next.attempt.id,
        arc_reply("Backstop Arc prose.", &["T1", "T2"]),
        "Summarize the closed sittings.",
    );
    assert_ne!(
        summary, old_arc,
        "ARC_BACKSTOP: the owed Arc landed a new summary"
    );
    assert!(
        input["sittings"].as_str().unwrap().contains(OTHER_LINE),
        "ARC_BACKSTOP: the new Arc input includes the later sitting's line"
    );
    assert!(
        f.vault.next_arc_due_at().unwrap().is_none(),
        "ARC_BACKSTOP: successful landing clears owed time"
    );
}
