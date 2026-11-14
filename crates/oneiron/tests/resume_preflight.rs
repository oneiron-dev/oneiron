//! L8-23: a resumed pending step walks its recorded calls against the re-entered program.
//!
//! Entry 1 parks a step after a memory search and a claim put. Entry 2 re-enters with the same,
//! a pure-changed, an effect-changed, or an effect-swapped program: a pure change proceeds with
//! the divergence recorded, an effect change holds with the walk's report, a call swapped in
//! before the claim put ends the walk with the put unreached, and nothing re-fires. A changed
//! guest boundary alone is a report flag, not a refusal.
//!
//! PR2: the hold asks the owner once, and the owner answers `refire` or `leave` through a new
//! owner verb. A refire runs the changed effect once; a leave answers it `effect_changed_left`.
//! A refire that meets new drift parks again with the refire kept; a left tail commits with its
//! kept rows. A non-owner is refused, and the same drift asks once.
//!
//! Red on main: a changed guest boundary or a changed call holds the entry, and main's outcome
//! and hold carry no report. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test resume_preflight`

#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use oneiron::code_run::{
    CodeRunDeterminism, GatedActorWrite, SelfCall, SelfDispatchOutcome, SelfMemoryPutClaimCall,
    SelfMemorySearchCall,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorError, EngineExecutorLimits, EngineExecutorOutcome,
    EngineExecutorResult, EngineExecutorStatus, EngineNativeExecutor, JsCodeModeHost,
    JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome, ResumePreflightReport,
};
use oneiron::inbox::NotificationKind;
use oneiron::llm::ReplyAssertions;
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::code_run_answer::install_actor_ceiling;
use oneiron::test_doors::resume_preflight::restamp_guest_abi;
use oneiron::verbs::{
    ResumeDivergenceAnswer, ResumeDivergenceChoice, answer_code_run_resume_divergence_as,
};
use oneiron::{
    BudgetLease, ClaimCandidate, ClaimSubject, ContentPart, EdgeActorClass, EntityId,
    FatalLlmError, FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef,
    TimeRange, Vault, VaultConfig, WriteActor,
};

const CONFIGURED_MODEL_ID: &str = "seat/generative_reasoner@1cadcf6de87a";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("executor future unexpectedly pending"),
    }
}

struct ScriptedBackend {
    response: LlmResponse,
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn scripted_response(text: &str, raw_provider: serde_json::Value) -> LlmResponse {
    let mut usage = LlmUsage::zero();
    usage.raw_provider = raw_provider;
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        },
        usage,
        finish_reason: FinishReason::Stop,
        reply_assertions: ReplyAssertions::default(),
        token_scores: None,
    }
}

fn determinism_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(EntityId::now().as_bytes());
    seed[16..].copy_from_slice(EntityId::now().as_bytes());
    seed
}

fn owner_vault() -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (dir, vault, owner, proof)
}

fn executor_config(run_id: EntityId) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: "resume a parked step".to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()
            .expect("workspace test prompt package"),
        model: ModelId::new(CONFIGURED_MODEL_ID).expect("seat model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, determinism_seed()),
        limits: EngineExecutorLimits { soft_steps: 1 },
        wake: None,
    }
}

fn seed_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("seed person");
    id
}

/// The re-entered program entry 2 runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Same,
    PureChanged,
    EffectChanged,
    /// A new read before the recorded claim put: the walk ends at seq 1 on an effect tail.
    EffectSwapped,
}

/// Entry 1 parks after a memory search and a claim put; entry 2 and later run `reentered`.
/// In three-call mode each entry also puts C3, on its own predicate, whose object is the claim id
/// the host's answer to that entry's claim put names.
struct TwoEntryRuntime {
    entry: u8,
    reentered: Variant,
    subject: EntityId,
    claim: EntityId,
    new_claim: EntityId,
    claim3: EntityId,
    three_call: bool,
    /// The `error` string of every `Failed` answer the host gave entry 2 and later, in order.
    failures: Vec<String>,
}

impl TwoEntryRuntime {
    fn search_call(query: &str) -> SelfCall {
        SelfCall::MemorySearch(SelfMemorySearchCall::new(query, 5))
    }

    fn put_call(&self, id: EntityId, object: &str) -> SelfCall {
        self.put_call_on(id, "profile.favorite_drink", object)
    }

    fn put_call_on(&self, id: EntityId, predicate: &str, object: &str) -> SelfCall {
        SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                predicate,
                ClaimSubject::Entity(self.subject),
                rmpv::Value::from(object),
                0.8,
            ),
            TimeRange { start: 11, end: 11 },
            12,
        ))
    }

    fn run_entry(
        &mut self,
        host: &mut dyn JsCodeModeHost,
        calls: Vec<SelfCall>,
        deadline: bool,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        for call in calls {
            self.dispatch(host, call)?;
        }
        if deadline {
            host.stopped_at_step_deadline();
        }
        Ok(JsCodeModeStepOutcome::pending("probe observation"))
    }

    /// Dispatches one call and keeps the `error` of a `Failed` answer to entry 2 and later.
    fn dispatch(
        &mut self,
        host: &mut dyn JsCodeModeHost,
        call: SelfCall,
    ) -> oneiron::Result<SelfDispatchOutcome> {
        let response = host.dispatch_self(call)?;
        if self.entry >= 2
            && let SelfDispatchOutcome::Failed(failed) = &response.outcome
        {
            self.failures.push(failed.error.clone());
        }
        Ok(response.outcome)
    }

    /// Entry 1 makes (a) search "alpha", (b) put C1 and (c) put C3 whose object is the id the
    /// host's answer to (b) names; later entries change (b) to the new-object put under
    /// `EffectChanged`. Any answer to (b) other than a write falls back to C1's id.
    fn run_three_call_entry(
        &mut self,
        host: &mut dyn JsCodeModeHost,
        deadline: bool,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        let second = if self.entry >= 2 && self.reentered == Variant::EffectChanged {
            self.put_call(self.new_claim, "black tea")
        } else {
            self.put_call(self.claim, "green tea")
        };
        self.dispatch(host, Self::search_call("alpha"))?;
        let object = match self.dispatch(host, second)? {
            SelfDispatchOutcome::MemoryWrite(wrote) => wrote.id.to_hex(),
            _ => self.claim.to_hex(),
        };
        let third = self.put_call_on(self.claim3, "profile.favorite_snack", &object);
        self.dispatch(host, third)?;
        if deadline {
            host.stopped_at_step_deadline();
        }
        Ok(JsCodeModeStepOutcome::pending("probe observation"))
    }
}

impl JsCodeModeRuntime for TwoEntryRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        self.entry += 1;
        if self.three_call {
            let deadline = self.entry == 1;
            return self.run_three_call_entry(host, deadline);
        }
        match self.entry {
            1 => {
                let search = Self::search_call("alpha");
                let put = self.put_call(self.claim, "green tea");
                self.run_entry(host, vec![search, put], true)
            }
            _ => {
                let calls = match self.reentered {
                    Variant::Same => {
                        vec![
                            Self::search_call("alpha"),
                            self.put_call(self.claim, "green tea"),
                        ]
                    }
                    Variant::PureChanged => {
                        vec![
                            Self::search_call("alpha "),
                            self.put_call(self.claim, "green tea"),
                        ]
                    }
                    Variant::EffectChanged => {
                        vec![
                            Self::search_call("alpha"),
                            self.put_call(self.new_claim, "black tea"),
                        ]
                    }
                    Variant::EffectSwapped => {
                        vec![
                            Self::search_call("alpha"),
                            Self::search_call("beta"),
                            self.put_call(self.claim, "green tea"),
                        ]
                    }
                };
                self.run_entry(host, calls, false)
            }
        }
    }
}

fn run_turn<R: JsCodeModeRuntime>(
    vault: &Vault,
    actor: EntityId,
    config: &EngineExecutorConfig,
    response: LlmResponse,
    runtime: &mut R,
) -> EngineExecutorResult<EngineExecutorOutcome> {
    let backend = ScriptedBackend { response };
    let lease = BudgetLease::for_test("resume-preflight");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-resume-preflight",
    )
    .expect("gated actor write");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, runtime, &gated);
    block_on_ready(executor.run(config))
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    proof: AuthenticatedOwner,
    run_id: EntityId,
    config: EngineExecutorConfig,
    runtime: TwoEntryRuntime,
    last_hold: Option<ResumePreflightReport>,
}

impl Fixture {
    fn open(reentered: Variant) -> Self {
        Self::open_with(reentered, false)
    }

    fn open_three_call(reentered: Variant) -> Self {
        Self::open_with(reentered, true)
    }

    fn open_with(reentered: Variant, three_call: bool) -> Self {
        let (_dir, vault, _owner, proof) = owner_vault();
        let owen = seed_person(&vault);
        let yuki = seed_person(&vault);
        // The run's agent writes at the gate's Auto ceiling, so its proposed claim lands.
        install_actor_ceiling(&vault, &owen, "auto").expect("an auto ceiling");
        let (actor, subject) = (owen, yuki);
        let run_id = EntityId::now();
        let config = executor_config(run_id);
        let runtime = TwoEntryRuntime {
            entry: 0,
            reentered,
            subject,
            claim: EntityId::now(),
            new_claim: EntityId::now(),
            claim3: EntityId::now(),
            three_call,
            failures: Vec::new(),
        };
        Self {
            _dir,
            vault,
            actor,
            proof,
            run_id,
            config,
            runtime,
            last_hold: None,
        }
    }

    fn park(&mut self, expected: &[u64]) {
        let parked = run_turn(
            &self.vault,
            self.actor,
            &self.config,
            scripted_response("console.log('probe');", serde_json::json!({})),
            &mut self.runtime,
        )
        .expect("the stopped step parks");
        assert_eq!(
            parked.status,
            EngineExecutorStatus::Yielded { next_step_seq: 0 },
            "the step its deadline stopped parks at the same seq",
        );
        // Preconditions: the parked step put C1 once, and its record keeps both calls pending.
        assert!(
            self.vault
                .get_claim(&self.runtime.claim)
                .expect("a claim read")
                .is_some(),
            "the parked step's put landed C1",
        );
        if self.runtime.three_call {
            assert!(
                self.vault
                    .get_claim(&self.runtime.claim3)
                    .expect("a claim read")
                    .is_some(),
                "the parked three-call step put C3",
            );
        }
        let record = self
            .vault
            .get_code_run_replay_record(&self.run_id)
            .expect("the parked record reads")
            .expect("the parked record is present");
        let pending = record.pending_step.expect("the step parks pending");
        assert_eq!(
            (pending.guest_calls.as_slice(), pending.bridge_frontier),
            (
                expected,
                u64::try_from(expected.len()).expect("a small frontier")
            ),
            "the parked step keeps its calls",
        );
    }

    fn reenter(&mut self) -> EngineExecutorResult<EngineExecutorOutcome> {
        let outcome = run_turn(
            &self.vault,
            self.actor,
            &self.config,
            scripted_response("console.log('not asked');", serde_json::json!({})),
            &mut self.runtime,
        );
        if let Err(error) = &outcome {
            self.last_hold = held_report(error);
        }
        outcome
    }
}

#[test]
fn boundary_change_alone_replays_free_and_commits() {
    let mut fixture = Fixture::open(Variant::Same);
    fixture.park(&[0, 1]);
    restamp_guest_abi(&fixture.vault, fixture.run_id, [0; 32]).expect("restamp the guest boundary");
    let outcome = fixture
        .reenter()
        .expect("the restamped step resumes and commits");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the resumed step commits, then the run yields",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "exactly one claim C1 lands",
    );
    assert_eq!(outcome.replay_record.bridge_calls.len(), 2);
    assert_eq!(
        report_line(&outcome),
        Some(
            "steps 0-1 replay free \u{00b7} guest boundary changed \u{00b7} 0 effect steps would re-fire"
                .to_owned()
        ),
    );
    assert_eq!(
        recorded_boundary_changed(&fixture.vault, fixture.run_id),
        Some(true),
        "the drifted report is recorded beside the step",
    );
}

#[test]
fn pure_change_proceeds_with_divergence_recorded() {
    let mut fixture = Fixture::open(Variant::PureChanged);
    fixture.park(&[0, 1]);
    let outcome = fixture
        .reenter()
        .expect("the pure-changed step resumes and commits");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the resumed step commits, then the run yields",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "one claim C1 lands, not two",
    );
    assert_eq!(outcome.replay_record.bridge_calls.len(), 2);
    assert_eq!(
        report_line(&outcome),
        Some(
            "step 1 replays free \u{00b7} step 0 changed \u{00b7} 0 effect steps would re-fire"
                .to_owned()
        ),
    );
}

#[test]
fn effect_change_holds_with_report_and_fires_nothing() {
    let mut fixture = Fixture::open(Variant::EffectChanged);
    fixture.park(&[0, 1]);
    let frontier = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the parked record reads")
        .expect("the parked record is present")
        .pending_step
        .expect("the step parks pending")
        .bridge_frontier;
    let error = fixture
        .reenter()
        .expect_err("the effect-changed step holds");
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "the parked claim C1 stands",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.new_claim)
            .expect("a claim read")
            .is_none(),
        "no claim with the new object fires",
    );
    let record = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the held record reads")
        .expect("the held record is present");
    let pending = record.pending_step.expect("the step is still pending");
    assert_eq!(pending.bridge_frontier, frontier);
    assert_eq!(record.bridge_calls.len(), frontier as usize);
    assert_eq!(
        divergence_line(&error),
        Some(
            "step 0 replays free \u{00b7} step 1 changed \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
}

#[test]
fn swapped_effect_ends_the_walk_with_the_tail_unreached() {
    let mut fixture = Fixture::open(Variant::EffectSwapped);
    fixture.park(&[0, 1]);
    let frontier = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the parked record reads")
        .expect("the parked record is present")
        .pending_step
        .expect("the step parks pending")
        .bridge_frontier;
    let error = fixture
        .reenter()
        .expect_err("the walk ends on an effect tail and holds");
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "the parked claim C1 stands",
    );
    let record = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the held record reads")
        .expect("the held record is present");
    let pending = record.pending_step.expect("the step is still pending");
    assert_eq!(pending.bridge_frontier, frontier);
    assert_eq!(record.bridge_calls.len(), frontier as usize);
    // The put after the swapped-in read must not line up with the kept tail again: the held read
    // took no position, yet the walk ended there.
    assert_eq!(
        divergence_line(&error),
        Some(
            "step 0 replays free \u{00b7} step 1 unreached \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
}

#[test]
fn unchanged_resume_reports_clean_and_records_no_report() {
    let mut fixture = Fixture::open(Variant::Same);
    fixture.park(&[0, 1]);
    let outcome = fixture
        .reenter()
        .expect("the unchanged step resumes and commits");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the resumed step commits, then the run yields",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "one claim C1 lands",
    );
    assert_eq!(
        report_line(&outcome),
        Some("steps 0-1 replay free \u{00b7} 0 effect steps would re-fire".to_owned()),
    );
    assert_eq!(
        recorded_boundary_changed(&fixture.vault, fixture.run_id),
        None,
        "a clean report records no output",
    );
}

#[test]
fn owner_refire_runs_changed_effect_once() {
    let mut fixture = Fixture::open(Variant::EffectChanged);
    fixture.park(&[0, 1]);
    let error = fixture
        .reenter()
        .expect_err("the effect-changed step holds");
    assert_eq!(
        divergence_line(&error),
        Some(
            "step 0 replays free \u{00b7} step 1 changed \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
    assert_eq!(
        owner_asks(&fixture.vault),
        1,
        "the hold asks the owner once"
    );
    assert_eq!(
        answer(&fixture, "refire"),
        Some("refire_released".to_owned()),
    );
    let outcome = fixture.reenter().expect("the refired step commits");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the resumed step commits, then the run yields",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "C1 stands",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.new_claim)
            .expect("a claim read")
            .is_some(),
        "the refire put the new-object claim once",
    );
    let record = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the committed record reads")
        .expect("the committed record is present");
    assert!(
        record.pending_step.is_none(),
        "the refired step commits with no pending step",
    );
    assert_eq!(record.bridge_calls.len(), 2, "two bridge rows stand");
    assert_eq!(
        report_line(&outcome),
        Some(
            "step 0 replays free \u{00b7} step 1 changed \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
}

#[test]
fn owner_leave_answers_effect_changed_left() {
    let mut fixture = Fixture::open(Variant::EffectChanged);
    fixture.park(&[0, 1]);
    let parked_row = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the parked record reads")
        .expect("the parked record is present")
        .bridge_calls[1]
        .request
        .clone();
    let error = fixture
        .reenter()
        .expect_err("the effect-changed step holds");
    assert_eq!(
        divergence_line(&error),
        Some(
            "step 0 replays free \u{00b7} step 1 changed \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
    assert_eq!(answer(&fixture, "leave"), Some("left".to_owned()));
    let outcome = fixture.reenter().expect("the left step commits");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the resumed step commits, then the run yields",
    );
    assert_eq!(
        fixture.runtime.failures,
        vec!["effect_changed_left".to_owned()],
        "the runtime read exactly one left failure",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "C1 stands",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.new_claim)
            .expect("a claim read")
            .is_none(),
        "no claim with the new object fires",
    );
    let record = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the committed record reads")
        .expect("the committed record is present");
    assert_eq!(record.bridge_calls.len(), 2, "two bridge rows stand");
    assert_eq!(record.bridge_calls[1].seq, 1);
    assert_eq!(
        record.bridge_calls[1].request, parked_row,
        "the row at seq 1 is the recorded put of C1",
    );
}

#[test]
fn non_owner_answer_refused_and_asked_once() {
    let mut fixture = Fixture::open(Variant::EffectChanged);
    fixture.park(&[0, 1]);
    let line = "step 0 replays free \u{00b7} step 1 changed \u{00b7} 1 effect step would re-fire"
        .to_owned();
    let first = fixture.reenter().expect_err("the first re-entry holds");
    assert_eq!(divergence_line(&first), Some(line.clone()));
    let second = fixture.reenter().expect_err("the second re-entry holds");
    assert_eq!(divergence_line(&second), Some(line));
    assert_eq!(
        owner_asks(&fixture.vault),
        1,
        "the same drift asks the owner once",
    );
    let refusal = agent_answer_refusal(&fixture).expect("an agent is refused");
    assert!(
        refusal.starts_with(&format!("{MEMORY_CODE_FORBIDDEN}: ")),
        "the agent's answer is refused as the owner's act: {refusal}",
    );
    let third = fixture.reenter().expect_err("a third re-entry still holds");
    assert!(
        divergence_line(&third).is_some(),
        "the step still holds with its report",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.new_claim)
            .expect("a claim read")
            .is_none(),
        "no claim with the new object fires",
    );
}

#[test]
fn refire_then_dependent_change_parks_with_the_refire_kept() {
    let mut fixture = Fixture::open_three_call(Variant::EffectChanged);
    fixture.park(&[0, 1, 2]);
    let old_object = fixture
        .vault
        .get_claim(&fixture.runtime.claim3)
        .expect("a claim read")
        .expect("the parked step put C3")
        .value;
    let parked_row = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the parked record reads")
        .expect("the parked record is present")
        .bridge_calls[1]
        .request
        .clone();
    let error = fixture
        .reenter()
        .expect_err("the effect-changed step holds");
    assert_eq!(
        divergence_line(&error),
        Some(
            "steps 0, 2 replay free \u{00b7} step 1 changed \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
    assert_eq!(
        answer(&fixture, "refire"),
        Some("refire_released".to_owned()),
    );
    let parked = fixture
        .reenter()
        .expect("the refire parks again, not holds");
    assert_eq!(
        parked.status,
        EngineExecutorStatus::Yielded { next_step_seq: 0 },
        "the dry pass after a refire parks at the same seq",
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.new_claim)
            .expect("a claim read")
            .is_some(),
        "the new-object claim exists once",
    );
    let kept = fixture
        .vault
        .get_claim(&fixture.runtime.claim3)
        .expect("a claim read")
        .expect("C3 stands");
    assert_eq!(kept.value, old_object, "C3 still carries its old object");
    let record = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the parked record reads")
        .expect("the parked record is present");
    let pending = record.pending_step.expect("the step parks pending again");
    assert_eq!(pending.step_seq, 0);
    assert_eq!(record.bridge_calls.len(), 3);
    assert_eq!(record.bridge_calls[1].seq, 1);
    assert_ne!(
        record.bridge_calls[1].request, parked_row,
        "the pending step's row at seq 1 is the live put",
    );
    let again = fixture.reenter().expect_err("the new drift holds");
    assert_eq!(
        divergence_line(&again),
        Some(
            "steps 0-1 replay free \u{00b7} step 2 changed \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
    let asks = ask_seen(&fixture.vault);
    assert_eq!(asks.len(), 2, "two owner asks raised in total");
    let unseen: Vec<_> = asks
        .iter()
        .filter(|(_, seen, acked)| !seen && !acked)
        .collect();
    assert_eq!(
        unseen.len(),
        1,
        "only the newest ask is unanswered and unseen"
    );
    let digest = held_digest(&again).expect("the new hold has a digest");
    assert!(
        unseen[0].0.contains(&digest),
        "the unseen ask names the new drift",
    );
    assert!(
        asks.iter().any(|(_, seen, acked)| *seen && *acked),
        "the clear marks the old ask seen and acked",
    );
}

#[test]
fn owner_leave_on_unreached_tail_keeps_its_row() {
    let mut fixture = Fixture::open(Variant::EffectSwapped);
    fixture.park(&[0, 1]);
    let parked: Vec<rmpv::Value> = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the parked record reads")
        .expect("the parked record is present")
        .bridge_calls
        .iter()
        .map(|row| row.request.clone())
        .collect();
    let error = fixture.reenter().expect_err("the swapped walk holds");
    assert_eq!(
        divergence_line(&error),
        Some(
            "step 0 replays free \u{00b7} step 1 unreached \u{00b7} 1 effect step would re-fire"
                .to_owned()
        ),
    );
    assert_eq!(answer(&fixture, "leave"), Some("left".to_owned()));
    let outcome = fixture.reenter().expect("the left step commits");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the resumed step commits, then the run yields",
    );
    let left: Vec<_> = fixture
        .runtime
        .failures
        .iter()
        .filter(|error| error.as_str() == "effect_changed_left")
        .collect();
    assert_eq!(left.len(), 2, "the runtime read two left failures");
    assert!(
        fixture
            .vault
            .get_claim(&fixture.runtime.claim)
            .expect("a claim read")
            .is_some(),
        "C1 exists once",
    );
    let record = fixture
        .vault
        .get_code_run_replay_record(&fixture.run_id)
        .expect("the committed record reads")
        .expect("the committed record is present");
    assert!(
        record.pending_step.is_none(),
        "the left step commits with no pending step",
    );
    assert_eq!(record.bridge_calls.len(), 2, "both rows stand");
    assert_eq!(
        record
            .bridge_calls
            .iter()
            .map(|row| row.request.clone())
            .collect::<Vec<_>>(),
        parked,
        "the record keeps the search at 0 and the put of C1 at 1",
    );
}

// Every read of the L8-23 API sits below, so the red pin on main stubs these helpers alone.

/// The resume-preflight line the entry's outcome carries.
fn report_line(outcome: &EngineExecutorOutcome) -> Option<String> {
    outcome
        .resume_preflight
        .as_ref()
        .map(|report| report.to_string())
}

/// The resume-preflight line a held entry's error carries.
fn divergence_line(error: &EngineExecutorError) -> Option<String> {
    match error {
        EngineExecutorError::ResumeDivergence(report) => Some(report.to_string()),
        _ => None,
    }
}

/// Whether the report recorded beside step 0 names a changed guest boundary; `None` when the
/// step recorded no report.
fn recorded_boundary_changed(vault: &Vault, run: EntityId) -> Option<bool> {
    report_output(vault, run).map(|report| report.boundary_changed)
}

/// The report recorded beside step 0, when the step recorded one.
fn report_output(vault: &Vault, run: EntityId) -> Option<ResumePreflightReport> {
    let record = vault
        .get_code_run_replay_record(&run)
        .expect("the run's replay record reads")
        .expect("the run holds a replay record");
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == "executor/repl/000000.resume-preflight.json")?;
    let body = vault
        .get_code_run_raw_output(output)
        .expect("the report body reads")
        .expect("the report body is present");
    Some(serde_json::from_slice(&body).expect("the report parses"))
}

/// The held report a held entry's error carries.
fn held_report(error: &EngineExecutorError) -> Option<ResumePreflightReport> {
    match error {
        EngineExecutorError::ResumeDivergence(report) => Some(report.as_ref().clone()),
        _ => None,
    }
}

/// The effect digest of a held entry's report.
fn held_digest(error: &EngineExecutorError) -> Option<String> {
    held_report(error).map(|report| report.effect_digest())
}

/// The owner's answer to the fixture's held report: `choice` is `refire` or `leave`. Answers the
/// outcome as its serde snake name.
fn answer(fixture: &Fixture, choice: &str) -> Option<String> {
    let report = fixture.last_hold.clone()?;
    let choice = match choice {
        "refire" => ResumeDivergenceChoice::Refire,
        "leave" => ResumeDivergenceChoice::Leave,
        _ => return None,
    };
    let answered = answer_code_run_resume_divergence_as(
        &fixture.vault,
        &fixture.proof,
        ResumeDivergenceAnswer {
            run_ref: fixture.run_id,
            step_seq: report.step_seq,
            report_digest: report.effect_digest(),
            choice,
        },
    )
    .ok()?;
    serde_json::to_value(&answered.outcome)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
}

/// The agent's call of the answer verb by name through the generic verb door: the refusal's stable
/// code and message. `None` when the call unexpectedly answers.
fn agent_answer_refusal(fixture: &Fixture) -> Option<String> {
    let memory = fixture
        .vault
        .memory(fixture.actor, oneiron::EdgeActorClass::Agent);
    let digest = fixture
        .last_hold
        .as_ref()
        .map(|report| report.effect_digest())
        .unwrap_or_else(|| "0".repeat(64));
    let step_seq = fixture
        .last_hold
        .as_ref()
        .map(|report| report.step_seq)
        .unwrap_or(0);
    let error = invoke(
        &memory,
        "vault.code_run.resume_divergence.answer",
        serde_json::json!({
            "run_ref": fixture.run_id.to_hex(),
            "step_seq": step_seq,
            "report_digest": digest,
            "choice": "refire",
        }),
    )
    .expect_err("an agent never answers the owner's ask");
    Some(format!("{}: {}", error.code, error.message))
}

/// How many resume-divergence asks the owner's inbox holds.
fn owner_asks(vault: &Vault) -> usize {
    ask_seen(vault).len()
}

/// Every resume-divergence ask the owner's inbox holds: its event identity and whether its owner
/// saw and acked it.
fn ask_seen(vault: &Vault) -> Vec<(String, bool, bool)> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let memory = vault.memory(owner, oneiron::EdgeActorClass::Human);
    let page = memory
        .inbox_list(None, 100)
        .expect("the owner's inbox reads");
    page.rows
        .iter()
        .filter(|row| {
            row.kind == NotificationKind::Ask && row.source.producer == "code_run.resume_divergence"
        })
        .map(|row| (row.source.event.clone(), row.seen, row.acked))
        .collect()
}
