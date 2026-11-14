//! L8-23: a resumed pending step walks its recorded calls against the re-entered program.
//!
//! Entry 1 parks a step after a memory search and a claim put. Entry 2 re-enters with the same,
//! a pure-changed, an effect-changed, or an effect-swapped program: a pure change proceeds with
//! the divergence recorded, an effect change holds with the walk's report, a call swapped in
//! before the claim put ends the walk with the put unreached, and nothing re-fires. A changed
//! guest boundary alone is a report flag, not a refusal.
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
    CodeRunDeterminism, GatedActorWrite, SelfCall, SelfMemoryPutClaimCall, SelfMemorySearchCall,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorError, EngineExecutorLimits, EngineExecutorOutcome,
    EngineExecutorResult, EngineExecutorStatus, EngineNativeExecutor, JsCodeModeHost,
    JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome, ResumePreflightReport,
};
use oneiron::llm::ReplyAssertions;
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::code_run_answer::install_actor_ceiling;
use oneiron::test_doors::resume_preflight::restamp_guest_abi;
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

/// Entry 1 parks after a memory search and a claim put; entry 2 runs `reentered`.
struct TwoEntryRuntime {
    entry: u8,
    reentered: Variant,
    subject: EntityId,
    claim: EntityId,
    new_claim: EntityId,
}

impl TwoEntryRuntime {
    fn search_call(query: &str) -> SelfCall {
        SelfCall::MemorySearch(SelfMemorySearchCall::new(query, 5))
    }

    fn put_call(&self, id: EntityId, object: &str) -> SelfCall {
        SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(self.subject),
                rmpv::Value::from(object),
                0.8,
            ),
            TimeRange { start: 11, end: 11 },
            12,
        ))
    }

    fn run_entry(
        host: &mut dyn JsCodeModeHost,
        calls: Vec<SelfCall>,
        deadline: bool,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        for call in calls {
            let _ = host.dispatch_self(call)?;
        }
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
        match self.entry {
            1 => {
                let search = Self::search_call("alpha");
                let put = self.put_call(self.claim, "green tea");
                Self::run_entry(host, vec![search, put], true)
            }
            2 => {
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
                Self::run_entry(host, calls, false)
            }
            _ => Ok(JsCodeModeStepOutcome::pending("probe observation")),
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
    run_id: EntityId,
    config: EngineExecutorConfig,
    runtime: TwoEntryRuntime,
}

impl Fixture {
    fn open(reentered: Variant) -> Self {
        let (_dir, vault, _owner, _proof) = owner_vault();
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
        };
        Self {
            _dir,
            vault,
            actor,
            run_id,
            config,
            runtime,
        }
    }

    fn park(&mut self) {
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
        let record = self
            .vault
            .get_code_run_replay_record(&self.run_id)
            .expect("the parked record reads")
            .expect("the parked record is present");
        let pending = record.pending_step.expect("the step parks pending");
        assert_eq!(
            (pending.guest_calls.as_slice(), pending.bridge_frontier),
            (&[0_u64, 1][..], 2),
            "the parked step keeps its two calls",
        );
    }

    fn reenter(&mut self) -> EngineExecutorResult<EngineExecutorOutcome> {
        run_turn(
            &self.vault,
            self.actor,
            &self.config,
            scripted_response("console.log('not asked');", serde_json::json!({})),
            &mut self.runtime,
        )
    }
}

#[test]
fn boundary_change_alone_replays_free_and_commits() {
    let mut fixture = Fixture::open(Variant::Same);
    fixture.park();
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
    fixture.park();
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
    fixture.park();
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
    fixture.park();
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
    fixture.park();
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
