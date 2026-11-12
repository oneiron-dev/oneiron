//! Row B1b of BUDGET-TRAP-UNTYPED-NO-SENDER: a run's step that a spend scope refuses for good
//! ends its try `Failed` with the typed refusal on the owner's surfaces, not only in its text.
//!
//! A live agent run submits a paid step through `submit_as_run_actor_on_scope` (the run step,
//! `ai.steps.submit`) on a soft scope that sits under a closed hard carve with less room than the
//! reservation asks. The step refuses `BoundaryClosed` (row B1) and its try fails. B1b keeps the
//! refusal typed on the failed row (`AttemptRecord::budget_refusal`), on the step's node in its
//! run tree (`RunTreeFailure::budget_refusal`, what `/v1/core/run-tree` serves) and on its receipt
//! (`ai.steps.receipt`). A failed run step has no pack or TASK receipt: its row carries no
//! manifest, attribution, team or TASK. Scope fixtures come from `oneiron::test_doors::spend`
//! and `oneiron::test_doors::park_typed_wait`, built only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test run_step_budget_refusal`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, SpendState, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::code_run::HostSelfDispatcher;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::llm::model_step::{
    ModelStepFailureClass, ModelStepResult, ModelStepRetryPolicy, ModelStepSubmit, RunStepCaller,
    submit_as_run_actor_on_scope,
};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::llm::{BudgetGuard, Scope, StepSpendScope};
use oneiron::run_tree::{RunTreeAdapter, RunTreeNode};
use oneiron::store::model_step_submission::StepBudgetRefusal;
use oneiron::task_verb::HostBinding;
use oneiron::test_doors::park_typed_wait::reserve_child_hold_scope;
use oneiron::test_doors::spend::reserve_child_scope;
use oneiron::{
    AttemptId, AttemptQueue, BudgetExhaustionPolicy, BudgetLease, CallClass, CallEnvelope,
    CallPurpose, ContentPart, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole,
    LlmRequest, LlmStreamResult, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault, VaultConfig, WriteActor,
};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// The lease owner the run's try is claimed under.
const WORKER: &str = "run-step-budget-refusal";

fn attached() -> bool {
    true
}

/// A run its host still holds attached.
static ATTACHED: fn() -> bool = attached;

/// Drives the test's steps on a current-thread runtime. This crate's tokio carries no `macros`
/// feature, so `#[tokio::test]` is not available.
fn block_on(steps: impl Future<Output = TestResult>) -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(steps)
}

fn open_vault(dir: &std::path::Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// A live agent run: its actor, definition, host lease and leased try.
struct LeasedRun {
    actor: WriteActor,
    definition: oneiron::agent_def::AgentDefinition,
    lease: HostBinding,
}

impl LeasedRun {
    fn caller(&self) -> RunStepCaller<'_> {
        RunStepCaller {
            actor: self.actor,
            lease: &self.lease,
            definition: &self.definition,
            attached: &ATTACHED,
        }
    }
}

fn claim(vault: &Vault, id: AttemptId) -> Result<AttemptRecord, TestError> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(queue.get(id)?.ok_or("a claimed attempt reads back")?);
        }
    }
    Err("the agent attempt is ready to claim".into())
}

/// The default agent dispatched under `run` and claimed, with its host's lease.
fn leased_run(vault: &Vault, run: &str) -> Result<LeasedRun, TestError> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now: 1,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )?
    else {
        return Err("expected one fresh agent run".into());
    };
    let actor = agent_dispatch_actor(&status.input)?;
    let attempt = claim(vault, status.attempt.id)?;
    let host = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &attempt)?;
    let lease = host
        .task_host_binding()?
        .ok_or("the agent run has a lease")?;
    Ok(LeasedRun {
        actor,
        definition: status.input.definition,
        lease,
    })
}

/// One paid text step under `key`, on the owner's own server, so the guard admits it on its paid
/// line and asks its scope for the whole reservation.
fn paid_step(key: &str) -> ModelStepSubmit {
    ModelStepSubmit {
        step_key: key.to_owned(),
        request: LlmRequest {
            model: ModelId::new("test/model@r1").expect("model id"),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Scope::default(),
                purpose: CallPurpose::Consolidation,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Consolidation,
                    ModelTierRef("default".into()),
                ),
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OwnServer,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "run step budget refusal".to_owned(),
                    signature: None,
                }],
            }],
            tools: Vec::new(),
            params: std::collections::BTreeMap::new(),
            provider_options: std::collections::BTreeMap::new(),
            host_segments: None,
        },
        retry: ModelStepRetryPolicy { max_attempts: 1 },
    }
}

/// A backend a refused step must never reach: any call panics, and the count stays readable.
struct NeverBackend {
    calls: AtomicUsize,
}

impl LlmBackend for NeverBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a refused step must not call its backend");
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a refused step must not call its backend");
    }
}

/// The default guard reserve: what a step's reservation asks of its scope.
fn default_reserve() -> u64 {
    BudgetGuard::new(
        "run-step-budget-refusal-reserve",
        0,
        BudgetExhaustionPolicy::Suspend,
    )
    .reserve_units()
}

/// Opens a hard root of `units`, shown at its start.
fn open_root(
    dispatcher: &AgentDispatcher<'_>,
    name: &str,
    units: u64,
) -> Result<SpendScopeId, TestError> {
    let root = SpendScopeId::launch(name)?;
    let opened = dispatcher.open_root_spend_scope(
        root.clone(),
        DeclaredMaximum {
            units,
            unit: LeaseUnit::tokens(),
        },
        Some(MaximumShown { at_ms: 12_000 }),
        12,
    )?;
    assert!(opened.hard, "the root is a hard cap");
    Ok(root)
}

/// The node of `attempt` in `nodes` or below them.
fn node_of<'a>(nodes: &'a [RunTreeNode], attempt: &str) -> Option<&'a RunTreeNode> {
    nodes.iter().find_map(|node| {
        (node.attempt_id == attempt)
            .then_some(node)
            .or_else(|| node_of(&node.children, attempt))
    })
}

/// The run step of a live agent run passes a closed hard carve with less room than its
/// reservation asks: it refuses `BoundaryClosed` and its try fails. The refusal is typed on the
/// failed row, on the step's node in its run tree and on its receipt, naming the carve, its room
/// and what the reservation asked of it.
#[test]
fn a_run_step_a_closed_carve_refuses_shows_its_typed_refusal_in_its_run_tree_and_receipt()
-> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "run-step-budget-refusal")?;
        let dispatcher = AgentDispatcher::new(&vault);
        let reserve = default_reserve();
        let carve_cap = reserve / 2;
        let hold = 10;
        assert!(
            (hold + 1..reserve).contains(&carve_cap),
            "the carve holds the step's hold and less than the reservation"
        );
        let root = open_root(&dispatcher, "owen-run-step-root", 4 * reserve)?;
        let carve_try = AttemptId::now();
        let carve = reserve_child_scope(&vault, &root, &carve_try, carve_cap, 13)?;
        assert!(carve.hard, "the carve is a hard cap");
        let step_try = AttemptId::now();
        let held = reserve_child_hold_scope(&vault, &carve.scope, &step_try, hold, 15)?;
        assert!(!held.hard, "the step's scope is a soft hold");
        dispatcher
            .settle_child(&carve_try, 16)?
            .ok_or("the carve settles")?;
        let closed = dispatcher
            .read_spend_scope(&carve.scope)?
            .ok_or("the closed carve")?;
        assert_eq!(closed.state, SpendState::Closed, "the carve is closed");

        let spend = StepSpendScope::read_before_guards(&vault, held.scope.clone())?;
        let guard = dispatcher.guard_for_scope(&held.scope)?;
        let backend = NeverBackend {
            calls: AtomicUsize::new(0),
        };
        let receipt = submit_as_run_actor_on_scope(
            &vault,
            run.caller(),
            paid_step("refused"),
            &backend,
            &guard,
            Some(&spend),
        )
        .await?;
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            0,
            "a refused step never calls its backend"
        );
        let expected = StepBudgetRefusal::BoundaryClosed {
            scope: carve.scope.as_str().to_owned(),
            available_units: carve_cap - hold,
            asked_units: reserve - hold,
        };

        // Its receipt (`ai.steps.receipt`): the step's own result, typed since row B1.
        let failure = match &receipt.result {
            Some(ModelStepResult::Failed { failure }) => failure,
            other => panic!("the closed carve fails the run step: got {other:?}"),
        };
        assert_eq!(
            failure.class,
            ModelStepFailureClass::BudgetRefused,
            "the step fails as budget refused"
        );
        assert_eq!(
            failure.budget_refusal.as_ref(),
            Some(&expected),
            "the step's receipt names the closed carve, its room and what the reservation asked"
        );

        // The failed row keeps the refusal beside its text.
        let step = node_attempt_id(&receipt.step_ref)?;
        let row = AttemptQueue::new(&vault)
            .get(step)?
            .ok_or("the run step's try")?;
        assert_eq!(row.state.as_str(), "failed", "the refused step's try fails");
        assert_eq!(
            row.last_error.as_deref(),
            Some(failure.message.as_str()),
            "the failed row keeps the step's failure text"
        );
        assert_eq!(
            row.budget_refusal.as_ref(),
            Some(&expected),
            "the failed row keeps the typed refusal beside its text"
        );

        // The step's node in its run tree: what the owner's run view serves.
        let run_id = row
            .run_id
            .clone()
            .ok_or("the run step's try names its run")?;
        let tree = RunTreeAdapter::new(&vault).read_run(&run_id)?;
        let node = node_of(&tree.roots, &receipt.step_ref)
            .ok_or("the run step is a node of its run tree")?;
        let shown = node
            .failure
            .as_ref()
            .ok_or("the failed step's node shows its failure")?;
        assert_eq!(
            shown.reason, failure.message,
            "the node shows the failure text"
        );
        assert_eq!(
            shown.budget_refusal.as_ref(),
            Some(&expected),
            "the run tree shows the typed refusal on the failed step's node"
        );
        Ok(())
    })
}

/// `step_ref`, the step's 32-hex attempt id, as its id.
fn node_attempt_id(step_ref: &str) -> Result<AttemptId, TestError> {
    let bytes: Vec<u8> = (0..step_ref.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&step_ref[at..at + 2], 16))
        .collect::<Result<_, _>>()?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| "a step ref is a 16-byte attempt id")?;
    Ok(AttemptId::from_bytes(&bytes)?)
}
