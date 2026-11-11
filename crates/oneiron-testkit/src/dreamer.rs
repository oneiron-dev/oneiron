//! One in-process Dreamer wake pass on the kit's fake clock, its model calls
//! answered by a [`ScriptedBackend`] (Fable's review of verdict 52,
//! 2026-11-10, section 4: the canary detector's step 2 and the golden-day
//! trace both run a vault through it).
//!
//! A pass does what a host's Dreamer supervisor does for one wake, through
//! public engine API only:
//! 1. elects this install the MACRO home node
//!    (`DreamerRunnerStore::elect_home_node`);
//! 2. queues the wake: a Timer wake at Macro scope
//!    ([`DreamerPass::run_timer_wake`], `dreamer_wake::request_wake` with no
//!    partition named, which plans the Nightly work and co-enqueues the Timer
//!    maintenance lanes), or the turn producer's wake at Micro scope
//!    ([`DreamerPass::run_turn_wake`], `Vault::wake_dreamer_on_turn`, one
//!    consolidation partition over the turns the Dreamer has not read);
//! 3. runs `DreamerWakeDriver::run_wake_pass` under a `WakePassDeadline`
//!    whose elapsed time is read off the fake clock, never a real monotonic
//!    clock;
//! 4. hands each attempt the driver does not run itself to a
//!    `ConsolidationExecutor` over the caller's backend, with a fresh
//!    `PromotionWriterSink` for that attempt, and records what it came to and
//!    what its sink promoted.
//!
//! A pass that parked, failed or landed an attempt, or stopped for any reason
//! but an empty queue, is refused ([`DreamerPassReport::unfinished`]); its
//! report rides the error, with every queued attempt's state and park
//! reason. A deferred attempt is a timed retry the pass settled (the Nightly
//! continuation defers until it is due), so it is reported, not refused.
//!
//! A Timer wake plans from the Dreamer's interest queue: it may make no
//! extraction call at all. The turn wake reads every turn the Dreamer has
//! not read yet, so a vault with a fresh turn makes at least one.
//!
//! Prepare the vault through public doors first:
//! - [`attach_test_host`], after every open: roots the vault under the kit's
//!   test host issuer, profiles this install so it carries the owner's acts,
//!   and enrols and retains the engine's machine writers, as a self-hosted
//!   server's start does. Without retained machine signers the Dreamer's
//!   own writes (its model-step receipts among them) are refused.
//! - [`allow_scripted_extraction`], once: the owner's purpose table lets
//!   extraction run on the backend's own server, the locality the scripted
//!   backend is bound at (the executor still carries a per-request egress
//!   verdict).
//! - [`grant_dreamer_read`], only for relationship or private content: the
//!   shipped policy already lets the Dreamer read an ordinary turn, and an
//!   owner Grant is tried only where that read refuses.
//!
//! The executor is a bare `ConsolidationExecutor`: unlike the production
//! host's stack (`oneiron-driver` `ConsolidationExecutorFactory`) it carries
//! no scope-summary, PERSON `about`, commitment-wake, weave-recipe or
//! connector-event wrapper, so a pass that queues one of those shapes reports
//! it parked. It does not opt into the Coach's host jobs (`coach.host`):
//! a Timer wake leaves them queued for a host consumer.
//!
//! The wake driver takes no async runtime (it yields by waking itself), and a
//! durable step's retry delay wakes its waker from a timer thread, so the
//! pass runs on the calling thread under a waker that unparks it.

use std::fmt;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use oneiron::dreamer_runner::DreamerAttemptPayload;
use oneiron::dreamer_wake::{WakeTurnSubject, request_wake};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::serialize::msgpack_value_from_json;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallPurpose, ConsolidationDecisions,
    ConsolidationExecutor, DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DreamerAdmittedAttempt,
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerClaimAuthoringStrategy,
    DreamerConsolidationScope, DreamerRunnerStore, DreamerWakeDriver, EnqueueDreamerAttemptOutcome,
    EntityId, LlmRequest, ModelId, ModelLocality, RunWakePass, Vault, WakeAttemptContext,
    WakeCancellation, WakePassDeadline, WakePassReport, WakePassStop, WakeTrigger, WriteActor,
};
use oneiron_keystore::{DeviceKeystore, MemoryKeystore};
use serde_json::{Value, json};

use crate::clock::FakeClock;
use crate::door;
use crate::provider::ScriptedBackend;

/// The model id the scripted backend serves the Dreamer as: a
/// `provider/name@revision` id no real provider uses.
pub const SCRIPTED_MODEL: &str = "oneiron-testkit/scripted@1";

/// The domain the kit's test host issuer seed is hashed from.
const HOST_ISSUER_DOMAIN: &[u8] = b"oneiron-testkit/host-issuer/v1\0";
/// Wakes a pass may take before it is reported stalled. The driver wakes
/// itself once at each attempt boundary, so a pass over a small vault takes
/// tens.
const MAX_POLLS: usize = 100_000;

/// Which wake a pass runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakeKind {
    /// A Timer wake at Macro scope: the Nightly plan and every Timer
    /// maintenance lane.
    Timer,
    /// The turn producer's wake at Micro scope: one consolidation partition
    /// over the turns the Dreamer has not read yet.
    Turn,
}

/// What a pass may spend, and how long it may run on the fake clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassBudget {
    /// The runner ledger line the pass reserves on. A second pass on the
    /// same line reuses what the first left: the total does not refill it.
    pub budget_id: String,
    /// The wake's total budget units.
    pub total_units: u64,
    /// The units each admission reserves; more than zero.
    pub reserve_units: u64,
    /// The pass's deadline, in fake-clock milliseconds from its start. The
    /// driver stops admitting in its last 15 000.
    pub deadline_ms: u64,
}

impl Default for PassBudget {
    /// 10 000 units on `oneiron-testkit-wake`, 100 per admission, and the
    /// engine's 180 s ceiling.
    fn default() -> Self {
        Self {
            budget_id: "oneiron-testkit-wake".to_owned(),
            total_units: 10_000,
            reserve_units: 100,
            deadline_ms: 180_000,
        }
    }
}

/// One attempt the pass handed the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerAttemptRun {
    /// The attempt's id, 32 hex.
    pub attempt_id: String,
    /// Its queue kind (`attempt_type`).
    pub attempt_type: String,
    /// What the executor answered, or its error's message.
    pub execution: Result<DreamerAttemptExecution, String>,
    /// Claims its sink landed approved.
    pub landed: Vec<EntityId>,
    /// Claims its sink kept as proposed.
    pub pended: Vec<EntityId>,
    /// Candidates its sink refused, each with the reason.
    pub rejected: Vec<(EntityId, String)>,
}

/// One row of the attempt queue after the pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRow {
    /// The attempt's id, 32 hex.
    pub attempt_id: String,
    /// Its queue kind.
    pub kind: String,
    /// Its state (`Queued`, `Completed`, `Paused`...).
    pub state: String,
    /// Why it is parked, when it is.
    pub park_reason: Option<String>,
}

/// One pass: the driver's tally, every attempt the executor ran, and the
/// queue it left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerPassReport {
    /// The wake it ran.
    pub wake: WakeKind,
    /// Whether queuing the wake added work (`false`: it joined a queued wake,
    /// or found no turn to read).
    pub wake_queued: bool,
    /// The MACRO home node the pass ran as.
    pub home_node: u64,
    /// The driver's tally, its stop reason among it.
    pub tally: WakePassReport,
    /// The attempts handed to the executor, in order. The driver runs
    /// cleanup and maintenance itself: those are in [`Self::queue`] only.
    pub attempts: Vec<DreamerAttemptRun>,
    /// Every working-set attempt after the pass, in creation order.
    pub queue: Vec<QueueRow>,
}

impl DreamerPassReport {
    /// Why the pass stopped.
    #[must_use]
    pub fn stop(&self) -> WakePassStop {
        self.tally.stop
    }

    /// Why the pass did not finish its work, one reason per entry: a stop
    /// other than an empty queue, or any parked, failed or landed attempt.
    /// Empty for a finished pass.
    #[must_use]
    pub fn unfinished(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.tally.stop != WakePassStop::QueueEmpty {
            reasons.push(format!("the pass stopped {:?}", self.tally.stop));
        }
        for (count, what) in [
            (self.tally.parked, "parked"),
            (self.tally.failed, "failed"),
            (self.tally.landed, "landed"),
        ] {
            if count > 0 {
                reasons.push(format!("{count} attempt(s) {what}"));
            }
        }
        reasons
    }

    /// The claims every attempt's sink landed, in order.
    #[must_use]
    pub fn landed(&self) -> Vec<EntityId> {
        self.attempts
            .iter()
            .flat_map(|attempt| attempt.landed.iter().copied())
            .collect()
    }
}

/// Why a pass, or the setup before it, did not go through.
#[derive(Debug)]
pub enum DreamerPassError {
    /// The engine refused a step.
    Engine(oneiron::Error),
    /// A public verb or the setup refused, with its message.
    Refused(String),
    /// No MACRO home node was elected.
    NoHomeNode,
    /// The pass was woken more than its poll budget allows.
    Stalled,
    /// The pass ran and left work undone ([`DreamerPassReport::unfinished`]).
    Unfinished(Box<DreamerPassReport>),
}

impl fmt::Display for DreamerPassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(f, "dreamer pass: {error}"),
            Self::Refused(message) => write!(f, "dreamer pass refused: {message}"),
            Self::NoHomeNode => f.write_str("dreamer pass: no MACRO home node was elected"),
            Self::Stalled => write!(f, "dreamer pass: not done after {MAX_POLLS} wakes"),
            Self::Unfinished(report) => {
                write!(
                    f,
                    "dreamer {:?} pass unfinished: {}; tally {:?}",
                    report.wake,
                    report.unfinished().join("; "),
                    report.tally
                )?;
                for attempt in &report.attempts {
                    write!(
                        f,
                        "\n- ran {} {}: {:?}",
                        attempt.attempt_type, attempt.attempt_id, attempt.execution
                    )?;
                }
                for row in report.queue.iter().filter(|row| row.state != "Completed") {
                    write!(f, "\n- queue {} {} {}", row.kind, row.attempt_id, row.state)?;
                    if let Some(reason) = &row.park_reason {
                        write!(f, ": {reason}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for DreamerPassError {}

impl From<oneiron::Error> for DreamerPassError {
    fn from(error: oneiron::Error) -> Self {
        Self::Engine(error)
    }
}

/// The kit's test host issuer: one fixed seed, so every open of a test vault
/// presents the host that rooted it.
///
/// # Errors
/// The engine refuses the seed.
pub fn test_host_issuer() -> oneiron::Result<HostSlipIssuer> {
    let seed: [u8; HOST_ISSUER_SEED_BYTES] = *blake3::hash(HOST_ISSUER_DOMAIN).as_bytes();
    HostSlipIssuer::from_seed(&seed)
}

/// The process's one this-device keystore, in memory. Its slots are named by
/// vault id and install, so every vault a test opens shares it, and a reopen
/// in the same process finds the keys its install was enrolled under. A vault
/// reopened in another process (a cached fixture's copy under nextest) finds
/// none, and its install's profile then stands under other keys.
fn test_keystore() -> Arc<dyn DeviceKeystore> {
    static KEYSTORE: OnceLock<Arc<MemoryKeystore>> = OnceLock::new();
    let keystore = KEYSTORE.get_or_init(|| Arc::new(MemoryKeystore::new()));
    Arc::clone(keystore) as Arc<dyn DeviceKeystore>
}

/// Attaches the kit's test host to an open vault, as a self-hosted server's
/// start does: installs the process's in-memory keystore, roots the vault
/// (binding the embedded owner as `human`), profiles this install so it
/// carries the owner's acts, and enrols and retains the engine's machine
/// writers. Call it after every open, once the vault's owner exists
/// ([`door::owner`]): the keystore handle and the machine signers live in
/// memory.
///
/// # Errors
/// The engine refuses a step: a vault rooted under another host, or an
/// install whose profile stands under other keys (one profiled in another
/// process: the keystore lives in this process's memory).
pub fn attach_test_host(vault: &Vault) -> Result<(), DreamerPassError> {
    let issuer = test_host_issuer()?;
    vault.install_device_keystore(test_keystore());
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.provision_engine_machine_identities(&issuer)?;
    Ok(())
}

/// The owner's purpose table, changed so extraction may run on the
/// backend's own server: the extraction row and the widest extraction
/// destination both name [`ModelLocality::OwnServer`], the locality the
/// scripted backend is bound at. Every other row stays.
///
/// # Errors
/// The table cannot be read, has no extraction row, or is refused.
pub fn allow_scripted_extraction(vault: &Vault) -> Result<(), DreamerPassError> {
    let mut table = vault.purpose_default_table()?;
    table.extraction_max_locality = ModelLocality::OwnServer;
    let Some(row) = table.purposes.get_mut(&CallPurpose::Extraction) else {
        return Err(DreamerPassError::Refused(
            "the purpose table has no extraction row".to_owned(),
        ));
    };
    row.locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&table)?;
    Ok(())
}

/// A Grant scope that reads every world, facet, kind band and project at
/// every sensitivity, and does nothing else.
#[must_use]
pub fn read_everything_scope() -> Value {
    json!({
        "worlds": {"kind": "all"},
        "facets": {"kind": "all"},
        "bands": {"kind": "all"},
        "audience": {"kind": "all"},
        "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "all"},
    })
}

/// The owner's read Grant to the Dreamer (`vault.agents.grants.mint`), under
/// `authority_scope` ([`read_everything_scope`], or narrower): what lets it
/// read content the shipped policy's own Dreamer read leaves out. The vault
/// must carry the owner's act ([`attach_test_host`] first). Returns the
/// Grant's ref.
///
/// # Errors
/// The owner, the Dreamer or the mint refuses.
pub fn grant_dreamer_read(
    vault: &Vault,
    authority_scope: Value,
) -> Result<String, DreamerPassError> {
    let owner = door::owner(vault).map_err(|error| refused("the owner", &error))?;
    let dreamer = vault.dreamer_authority()?.entity_ref().to_hex();
    let minted = door::invoke(
        &owner,
        "vault.agents.grants.mint",
        json!({"agent": dreamer, "authority_scope": authority_scope}),
    )
    .map_err(|error| refused("vault.agents.grants.mint", &error))?;
    minted
        .pointer("/grant/grant_ref")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| DreamerPassError::Refused(format!("the mint named no grant_ref: {minted}")))
}

/// One wake pass over a vault, its model calls answered by a scripted
/// backend. See the module docs.
#[derive(Debug)]
pub struct DreamerPass<'b> {
    backend: &'b ScriptedBackend,
    budget: PassBudget,
    run_id: String,
    lease_owner: String,
}

impl<'b> DreamerPass<'b> {
    /// A pass whose model calls `backend` answers, on the default budget.
    #[must_use]
    pub fn new(backend: &'b ScriptedBackend) -> Self {
        Self {
            backend,
            budget: PassBudget::default(),
            run_id: "oneiron-testkit-dreamer-pass".to_owned(),
            lease_owner: "oneiron-testkit".to_owned(),
        }
    }

    /// The same pass on `budget`.
    #[must_use]
    pub fn with_budget(mut self, budget: PassBudget) -> Self {
        self.budget = budget;
        self
    }

    /// The same pass under `run_id`: the wake's run and dedupe key, and
    /// every promotion's run context. A second pass needs its own.
    #[must_use]
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = run_id.into();
        self
    }

    /// Runs a Timer wake at Macro scope at `clock`'s time over `vault`
    /// (opened process-owned, [`attach_test_host`] run on this open).
    ///
    /// # Errors
    /// The engine refuses a step, no home node is elected, the pass stalls,
    /// or it leaves work undone ([`DreamerPassError::Unfinished`] carries its
    /// report).
    pub fn run_timer_wake(
        &self,
        vault: &Vault,
        clock: &FakeClock,
    ) -> Result<DreamerPassReport, DreamerPassError> {
        self.run(vault, clock, WakeKind::Timer)
    }

    /// Runs the turn producer's wake at Micro scope: one consolidation over
    /// the turns the Dreamer has not read yet. As [`Self::run_timer_wake`].
    ///
    /// # Errors
    /// As [`Self::run_timer_wake`].
    pub fn run_turn_wake(
        &self,
        vault: &Vault,
        clock: &FakeClock,
    ) -> Result<DreamerPassReport, DreamerPassError> {
        self.run(vault, clock, WakeKind::Turn)
    }

    fn run(
        &self,
        vault: &Vault,
        clock: &FakeClock,
        wake: WakeKind,
    ) -> Result<DreamerPassReport, DreamerPassError> {
        let now = clock.now();
        let store = DreamerRunnerStore::new(vault);
        let home = store.local_home_node_candidate(true, true, true)?;
        let home_node = home.node_id;
        if store.elect_home_node(&[home], now)?.is_none() {
            return Err(DreamerPassError::NoHomeNode);
        }
        let (trigger, scope, wake_queued) = match wake {
            WakeKind::Timer => {
                let outcome = request_wake(
                    &store,
                    WakeTrigger::Timer,
                    DreamerConsolidationScope::Macro,
                    DreamerAttemptPayload {
                        attempt_type: DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND.to_owned(),
                        input: msgpack_value_from_json(&Value::Null)?,
                        parent_attempt: None,
                    },
                    Some(self.run_id.clone()),
                    Some(self.run_id.clone()),
                    now,
                )?;
                let queued = matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_));
                (WakeTrigger::Timer, DreamerConsolidationScope::Macro, queued)
            }
            WakeKind::Turn => {
                let queued = vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, now)?;
                (WakeTrigger::Event, DreamerConsolidationScope::Micro, queued)
            }
        };

        let guard = BudgetGuard::with_reserve_units(
            self.budget.budget_id.clone(),
            self.budget.total_units,
            self.budget.reserve_units,
            BudgetExhaustionPolicy::Suspend,
        );
        let started_ms = clock.now_ms();
        let elapsed = clock.clone();
        let deadline = WakePassDeadline::with_clock(
            self.budget.deadline_ms,
            Arc::new(move || elapsed.now_ms().saturating_sub(started_ms)),
        );
        let mut driver = DreamerWakeDriver::new(vault, self.budget.budget_id.clone(), deadline)
            .with_budget_guard(guard.clone());
        let model = ModelId::new(SCRIPTED_MODEL)
            .map_err(|error| DreamerPassError::Refused(format!("{SCRIPTED_MODEL}: {error}")))?;
        let mut executor = PassExecutor {
            vault,
            backend: self.backend,
            guard: &guard,
            actor: vault.dreamer_authority()?,
            model,
            decisions: ConsolidationDecisions::shipped()?,
            run_id: self.run_id.clone(),
            attempts: Vec::new(),
        };
        let input = RunWakePass {
            trigger,
            scope,
            local_node_id: home_node,
            lease_owner: self.lease_owner.clone(),
            budget_total_units: self.budget.total_units,
            reserve_units: self.budget.reserve_units,
            now,
            host_scope: None,
            destination_bound: None,
        };
        let cancel = WakeCancellation::new();
        let tally = block_on(driver.run_wake_pass(input, &mut executor, &cancel))
            .ok_or(DreamerPassError::Stalled)??;
        let report = DreamerPassReport {
            wake,
            wake_queued,
            home_node,
            tally,
            attempts: executor.attempts,
            queue: queue_rows(vault, &store)?,
        };
        if report.unfinished().is_empty() {
            Ok(report)
        } else {
            Err(DreamerPassError::Unfinished(Box::new(report)))
        }
    }
}

/// The host's executor for one pass: a `ConsolidationExecutor` per attempt
/// over the scripted backend, each with its own promotion sink.
struct PassExecutor<'v, 'g> {
    vault: &'v Vault,
    backend: &'g ScriptedBackend,
    guard: &'g BudgetGuard,
    actor: WriteActor,
    model: ModelId,
    decisions: ConsolidationDecisions,
    run_id: String,
    attempts: Vec<DreamerAttemptRun>,
}

impl DreamerAttemptExecutor for PassExecutor<'_, '_> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let mut sink = PromotionWriterSink::new(
            self.vault,
            DreamerRunContext {
                run_id: self.run_id.clone(),
                attempt_id: attempt.status.attempt.id,
                agent_actor: self.actor,
                now_ms: ctx.now_ms,
            },
        );
        let execution = {
            let mut inner = ConsolidationExecutor {
                backend: self.backend,
                guard: self.guard,
                strategy: DreamerClaimAuthoringStrategy::SinglePass,
                actor: self.actor,
                model: self.model.clone(),
                inference: scripted_inference(&self.model),
                roles: Default::default(),
                sink: &mut sink,
                scope: None,
                decisions: self.decisions.clone(),
            };
            DreamerAttemptExecutor::execute(&mut inner, attempt, ctx).await
        };
        self.attempts.push(DreamerAttemptRun {
            attempt_id: hex(attempt.status.attempt.id.as_bytes()),
            attempt_type: attempt.status.payload.attempt_type.clone(),
            execution: execution.as_ref().cloned().map_err(ToString::to_string),
            landed: std::mem::take(&mut sink.outcome.landed),
            pended: std::mem::take(&mut sink.outcome.pended),
            rejected: std::mem::take(&mut sink.outcome.rejected),
        });
        execution
    }
}

/// The scripted backend as the host binds it: advertised at `model` on its
/// own server, every extraction request let through.
fn scripted_inference(model: &ModelId) -> HostInferenceContext<'static> {
    HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: model.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        },
        extraction_egress: Some(&permit_scripted_extraction),
    }
}

/// The host's egress verdict for a scripted pass: the backend is in
/// process, so every extraction request may go to it.
fn permit_scripted_extraction(_request: &LlmRequest) -> bool {
    true
}

/// Every working-set attempt, in creation order, with its park reason.
fn queue_rows(
    vault: &Vault,
    store: &DreamerRunnerStore<'_>,
) -> Result<Vec<QueueRow>, DreamerPassError> {
    Ok(AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .map(|record| {
            let park_reason = if record.state == AttemptState::Completed {
                None
            } else {
                store
                    .status_with_park(record.id)
                    .ok()
                    .flatten()
                    .and_then(|(_, park)| park)
                    .map(|park| park.reason)
            };
            QueueRow {
                attempt_id: hex(record.id.as_bytes()),
                kind: record.kind,
                state: format!("{:?}", record.state),
                park_reason,
            }
        })
        .collect())
}

/// Wakes the thread that waits on a pass.
struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls `future` on this thread until it is ready, parking between polls
/// until its waker unparks the thread; `None` after [`MAX_POLLS`] polls.
fn block_on<F: Future>(future: F) -> Option<F::Output> {
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    for _ in 0..MAX_POLLS {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return Some(output);
        }
        thread::park();
    }
    None
}

fn refused(what: &str, error: &dyn fmt::Display) -> DreamerPassError {
    DreamerPassError::Refused(format!("{what}: {error}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
