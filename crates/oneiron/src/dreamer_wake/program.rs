//! The Dreamer's turn program runtime (DOOR-141 PR2, FIX 4382).
//!
//! [`TurnProgramExecutor`] wraps a host's executor: every other kind runs on
//! the wrapped one as before, and a turn program attempt runs here, on the
//! L11 inner runtime ([`EngineNativeExecutor`]) in the code run its admission
//! fixed. Each entry binds the attempt to its waking actor's live authority
//! and its pin first; a lapse runs nothing new. The host lends the runtime,
//! its verb door and the backend ([`TurnProgramRuntime`]); a host that lends
//! none for an actor parks that program alone.
//!
//! Every model call of the run is one durable step through `call_as_step`,
//! on the program's own actor meter, which borrows from the pass's shared
//! meter and never reserves twice. Identical requests at two places of the
//! run are two steps: each carries its logical occurrence. Each write and
//! send settles into the program's step (`dreamer_runner::program`).
//!
//! Waits, yields and parks are honest. A run that finished with its pinned
//! entry finished completes, its result attached under its lease in one
//! commit. A run that stops short parks, and an entry that finds a run an
//! earlier entry left unsettled parks too: resuming it lands with DOOR-141
//! PR3. Nothing restarts it from scratch, and nothing reports it complete.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::code_run::{AgentVerbDoor, HostSelfDispatcher};
use crate::dreamer_runner::{
    DREAMER_TURN_PROGRAM_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
    DreamerRunnerStore, PROGRAM_PARK_OWNER, ParkDreamerAttempt, ProgramRecipePin,
    TurnProgramBinding, TurnProgramBound, TurnProgramEntered,
};
use crate::engine_executor::{
    EngineExecutorConfig, EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus,
    EngineNativeExecutor, JsCodeModeRuntime,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::seat::ModelSeat;
use crate::llm::{
    BudgetGuard, BudgetLease, DurableStepContext, DurableStepError, FatalLlmError, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmRequest, LlmResponse, LlmResult,
    LlmStreamResult, ModelId, StepOutcome, call_as_step,
};
use crate::task_verb::{RunnerDoneAnswer, RunnerDoneQuestion};
use crate::{Vault, WriteActor};

use super::deadline::WakePassDeadline;
use super::types::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};

/// The provider-option namespace a program's model step carries its logical
/// occurrence in. No adapter reads it; the step's identity does.
const OCCURRENCE_NAMESPACE: &str = "oneiron";
const OCCURRENCE_KEY: &str = "turn_program_step";
const RESPONSE_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-response:v1";

const UNBOUND_REASON: &str = "this host binds no turn program runtime for the program's actor";
const LAPSED_PREFIX: &str = "the turn program runs nothing new: ";
const CUT_REASON: &str = "an earlier entry of the turn program stopped before it settled; its resume lands with DOOR-141 PR3";
const UNFINISHED_REASON: &str =
    "the turn program's run ended without its pinned entry finishing; it is not complete";
const TRAPPED_REASON: &str = "durable step trapped for resume";

/// The host's own runtime for one program entry's model steps: the Dreamer's
/// thread never enters it, so each step runs on a thread of its own and
/// blocks there until `step` is done.
pub trait TurnProgramReactor: Send + Sync {
    fn block_on(&self, step: Pin<Box<dyn Future<Output = ()> + '_>>);
}

/// What a host lends one turn program entry: a fresh JS runtime, the backend
/// its model steps call, its verb door bound to the program's actor, the
/// vault as it holds it (for the pinned callable), the run's config and seat
/// on the program's code run, and the runtime its model steps block on.
pub struct TurnProgramHost {
    pub runtime: Box<dyn JsCodeModeRuntime + Send>,
    pub backend: Arc<dyn LlmBackend>,
    pub door: Arc<dyn AgentVerbDoor>,
    pub vault: Arc<Vault>,
    pub config: EngineExecutorConfig,
    pub seat: Option<ModelSeat>,
    pub reactor: Arc<dyn TurnProgramReactor>,
}

/// One program entry a host is asked to bind: the program's leased try, the
/// waking actor it runs as, its code run and its task.
pub struct TurnProgramRequest<'r> {
    pub attempt: &'r AttemptRecord,
    pub actor: WriteActor,
    pub code_run: EntityId,
    pub task: &'r str,
}

/// A host's binding of turn program entries to its runtime and credential
/// door. `None` when it lends nothing for this program's actor: that
/// program parks, and nothing else changes.
pub trait TurnProgramRuntime: Send {
    fn bind(&mut self, vault: &Vault, request: &TurnProgramRequest<'_>) -> Option<TurnProgramHost>;
}

/// The program runtime around a host's executor. Without a runtime it
/// admits no program, and every attempt it is given runs on `inner`.
pub struct TurnProgramExecutor<'p, E> {
    inner: E,
    runtime: Option<&'p mut (dyn TurnProgramRuntime + 'static)>,
    shared: &'p BudgetGuard,
}

impl<'p, E> TurnProgramExecutor<'p, E> {
    /// `shared` is the pass's meter, the one cap every program's own meter
    /// borrows under.
    #[must_use]
    pub fn new(
        inner: E,
        runtime: Option<&'p mut (dyn TurnProgramRuntime + 'static)>,
        shared: &'p BudgetGuard,
    ) -> Self {
        Self {
            inner,
            runtime,
            shared,
        }
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for TurnProgramExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.attempt.kind != DREAMER_TURN_PROGRAM_ATTEMPT_KIND {
            return self.inner.execute(attempt, ctx).await;
        }
        match self.runtime.as_deref_mut() {
            Some(runtime) => run_program(runtime, self.shared, attempt, ctx).await,
            None => hold(ctx, &attempt.status.attempt, UNBOUND_REASON.to_owned()),
        }
    }

    async fn judge_done(&self, question: RunnerDoneQuestion) -> Option<RunnerDoneAnswer> {
        self.inner.judge_done(question).await
    }

    fn runner_budget_id(&mut self, candidate: &AttemptRecord) -> Option<String> {
        self.inner.runner_budget_id(candidate)
    }

    fn runs_turn_programs(&self) -> bool {
        self.runtime.is_some()
    }
}

/// Parks `attempt` as the program runtime's own hold: it stays parked until
/// its runtime resumes it, never on a pass's or a boot's own sweep.
fn hold(
    ctx: &WakeAttemptContext<'_>,
    attempt: &AttemptRecord,
    reason: String,
) -> Result<DreamerAttemptExecution> {
    DreamerRunnerStore::new(ctx.vault).park_attempt(ParkDreamerAttempt {
        attempt_id: attempt.id,
        reason: reason.clone(),
        cause: DreamerParkCause::Other,
        park_owner: PROGRAM_PARK_OWNER.to_owned(),
        now: ctx.now_ms / 1_000,
    })?;
    Ok(DreamerAttemptExecution::Park {
        reason,
        cause: DreamerParkCause::Other,
    })
}

/// The program's task: run its pinned callable entry, exactly as pinned.
fn program_task(pin: &ProgramRecipePin) -> String {
    format!(
        "Run this turn program and nothing else. Call `self.skills.call` exactly once, with the \
         callable skill `{skill}` and exactly these arguments: {args}. It is the program pinned \
         at version {version} (content {hash}, entry `{entry}`). Make no other call, and answer \
         with its result once it returns.",
        skill = pin.skill.to_hex(),
        args = pin.args,
        version = pin.version,
        hash = pin.content_hash,
        entry = pin.entry,
    )
}

async fn run_program(
    runtime: &mut dyn TurnProgramRuntime,
    shared: &BudgetGuard,
    admitted: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
) -> Result<DreamerAttemptExecution> {
    let vault = ctx.vault;
    let attempt = &admitted.status.attempt;
    let binding = match vault.bind_turn_program_execution(attempt.id)? {
        TurnProgramBound::Bound(binding) => binding,
        TurnProgramBound::Lapsed(why) => {
            return hold(ctx, attempt, format!("{LAPSED_PREFIX}{why}"));
        }
    };
    let task = program_task(&binding.pin);
    let request = TurnProgramRequest {
        attempt,
        actor: binding.actor,
        code_run: binding.code_run,
        task: &task,
    };
    let Some(host) = runtime.bind(vault, &request) else {
        return hold(ctx, attempt, UNBOUND_REASON.to_owned());
    };
    // The program's own actor meter, lent under the pass's shared cap: the
    // loan reserves its limit on the shared meter, and settles there with
    // what the program spent. Its steps reserve on the program's meter
    // alone, so no unit is reserved twice.
    let read = shared.read();
    let limit = attempt
        .ordinary_budget_limit_units()
        .min(read.remaining_units);
    let Ok(loan) = shared.admit_reserve(limit) else {
        return Ok(DreamerAttemptExecution::Park {
            reason: "the pass's meter holds nothing to lend the turn program".to_owned(),
            cause: DreamerParkCause::Checkpoint,
        });
    };
    let meter = match vault.policy_budget_guard(
        format!("turn-program:{}", binding.code_run.to_hex()),
        limit,
        shared.reserve_units(),
        read.on_budget_exhausted,
        binding.actor,
    ) {
        Ok(meter) => meter,
        Err(error) => {
            repay(shared, &loan.lease, 0);
            return Err(error);
        }
    };
    let entered = vault.enter_turn_program_run(
        attempt,
        &binding.admission,
        binding.code_run,
        ctx.now_ms / 1_000,
    );
    let ran = match entered {
        Ok(TurnProgramEntered::Fresh) => {
            enter(host, &binding, attempt, ctx, &meter, &loan.lease).await
        }
        Ok(TurnProgramEntered::Settled) => {
            // Settled before its try closed: the result stands, and the
            // try completes on it without running again.
            repay(shared, &loan.lease, 0);
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        Ok(TurnProgramEntered::Cut) => {
            repay(shared, &loan.lease, 0);
            return hold(ctx, attempt, CUT_REASON.to_owned());
        }
        Err(error) => {
            repay(shared, &loan.lease, 0);
            return Err(error);
        }
    };
    let used = meter.read().used_units;
    repay(shared, &loan.lease, used);
    settle(vault, &binding, attempt, ctx, ran, used)
}

/// Settles the program's loan on the shared meter with what it spent.
fn repay(shared: &BudgetGuard, loan: &BudgetLease, used: u64) {
    if let Err(denied) = shared.settle_absolute(loan, used) {
        tracing::warn!(
            ?denied,
            "a turn program's meter loan did not settle on the pass meter"
        );
    }
}

/// How one entry's run ended, and why the program's model seam stopped it,
/// when it did.
struct Ran {
    outcome: EngineExecutorResult<EngineExecutorOutcome>,
    stop: Option<SeamStop>,
    pinned_finished: bool,
}

/// Runs one entry of the program's code run on the host's runtime, through
/// the engine executor's own loop: a yield goes on in the same entry while
/// the pass has time.
async fn enter(
    host: TurnProgramHost,
    binding: &TurnProgramBinding,
    attempt: &AttemptRecord,
    ctx: &WakeAttemptContext<'_>,
    meter: &BudgetGuard,
    lease: &BudgetLease,
) -> Result<Ran> {
    let TurnProgramHost {
        mut runtime,
        backend,
        door,
        vault: lent,
        mut config,
        seat,
        reactor,
    } = host;
    let vault = ctx.vault;
    if config.run_id != binding.code_run {
        return Err(Error::InvalidConfig(
            "a turn program's host config names another code run".to_owned(),
        ));
    }
    if let Some(seat) = &seat {
        config.model = seat.model().clone();
        config.model_locality = seat.locality();
        config.seat_effort = Some(seat.effort());
    }
    let dispatcher = HostSelfDispatcher::for_turn_program(
        vault,
        binding.actor,
        format!("turn-program:{}", binding.code_run.to_hex()),
        attempt,
        binding.pin.skill,
    )?
    .with_callable_skills(lent)?
    .with_agent_verb_door(door);
    let seam = ProgramModelSeam {
        vault,
        deadline: ctx.deadline,
        attempt: attempt.id,
        run_id: attempt.run_id.clone(),
        actor: binding.actor,
        code_run: binding.code_run,
        inner: &*backend,
        meter,
        reactor: &*reactor,
        occurrence: AtomicU64::new(0),
        stop: Mutex::new(None),
    };
    let js: &mut dyn JsCodeModeRuntime = &mut *runtime;
    let mut executor = EngineNativeExecutor::new(vault, &seam, lease, js, &dispatcher);
    if let Some(seat) = &seat {
        executor = executor.with_model_seat(seat);
    }
    let outcome = loop {
        let outcome = executor.run(&config).await;
        let yielded = outcome
            .as_ref()
            .is_ok_and(|done| matches!(done.status, EngineExecutorStatus::Yielded { .. }));
        if !yielded || ctx.deadline.expired() {
            break outcome;
        }
    };
    let pinned_finished = outcome
        .as_ref()
        .is_ok_and(|done| dispatcher.pinned_entry_finished(&done.replay_record));
    Ok(Ran {
        outcome,
        stop: seam.stop(),
        pinned_finished,
    })
}

/// What one entry's end means for the program's try.
fn settle(
    vault: &Vault,
    binding: &TurnProgramBinding,
    attempt: &AttemptRecord,
    ctx: &WakeAttemptContext<'_>,
    ran: Result<Ran>,
    used: u64,
) -> Result<DreamerAttemptExecution> {
    let stopped = |reason: String| DreamerAttemptExecution::ParkWithSpend {
        reason,
        cause: DreamerParkCause::Checkpoint,
        completed_units: used,
        step_hashes: Vec::new(),
    };
    let ran = match ran {
        Ok(ran) => ran,
        Err(error) => return Ok(stopped(format!("the turn program did not enter: {error}"))),
    };
    let outcome = match ran.outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok(match ran.stop {
                // The step layer parked the try in its trap's own commit.
                Some(SeamStop::Trapped) => DreamerAttemptExecution::Park {
                    reason: TRAPPED_REASON.to_owned(),
                    cause: DreamerParkCause::Signal,
                },
                Some(SeamStop::Deadline) => stopped(format!(
                    "the pass's deadline cut the turn program; {CUT_REASON}"
                )),
                Some(SeamStop::Failed) | None => {
                    stopped(format!("the turn program's run stopped: {error}"))
                }
            });
        }
    };
    Ok(match outcome.status {
        EngineExecutorStatus::Complete if ran.pinned_finished => {
            let generation = outcome.replay_record.generation()?;
            vault.settle_turn_program_run(
                attempt,
                binding.code_run,
                &generation,
                ctx.now_ms / 1_000,
            )?;
            DreamerAttemptExecution::Completed {
                completed_units: used,
            }
        }
        EngineExecutorStatus::Complete => stopped(UNFINISHED_REASON.to_owned()),
        EngineExecutorStatus::Yielded { next_step_seq } => stopped(format!(
            "the turn program yielded at step {next_step_seq} as the pass ended; its resume \
             lands with DOOR-141 PR3"
        )),
        EngineExecutorStatus::Waiting(_) => stopped(
            "the turn program waits on a durable wait; its resume lands with DOOR-141 PR3"
                .to_owned(),
        ),
        EngineExecutorStatus::WindowFull { next_step_seq, .. } => stopped(format!(
            "the turn program's window filled at step {next_step_seq}; its resume lands with \
             DOOR-141 PR3"
        )),
    })
}

/// Why the program's model seam stopped the run.
#[derive(Debug, Clone, Copy)]
enum SeamStop {
    /// A step trapped (budget or consent): the step layer parked the try.
    Trapped,
    /// The pass's deadline refused a new step.
    Deadline,
    /// A step failed, or could not be bound.
    Failed,
}

/// The program run's model door: each call the engine executor makes is one
/// durable step (`call_as_step`) on the program's own meter, as the program's
/// actor, told apart from an identical call elsewhere in the run by its
/// logical occurrence. The executor's own lease is never charged here.
struct ProgramModelSeam<'s> {
    vault: &'s Vault,
    deadline: &'s WakePassDeadline,
    attempt: AttemptId,
    run_id: Option<String>,
    actor: WriteActor,
    code_run: EntityId,
    inner: &'s dyn LlmBackend,
    meter: &'s BudgetGuard,
    reactor: &'s dyn TurnProgramReactor,
    occurrence: AtomicU64,
    stop: Mutex<Option<SeamStop>>,
}

impl ProgramModelSeam<'_> {
    fn stop(&self) -> Option<SeamStop> {
        *self.stop.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps the first reason the seam stopped the run.
    fn note(&self, stop: SeamStop) {
        let mut held = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none() {
            *held = Some(stop);
        }
    }

    fn stopped(&self, stop: SeamStop) -> LlmError {
        self.note(stop);
        FatalLlmError::InvalidRequest.into()
    }

    /// One model call as one durable step, on a thread of its own: the
    /// Dreamer's thread never blocks on a runtime.
    fn step(&self, mut request: LlmRequest) -> LlmResult<LlmResponse> {
        let occurrence = self.occurrence.fetch_add(1, Ordering::SeqCst);
        let mut place = serde_json::Map::new();
        place.insert(
            OCCURRENCE_KEY.to_owned(),
            serde_json::Value::from(occurrence),
        );
        request.provider_options.insert(
            OCCURRENCE_NAMESPACE.to_owned(),
            serde_json::Value::Object(place),
        );
        let Ok(request_hash) = request.canonical_hash() else {
            return Err(self.stopped(SeamStop::Failed));
        };
        let now = self.vault.now_recorded_at();
        if let Err(error) = self.vault.record_turn_program_model_step(
            self.attempt,
            self.code_run,
            occurrence,
            request_hash,
            None,
            now,
        ) {
            tracing::warn!(kind = ?error.kind(), "a turn program's model step was not bound");
            return Err(self.stopped(SeamStop::Failed));
        }
        let outcome = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let ctx = DurableStepContext {
                        vault: self.vault,
                        attempt_id: self.attempt,
                        run_id: self.run_id.clone(),
                        envelope_actor: self.actor,
                        subject: self.code_run,
                        deadline: Some(self.deadline),
                        now_ms: now.saturating_mul(1_000),
                    };
                    let mut slot = None;
                    self.reactor.block_on(Box::pin(async {
                        slot = Some(call_as_step(&ctx, self.inner, self.meter, request).await);
                    }));
                    slot
                })
                .join()
        })
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        match outcome {
            Some(Ok(StepOutcome::Finished { response, .. })) => {
                if let Some(digest) = response_digest(&response)
                    && let Err(error) = self.vault.record_turn_program_model_step(
                        self.attempt,
                        self.code_run,
                        occurrence,
                        request_hash,
                        Some(digest),
                        now,
                    )
                {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a turn program's model step was not settled; its step claim stands"
                    );
                }
                Ok(response)
            }
            Some(Ok(StepOutcome::Trapped { .. })) => Err(self.stopped(SeamStop::Trapped)),
            Some(Err(
                DurableStepError::FinalizeRefused
                | DurableStepError::DeadlineHardCut
                | DurableStepError::SpentFinalizeRefused { .. },
            )) => Err(self.stopped(SeamStop::Deadline)),
            Some(Err(DurableStepError::Llm(error))) => {
                self.note(SeamStop::Failed);
                Err(error)
            }
            Some(Err(_)) | None => Err(self.stopped(SeamStop::Failed)),
        }
    }
}

fn response_digest(response: &LlmResponse) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(response).ok()?;
    Some(
        *blake3::Hasher::new()
            .update(RESPONSE_DOMAIN)
            .update(&bytes)
            .finalize()
            .as_bytes(),
    )
}

impl LlmBackend for ProgramModelSeam<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move { self.step(request) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
