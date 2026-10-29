//! The Dreamer's turn program runtime (DOOR-141 PR2 and PR3b, FIX 4382).
//!
//! [`TurnProgramExecutor`] wraps a host's executor: every other kind runs on
//! the wrapped one as before, and a turn program attempt runs here, on the
//! L11 inner runtime ([`EngineNativeExecutor`]) in the code run its admission
//! fixed. Each entry binds the attempt to its waking actor's live authority
//! and its pin first; a lapse runs nothing new. The host lends the runtime,
//! its verb door and the backend ([`TurnProgramRuntime`]); a host that lends
//! none for an actor holds that program alone.
//!
//! Each entry runs the pinned entry itself, through the executor's pinned
//! entry (`run_pinned_program`): the stored, pinned source on the same
//! attempt and code run, with no model writing its call. An entry after the
//! first replays that source, and each call an earlier entry settled is
//! answered from its checkpoint, never issued again (PR3b). Every model call
//! of the run is one durable step through `call_as_step`, on the program's
//! own actor meter, which borrows from the pass's shared meter and never
//! reserves twice. Each write and send settles into the program's step
//! (`dreamer_runner::program`).
//!
//! Waits and holds are honest. A run whose pinned entry finished completes,
//! its result attached under its lease in one commit. A run that stops short
//! is held by the program runtime: a wait until its reply is delivered, an
//! uncertain effect until nothing it did is unsettled, a lapsed authority
//! until it stands again, each resumed as the same try before a selection
//! (`dreamer_runner::program`'s resumer). Nothing restarts it from scratch,
//! and nothing reports it complete.
//!
//! A managed vault's attested owner's program runs only while the vault
//! records him as its live owner (FIX 11090): the owner refusal its entry's
//! binding or a write's reservation raises ends that try Failed, never held
//! for his standing to return.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::authority::ManagedOwnerCheckError;
use crate::code_run::{AgentVerbDoor, HostSelfDispatcher};
use crate::dreamer_runner::{
    DREAMER_TURN_PROGRAM_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause, ProgramHold,
    ProgramRecipePin, TurnProgramBinding, TurnProgramBound, TurnProgramEntered,
};
use crate::engine_executor::{
    EngineExecutorConfig, EngineExecutorError, EngineExecutorResult, EngineExecutorStatus,
    EngineNativeExecutor, JsCodeModeRuntime, PinnedProgramEntry, PinnedProgramRun,
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

const TRAPPED_REASON: &str = "durable step trapped for resume";
/// Why a program's entry stopped short of a hold: the next entry resumes it
/// from its pinned entry.
const RESUMES: &str = "its next entry resumes it from its pinned entry";

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
/// waking actor it runs as, its code run and its task, and, for a slip's
/// turn, that slip's live, verified view: the door the host lends binds
/// every row it serves to it (FIX 8717).
pub struct TurnProgramRequest<'r> {
    pub attempt: &'r AttemptRecord,
    pub actor: WriteActor,
    pub code_run: EntityId,
    pub task: &'r str,
    pub proof: Option<&'r crate::authority::VerifiedSlip>,
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
            None => hold(ctx, &attempt.status.attempt, ProgramHold::Unbound),
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
/// the program kind's resumer finds `held`'s condition met, never on a
/// pass's or a boot's own sweep.
fn hold(
    ctx: &WakeAttemptContext<'_>,
    attempt: &AttemptRecord,
    held: ProgramHold,
) -> Result<DreamerAttemptExecution> {
    ctx.vault
        .hold_turn_program(attempt.id, held, ctx.now_ms / 1_000)?;
    Ok(DreamerAttemptExecution::Park {
        reason: held.reason().to_owned(),
        cause: DreamerParkCause::Other,
    })
}

/// The try of an attested owner who is no longer the vault's live owner,
/// ended Failed with what it spent (FIX 11090).
fn owner_not_live(completed_units: u64) -> DreamerAttemptExecution {
    DreamerAttemptExecution::Failed {
        reason: crate::authority::OWNER_NOT_LIVE.to_owned(),
        completed_units,
    }
}

/// The program's task, as its host binds its run's config and seat from it:
/// its pinned callable entry, exactly as pinned. The entry runs as pinned
/// with no model writing its call.
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
        TurnProgramBound::Lapsed(held) => return hold(ctx, attempt, held),
        TurnProgramBound::OwnerNotLive => return Ok(owner_not_live(0)),
    };
    let task = program_task(&binding.pin);
    let request = TurnProgramRequest {
        attempt,
        actor: binding.actor,
        code_run: binding.code_run,
        task: &task,
        proof: binding.proof.as_ref(),
    };
    let Some(host) = runtime.bind(vault, &request) else {
        return hold(ctx, attempt, ProgramHold::Unbound);
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
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
        }
        // A cut run resumes from its pinned entry as this same try, unless an
        // effect of it is not settled or its actor is gone (DOOR-141 PR3b).
        Ok(TurnProgramEntered::Cut) => match vault.turn_program_resume_preflight(attempt.id) {
            Ok(None) => enter(host, &binding, attempt, ctx, &meter, &loan.lease).await,
            Ok(Some(held)) => {
                repay(shared, &loan.lease, 0);
                return hold(ctx, attempt, held);
            }
            Err(error) => {
                repay(shared, &loan.lease, 0);
                return Err(error);
            }
        },
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
    outcome: EngineExecutorResult<PinnedProgramRun>,
    stop: Option<SeamStop>,
    pinned_finished: bool,
}

/// Runs one entry of the program's code run on the host's runtime, through
/// the engine executor's pinned entry: the pinned callable, from its stored
/// source, resumed past every call an earlier entry settled.
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
    let entry = pinned_entry(binding, attempt, ctx)?;
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
        binding.proof.clone(),
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
    let outcome = executor.run_pinned_program(&config, &entry);
    let pinned_finished = matches!(
        &outcome,
        Ok(PinnedProgramRun::Ran(done)) if dispatcher.pinned_entry_finished(&done.replay_record)
    );
    Ok(Ran {
        outcome,
        stop: seam.stop(),
        pinned_finished,
    })
}

/// The entry the program's pin names, for its try.
fn pinned_entry(
    binding: &TurnProgramBinding,
    attempt: &AttemptRecord,
    ctx: &WakeAttemptContext<'_>,
) -> Result<PinnedProgramEntry> {
    let pin = &binding.pin;
    let args: serde_json::Value = serde_json::from_str(&pin.args).map_err(|_| {
        Error::InvalidConfig("a turn program's pinned arguments are not JSON".to_owned())
    })?;
    Ok(PinnedProgramEntry {
        code_run: binding.code_run,
        skill: pin.skill,
        args,
        content_hash: pin.content_hash.clone(),
        contract_digest: pin.contract_digest,
        executor: pin.executor.clone(),
        attempt: *attempt.id.as_bytes(),
        at: ctx.now_ms / 1_000,
    })
}

/// What one entry's end means for the program's try. An entry that stops
/// short is held by the program runtime, its spend settled on the pass's
/// meter all the same. One that stopped on the owner refusal its attested
/// owner's authority check raised ends Failed on that refusal, carried as it
/// was raised (FIX 11090), never held.
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
    let held = |kind: ProgramHold| -> Result<DreamerAttemptExecution> {
        vault.hold_turn_program(attempt.id, kind, ctx.now_ms / 1_000)?;
        Ok(DreamerAttemptExecution::ParkWithSpend {
            reason: kind.reason().to_owned(),
            cause: DreamerParkCause::Other,
            completed_units: used,
            step_hashes: Vec::new(),
        })
    };
    let ran = match ran {
        Ok(ran) => ran,
        Err(error) if ManagedOwnerCheckError::is_owner_refusal(&error) => {
            return Ok(owner_not_live(used));
        }
        Err(error) => return Ok(stopped(format!("the turn program did not enter: {error}"))),
    };
    let outcome = match ran.outcome {
        Ok(PinnedProgramRun::Ran(outcome)) => outcome,
        Ok(PinnedProgramRun::Held(why)) => {
            tracing::warn!(why, "a turn program's entry holds; it ran nothing new");
            return held(ProgramHold::Diverged);
        }
        Err(error) => {
            return Ok(match ran.stop {
                // The step layer parked the try in its trap's own commit.
                Some(SeamStop::Trapped) => DreamerAttemptExecution::Park {
                    reason: TRAPPED_REASON.to_owned(),
                    cause: DreamerParkCause::Signal,
                },
                // A write's reservation met the owner refusal (FIX 11090).
                _ if matches!(
                    &error,
                    EngineExecutorError::Engine(error) if ManagedOwnerCheckError::is_owner_refusal(error)
                ) =>
                {
                    owner_not_live(used)
                }
                Some(SeamStop::Deadline) => stopped(format!(
                    "the pass's deadline cut the turn program; {RESUMES}"
                )),
                Some(SeamStop::Failed) | None => stopped(format!(
                    "the turn program's run stopped: {error}; {RESUMES}"
                )),
            });
        }
    };
    match outcome.status {
        EngineExecutorStatus::Complete if ran.pinned_finished => {
            let generation = outcome.replay_record.generation()?;
            vault.settle_turn_program_run(
                attempt,
                binding.code_run,
                &generation,
                ctx.now_ms / 1_000,
            )?;
            Ok(DreamerAttemptExecution::Completed {
                completed_units: used,
                step_hashes: Vec::new(),
            })
        }
        EngineExecutorStatus::Complete => held(ProgramHold::Unfinished),
        EngineExecutorStatus::Waiting(_) => held(ProgramHold::Wait),
        EngineExecutorStatus::Yielded { next_step_seq }
        | EngineExecutorStatus::WindowFull { next_step_seq, .. } => Ok(stopped(format!(
            "the turn program stopped at step {next_step_seq} as the pass ended; {RESUMES}"
        ))),
    }
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
