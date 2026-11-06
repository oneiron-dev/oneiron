//! A contribution fork's program, run (FIX 3607, FIX 3028), and the
//! evidence mode its pair is scored in. L08-A owns the scorer and rubric
//! contract. Its answer of 2026-11-06 07:42: no frozen held-out or audit
//! rubric is qualified to read only an executed step's output. So the mode
//! is chosen per pair, never per fork ([`pair_evidence_mode`]). In the
//! `Executed` mode both forks of an engine step ran their answers to the
//! step's end under one pin. The scorer then reads each answer's text and
//! what its program did, together: every input the rubric read before is
//! still there, and the execution is added to it. Otherwise both forks are
//! scored in the `Text` mode, on the answer's text alone, as before FIX
//! 3607. A workflow step's pair is always in the `Text` mode.
//!
//! The step's frozen window is prepared once, before either fork is
//! generated ([`freeze_program_step`]). Each fork's kept answer then runs
//! on a fresh runtime of the host's one pinned component, in a scratch store
//! of its own, against the same recorded calls, clock and seed
//! ([`execute_contribution_fork`], through the shadow runner's
//! [`run_shadow_step`]). The host lends the runtime and the store
//! ([`ContributionForkProgram`]). The program runs inside the executor's
//! sandbox boundary without host services: no live dispatcher, gated write,
//! outbound adapter, credential resolver or memory query reaches it.
//!
//! Its observation, files, stored results and both traces are adopted as
//! bodies the run owns, in the one writer that keeps the fork's execution;
//! a retry reuses a committed execution. A program the record cannot answer
//! is unavailable for the shadow runner's own reason, and the fork keeps
//! that reason ([`ForkExecutionOutcome`]): a call the record does not hold,
//! a nested unit not captured, a call whose guest response the step's replay
//! context does not hold (FIX 6351), a step that parked on a recorded wait,
//! no runtime now. A lasting reason puts the pair in the `Text` mode at
//! once. A reason a retry may clear waits for one retry first. Neither is a
//! loss. A call the live guest read through a hook's view the context kept
//! runs as it ran, and its fork is evidence like any other.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::super::replay_capsule::{CapsuleHost, StepReplayCapsule};
use super::super::storage::{fork_execution_outputs, fork_response, store_fork_execution};
use super::owner::OwnerJudgment;
use super::{
    ContributionForkReceipt, ContributionReplayUnavailable as Unavailable, Outcome, Prepared,
    Runner,
};
use crate::code_run::shadow_runner::{
    PreparedShadowStep, ShadowBodyRef, ShadowBodyStore, ShadowDeterminism, ShadowStatus,
    ShadowUnavailable, ShadowUnavailableReason as Reason, prepare_shadow_step_source,
};
use crate::code_sandbox::SANDBOX_WIT_WORLD_NAME;
use crate::compaction::output::OutputRef;
use crate::dreamer_runner::shadow_values::SHADOW_PROTOCOL_VERSION;
use crate::engine_executor::{
    ArmTypeFeedback, JsCodeModeRuntime, StepCancellation, is_result_output_path, run_shadow_step,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, LlmResponse, Result, Vault};

/// A program run's part, or the shadow runner's reason it has none.
type Ran<T> = Result<std::result::Result<T, ShadowUnavailable>>;

/// What a pair's scorer reads (FIX 3607), the same for both forks: one part
/// of the identity both forks are scored under, beside their anchor's
/// frozen rubric and scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkEvidenceMode {
    /// Each answer's text alone: the route before FIX 3607, and a workflow
    /// step's always.
    Text,
    /// An engine step whose two forks both ran their answers under one pin:
    /// each answer's text and what its program did, by the digest of the
    /// [`ForkExecutionPin`] both ran under.
    Executed { pin: [u8; 32] },
}

/// A fork's score: the evidence mode its pair was scored in, whether it
/// passed and who decided that. Both forks of a pair are scored in one mode
/// and by one judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkScore {
    pub mode: ForkEvidenceMode,
    pub passed: bool,
    pub judge: ForkJudge,
}

/// Who decided a fork's score (FIX 3609). It is kept apart from the
/// evidence mode: the mode says what was read, the judge says who read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkJudge {
    /// The anchor's scorer the host lent, by the pair's frozen rubric.
    Scorer,
    /// The owner's own counted word on the pair's question.
    Owner(OwnerJudgment),
}

/// What both forks of an engine step run under (FIX 3607), frozen before
/// either is generated: the captured start, where the step's recorded calls
/// are, the responses its live guest read, the guest clock and seed, and the
/// runtime's component pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkExecutionPin {
    /// BLAKE3 of the step's start body as stored.
    pub start: [u8; 32],
    /// Where the step's recorded calls are in its run's bridge log.
    pub bridge_start: u64,
    pub bridge_end: u64,
    /// BLAKE3 of the step's replay context as stored: the responses its live
    /// guest read (FIX 6351) and what its result reads saw of reader state
    /// (FIX 6352); `None` when none was read.
    pub context: Option<[u8; 32]>,
    pub determinism: ShadowDeterminism,
    /// The SHA-256 the host pinned its runtime's component to.
    pub runtime: [u8; 32],
}

impl ForkExecutionPin {
    fn of(step: &PreparedShadowStep, runtime: [u8; 32]) -> Self {
        let (bridge_start, bridge_end) = step.bridge_window();
        Self {
            start: step.start().digest,
            bridge_start,
            bridge_end,
            context: step.context_digest(),
            determinism: step.determinism(),
            runtime,
        }
    }

    /// Its digest, bound to the executor's sandbox contract as well: the WIT
    /// world and the shadow protocol the programs run under.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron contribution fork execution pin");
        hasher.update(SANDBOX_WIT_WORLD_NAME.as_bytes());
        hasher.update(&[0]);
        hasher.update(&SHADOW_PROTOCOL_VERSION.to_be_bytes());
        hasher.update(&self.start);
        hasher.update(&self.bridge_start.to_be_bytes());
        hasher.update(&self.bridge_end.to_be_bytes());
        hasher.update(&[u8::from(self.context.is_some())]);
        if let Some(context) = &self.context {
            hasher.update(context);
        }
        hasher.update(&self.determinism.frozen_unix_ms.to_be_bytes());
        hasher.update(&self.determinism.rng_seed);
        hasher.update(&self.runtime);
        *hasher.finalize().as_bytes()
    }
}

/// How a fork's program step ended when it ran: to its end (`done` when its
/// program finished the run), or failed as a run's step fails (`kind` names
/// how). Only these are evidence a scorer reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedStepStatus {
    StepComplete { done: bool },
    Failed { kind: String },
}

/// One body a fork's program left, adopted as a body its source run owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedBody {
    /// Its path in the step, as the program's run names it.
    pub path: String,
    /// Where the run keeps it: an opaque fork path.
    pub stored_path: String,
    pub body: OutputRef,
    /// Whether its producer finished it.
    pub complete: bool,
}

/// One fork's executed program (FIX 3607): the answer it ran, the pin it ran
/// under, how its step ended, how far into the step's recorded calls it
/// matched, and every body it left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionForkExecution {
    /// The fork's own answer it ran, by its body ref.
    pub response: OutputRef,
    pub pin: ForkExecutionPin,
    pub status: ExecutedStepStatus,
    /// The bridge position after the last recorded call it matched.
    pub consumed: u64,
    /// Its observation, its files and the results it stored.
    pub outputs: Vec<ExecutedBody>,
    /// The effects it asked for, matched or not: a MessagePack trace.
    pub effect_trace: ExecutedBody,
    /// The recorded calls it matched: a MessagePack trace.
    pub bridge_trace: ExecutedBody,
    /// Unix seconds it ran.
    pub executed_at: u64,
}

impl ContributionForkExecution {
    /// Every body it names: its outputs, then its two traces.
    pub(crate) fn bodies(&self) -> impl Iterator<Item = &ExecutedBody> {
        self.outputs
            .iter()
            .chain([&self.effect_trace, &self.bridge_trace])
    }
}

/// What came of an engine step's fork's program run (FIX 3607), kept on the
/// fork's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkExecutionOutcome {
    /// It ran to the step's end, and its bodies are adopted.
    Executed(ContributionForkExecution),
    /// It did not run, for a reason the shadow runner says a retry may
    /// clear. A later pass runs it once more before its pair falls back to
    /// the `Text` mode.
    RetryPending(ShadowUnavailable),
    /// It cannot run: a lasting reason, or a retryable one that held at its
    /// retry. Its pair is scored in the `Text` mode.
    Unavailable(ShadowUnavailable),
}

impl ForkExecutionOutcome {
    /// Whether it is final: it does not wait for a retry.
    #[must_use]
    pub const fn settled(&self) -> bool {
        !matches!(self, Self::RetryPending(_))
    }

    /// Its kept execution, when it ran.
    #[must_use]
    pub const fn executed(&self) -> Option<&ContributionForkExecution> {
        match self {
            Self::Executed(execution) => Some(execution),
            Self::RetryPending(_) | Self::Unavailable(_) => None,
        }
    }

    /// Every body it names: none unless it ran.
    pub(crate) fn bodies(&self) -> impl Iterator<Item = &ExecutedBody> {
        self.executed()
            .into_iter()
            .flat_map(ContributionForkExecution::bodies)
    }
}

/// One output of a fork's program, as its scorer reads it: its path in the
/// step, whether its producer finished it, and its bytes, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedOutput {
    pub path: String,
    pub complete: bool,
    pub bytes: Vec<u8>,
}

/// A fork's executed program as its scorer reads it in the `Executed` mode
/// (FIX 3607), beside the answer's text: how its step ended, the pin it ran
/// under, how far into the step's recorded calls it matched, and its
/// observation, files and stored results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedForkView {
    pub status: ExecutedStepStatus,
    pub pin: ForkExecutionPin,
    pub consumed: u64,
    pub outputs: Vec<ExecutedOutput>,
}

/// One fork's program as the host's runtime ran it, read back whole from its
/// scratch store before the host released the store: the component it ran
/// on, how its step ended, where it matched to, and each body to adopt.
pub struct ExecutedFork {
    runtime: [u8; 32],
    status: ExecutedStepStatus,
    consumed: u64,
    outputs: Vec<(ShadowBodyRef, Vec<u8>)>,
    effect_trace: (ShadowBodyRef, Vec<u8>),
    bridge_trace: (ShadowBodyRef, Vec<u8>),
}

impl ExecutedFork {
    /// Every body it read back: its outputs, then its two traces.
    fn bodies(&self) -> impl Iterator<Item = &(ShadowBodyRef, Vec<u8>)> {
        self.outputs
            .iter()
            .chain([&self.effect_trace, &self.bridge_trace])
    }

    /// Its execution, run on `response` under `pin`, each body kept at its
    /// path of `paths` as its ref of `refs`, in [`Self::bodies`] order;
    /// `None` when they name another count of bodies.
    fn record(
        &self,
        response: OutputRef,
        pin: ForkExecutionPin,
        paths: &[String],
        refs: &[OutputRef],
    ) -> Option<ContributionForkExecution> {
        if paths.len() != refs.len() {
            return None;
        }
        let mut kept =
            self.bodies()
                .zip(paths.iter().zip(refs))
                .map(|((body, _), (stored_path, adopted))| ExecutedBody {
                    path: body.path.clone(),
                    stored_path: stored_path.clone(),
                    body: *adopted,
                    complete: body.complete,
                });
        let outputs: Vec<ExecutedBody> = kept.by_ref().take(self.outputs.len()).collect();
        let effect_trace = kept.next()?;
        let bridge_trace = kept.next()?;
        if outputs.len() != self.outputs.len() || kept.next().is_some() {
            return None;
        }
        Some(ContributionForkExecution {
            response,
            pin,
            status: self.status.clone(),
            consumed: self.consumed,
            outputs,
            effect_trace,
            bridge_trace,
            executed_at: crate::unix_seconds_now(),
        })
    }
}

/// The program run an engine step's fork makes (FIX 3607), lent by the host.
pub trait ContributionForkProgram {
    /// The pin of the component every fork's program runs on, as the host
    /// holds it now; unavailable when it has none.
    ///
    /// # Errors
    ///
    /// A host failure.
    fn runtime_pin(&self) -> Result<std::result::Result<[u8; 32], ShadowUnavailable>>;

    /// `response`'s program run for `step`'s captured step through
    /// [`execute_contribution_fork`], on a fresh runtime of that component
    /// and in a scratch store of its own that the host releases before this
    /// returns.
    ///
    /// # Errors
    ///
    /// The scratch store failing, and a step the executor cannot set up.
    fn execute(
        &self,
        step: &PreparedShadowStep,
        response: &LlmResponse,
    ) -> Result<std::result::Result<ExecutedFork, ShadowUnavailable>>;
}

/// Runs `response`'s program for `step`'s captured step on `runtime`, a
/// fresh runtime of the component pinned at `runtime_pin`, its bodies in
/// `store`, a scratch store of its own, and reads back whole what it left.
/// Its program is not type-checked: no reader of a fork's feedback exists.
/// Unavailable for the shadow runner's own reason, and also for a recorded
/// call it matched whose guest response the step's replay context does not
/// hold (`guest_view_capture_missing`, the bridge's own check, FIX 6351), a
/// step that parked on a recorded wait (`captured_outcome_missing`), and a
/// body the secret scan marked (`source_withheld`).
///
/// # Errors
///
/// The store failing, and a step the executor cannot set up.
pub fn execute_contribution_fork(
    step: &PreparedShadowStep,
    response: &LlmResponse,
    runtime: &mut dyn JsCodeModeRuntime,
    runtime_pin: [u8; 32],
    store: &ShadowBodyStore,
    cancel: &StepCancellation,
) -> Result<std::result::Result<ExecutedFork, ShadowUnavailable>> {
    let feedback = ArmTypeFeedback {
        service: None,
        arm: EntityId::now(),
        live: Arc::new(|| false),
    };
    let run = run_shadow_step(step, response, runtime, store, cancel, &feedback)?;
    let status = match run.status {
        ShadowStatus::Unavailable { unavailable } => return Ok(Err(unavailable)),
        ShadowStatus::StepComplete { done } => Some(ExecutedStepStatus::StepComplete { done }),
        ShadowStatus::Failed { kind } => Some(ExecutedStepStatus::Failed { kind }),
        ShadowStatus::Waiting { .. }
        | ShadowStatus::Yielded { .. }
        | ShadowStatus::WindowFull { .. } => None,
    };
    let consumed = run.bridge.consumed;
    // Every call it matched was answered with the response its live guest
    // read (FIX 6351): the same check the bridge answered each one by.
    if let Err(missing) = step.captured_responses(consumed) {
        return Ok(Err(missing));
    }
    // A step parked on a recorded wait, or left open, has its answer in a
    // later step: the captured step holds no outcome of it.
    let Some(status) = status else {
        let open = ShadowUnavailable::new(Reason::CapturedOutcomeMissing, "step_open");
        return Ok(Err(open));
    };
    let mut outputs = Vec::new();
    for body in run.outputs {
        if !is_result_output_path(&body.path) {
            continue;
        }
        match read_whole(store, body)? {
            Ok(read) => outputs.push(read),
            Err(unavailable) => return Ok(Err(unavailable)),
        }
    }
    let effect_trace = match read_whole(store, run.effect_trace)? {
        Ok(read) => read,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let bridge_trace = match read_whole(store, run.bridge_trace)? {
        Ok(read) => read,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    // An erase that took the source's content while the bodies were read
    // leaves nothing of them to adopt (FIX 5718).
    if let Some(withheld) = store.source_withheld() {
        return Ok(Err(withheld));
    }
    Ok(Ok(ExecutedFork {
        runtime: runtime_pin,
        status,
        consumed,
        outputs,
        effect_trace,
        bridge_trace,
    }))
}

/// `body`, read whole from `store`: unavailable when the secret scan marked
/// it, which no read shows, or the store no longer holds it.
fn read_whole(store: &ShadowBodyStore, body: ShadowBodyRef) -> Ran<(ShadowBodyRef, Vec<u8>)> {
    if let Some(reason) = body.secret.as_deref() {
        return Ok(Err(ShadowUnavailable::new(Reason::SourceWithheld, reason)));
    }
    Ok(match store.read(body.body)? {
        Some(bytes) => Ok((body, bytes)),
        None => Err(ShadowUnavailable::new(Reason::SourceMissing, "arm_body")),
    })
}

/// An engine step's frozen window and the pin both forks' programs run
/// under, prepared once before either fork is generated.
pub(super) struct ProgramStep {
    pub(super) step: PreparedShadowStep,
    pub(super) pin: ForkExecutionPin,
}

/// `capsule`'s frozen program step: `None` for a workflow step, which has
/// no program. An engine step's window is frozen now under the host's
/// runtime pin. A window or runtime that is unavailable now is that reason,
/// which each fork keeps as its program's outcome; the pair then falls back
/// to the `Text` mode, never to a loss.
pub(super) fn freeze_program_step(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    program: &dyn ContributionForkProgram,
) -> Result<Option<std::result::Result<ProgramStep, ShadowUnavailable>>> {
    if capsule.host == CapsuleHost::WorkflowStep {
        return Ok(None);
    }
    let step = match prepare_shadow_step_source(vault, capsule)? {
        Ok(step) => step,
        Err(unavailable) => return Ok(Some(Err(unavailable))),
    };
    Ok(Some(program.runtime_pin()?.map(|runtime| ProgramStep {
        pin: ForkExecutionPin::of(&step, runtime),
        step,
    })))
}

/// The evidence mode a pair is scored in (FIX 3607), chosen per pair and
/// never per fork: `Executed`, under the pin both forks ran under, when
/// both are an engine step's forks whose kept executions ran their own
/// answers under one pin; else `Text` for both. A workflow step's pair is
/// always `Text`. `None` while an engine step's fork has not run, or waits
/// for its retry.
pub(super) fn pair_evidence_mode(
    host: CapsuleHost,
    with_skill: &ContributionForkReceipt,
    without_skill: &ContributionForkReceipt,
) -> Option<ForkEvidenceMode> {
    if host == CapsuleHost::WorkflowStep {
        return Some(ForkEvidenceMode::Text);
    }
    Some(match (own_run(with_skill)?, own_run(without_skill)?) {
        (Some(with), Some(without)) if with.pin == without.pin => ForkEvidenceMode::Executed {
            pin: with.pin.digest(),
        },
        _ => ForkEvidenceMode::Text,
    })
}

/// `fork`'s kept execution of its own answer, once its program's outcome is
/// settled: `Some(None)` when it settled without one, `None` while it has
/// not run or waits for its retry.
fn own_run(fork: &ContributionForkReceipt) -> Option<Option<&ContributionForkExecution>> {
    let outcome = fork
        .execution
        .as_ref()
        .filter(|outcome| outcome.settled())?;
    Some(
        outcome
            .executed()
            .filter(|execution| execution.response == fork.response),
    )
}

/// `fork`, when it is scored in `mode` by the anchor's scorer; else the pair
/// diverged.
pub(super) fn scored_in(
    fork: ContributionForkReceipt,
    mode: ForkEvidenceMode,
) -> std::result::Result<ContributionForkReceipt, Unavailable> {
    if fork
        .score
        .is_some_and(|score| score.mode == mode && score.judge == ForkJudge::Scorer)
    {
        Ok(fork)
    } else {
        Err(Unavailable::ForksDiverged)
    }
}

/// Why a pair whose mode is not settled is not scored this pass: the reason
/// a fork's program waits for its retry on, which a later pass asks again.
pub(super) fn retry_pending(forks: [&ContributionForkReceipt; 2]) -> Unavailable {
    forks
        .into_iter()
        .find_map(|fork| match &fork.execution {
            Some(ForkExecutionOutcome::RetryPending(unavailable)) => {
                Some(Unavailable::ProgramReplay(unavailable.clone()))
            }
            _ => None,
        })
        .unwrap_or(Unavailable::Unfinished)
}

impl Runner<'_> {
    /// An engine step's fork with its program's outcome settled or pending,
    /// kept before either fork is scored: as kept when it is settled, else
    /// its kept answer's program run now. A workflow step's fork as it is.
    /// An outcome its writer does not keep is unavailable for that writer's
    /// own reason (FIX 6256).
    pub(super) fn executed(
        &self,
        prepared: &Prepared,
        fork: ContributionForkReceipt,
    ) -> Outcome<ContributionForkReceipt> {
        let Some(frozen) = &prepared.frozen_program else {
            return Ok(Ok(fork));
        };
        if fork
            .execution
            .as_ref()
            .is_some_and(ForkExecutionOutcome::settled)
        {
            return Ok(Ok(fork));
        }
        let frozen = match frozen {
            Ok(frozen) => frozen,
            Err(unavailable) => return self.unexecuted(prepared, fork, unavailable.clone()),
        };
        if !self.clock.decision_may_start() {
            return Ok(Err(Unavailable::Unfinished));
        }
        let Some(response) = fork_response(self.vault, prepared.capsule.run, &fork)? else {
            return Ok(Err(if fork.response_erased {
                Unavailable::Erased
            } else {
                Unavailable::Unreadable
            }));
        };
        let executed = match self.program.execute(&frozen.step, &response)? {
            Ok(executed) => executed,
            Err(unavailable) => return self.unexecuted(prepared, fork, unavailable),
        };
        if executed.runtime != frozen.pin.runtime {
            let drift = ShadowUnavailable::new(Reason::ArtifactDigestMismatch, "runtime");
            return self.unexecuted(prepared, fork, drift);
        }
        // The bodies' paths are opaque, as the fork's answer's is.
        let path_id = bytes_to_hex_lower(&self.vault.store.clock.ulid()?);
        let paths: Vec<String> = (0..executed.bodies().count())
            .map(|index| format!("replay/contribution/{path_id}.execution.{index:03}"))
            .collect();
        let bodies: Vec<(&str, &[u8])> = paths
            .iter()
            .map(String::as_str)
            .zip(executed.bodies().map(|(_, bytes)| bytes.as_slice()))
            .collect();
        let (answer, pin) = (fork.response, frozen.pin);
        let capsule = &prepared.capsule;
        // Its bodies, its execution and their erase ownership commit together.
        store_fork_execution(self.vault, capsule, &self.pair, &fork, &bodies, |refs| {
            executed
                .record(answer, pin, &paths, refs)
                .map(ForkExecutionOutcome::Executed)
        })
    }

    /// `fork` with its program kept unavailable for `unavailable`: pending
    /// one retry when a retry may clear it and the fork has not waited yet,
    /// else for good.
    fn unexecuted(
        &self,
        prepared: &Prepared,
        fork: ContributionForkReceipt,
        unavailable: ShadowUnavailable,
    ) -> Outcome<ContributionForkReceipt> {
        let outcome = if unavailable.retryable && fork.execution.is_none() {
            ForkExecutionOutcome::RetryPending(unavailable)
        } else {
            ForkExecutionOutcome::Unavailable(unavailable)
        };
        let (vault, capsule) = (self.vault, &prepared.capsule);
        store_fork_execution(vault, capsule, &self.pair, &fork, &[], |_| {
            Some(outcome.clone())
        })
    }

    /// A fork's executed program, as its scorer reads it in `mode`: `None`
    /// in the `Text` mode. Unreadable once a body of it is gone.
    pub(super) fn executed_view(
        &self,
        prepared: &Prepared,
        fork: &ContributionForkReceipt,
        mode: ForkEvidenceMode,
    ) -> Outcome<Option<ExecutedForkView>> {
        if mode == ForkEvidenceMode::Text {
            return Ok(Ok(None));
        }
        let execution = fork
            .execution
            .as_ref()
            .and_then(ForkExecutionOutcome::executed);
        let Some(execution) = execution else {
            return Ok(Err(Unavailable::ForksDiverged));
        };
        let run = prepared.capsule.run;
        let Some(outputs) = fork_execution_outputs(self.vault, run, execution)? else {
            return Ok(Err(Unavailable::Unreadable));
        };
        Ok(Ok(Some(ExecutedForkView {
            status: execution.status.clone(),
            pin: execution.pin,
            consumed: execution.consumed,
            outputs,
        })))
    }
}
