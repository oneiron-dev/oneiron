//! A contribution fork's program, run (FIX 3607, FIX 3028): an engine
//! step's fork is scored on what its answer's program did, never on the
//! answer's text. The step's frozen window is prepared once, before either
//! fork is generated ([`fork_evidence`]). Each fork's kept answer then runs
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
//! is unavailable for the shadow runner's own reason, never a loss: a call
//! the record does not hold, a nested unit not captured, an answer the live
//! guest read through a view the record does not keep, a step that parked on
//! a recorded wait. A workflow step keeps its text scoring; an engine step
//! never falls back to it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::super::replay_capsule::{CapsuleHost, StepReplayCapsule};
use super::super::storage::{fork_execution_outputs, fork_response, store_fork_execution};
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

/// What a fork's scorer reads (FIX 3607): a workflow step's answer text, or
/// an engine step's executed program under the pin both forks ran under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkEvidence {
    /// A saved-workflow step's single text call: its answer's text.
    AnswerText,
    /// An engine step: what its answer's program did when run, by the
    /// digest of the [`ForkExecutionPin`] both forks ran under.
    ExecutedProgram { pin: [u8; 32] },
}

impl ForkEvidence {
    /// Its bytes in the anchor's hash.
    pub(super) fn hash_into(&self, hasher: &mut blake3::Hasher) {
        match self {
            Self::AnswerText => {
                hasher.update(&[0]);
            }
            Self::ExecutedProgram { pin } => {
                hasher.update(&[1]);
                hasher.update(pin);
            }
        }
    }
}

/// What both forks of an engine step run under (FIX 3607), frozen before
/// either is generated: the captured start, where the step's recorded calls
/// are, the guest clock and seed, and the runtime's component pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkExecutionPin {
    /// BLAKE3 of the step's start body as stored.
    pub start: [u8; 32],
    /// Where the step's recorded calls are in its run's bridge log.
    pub bridge_start: u64,
    pub bridge_end: u64,
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

/// One output of a fork's program, as its scorer reads it: its path in the
/// step, whether its producer finished it, and its bytes, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedOutput {
    pub path: String,
    pub complete: bool,
    pub bytes: Vec<u8>,
}

/// A fork's executed program as its scorer reads it (FIX 3607): how its
/// step ended, the pin it ran under, how far into the step's recorded calls
/// it matched, and its observation, files and stored results.
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
/// call it matched whose answer the live guest read through a hook's view
/// (`guest_view_capture_missing`), a step that parked on a recorded wait
/// (`captured_outcome_missing`), and a body the secret scan marked
/// (`source_withheld`).
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
    if served_view(step, consumed) {
        let view = ShadowUnavailable::new(Reason::GuestViewCaptureMissing, "hook_view");
        return Ok(Err(view));
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

/// Whether a recorded call the program matched, from the step's start to
/// `consumed`, reached the live guest through a hook's view: the record
/// keeps the outcome, never the view the guest read.
fn served_view(step: &PreparedShadowStep, consumed: u64) -> bool {
    let (start, _) = step.bridge_window();
    let (Ok(start), Ok(consumed)) = (usize::try_from(start), usize::try_from(consumed)) else {
        return true;
    };
    step.window
        .bridge_calls
        .get(start..consumed)
        .is_none_or(|calls| calls.iter().any(|call| call.hook_view_served))
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

/// What `capsule`'s forks are scored on: a workflow step's answer text, or
/// an engine step's executed program, its window frozen now under the host's
/// runtime pin. An engine step whose window or runtime is unavailable is
/// unavailable for that reason, never scored on text.
pub(super) fn fork_evidence(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    program: &dyn ContributionForkProgram,
) -> Outcome<(ForkEvidence, Option<ProgramStep>)> {
    if capsule.host == CapsuleHost::WorkflowStep {
        return Ok(Ok((ForkEvidence::AnswerText, None)));
    }
    let step = match prepare_shadow_step_source(vault, capsule)? {
        Ok(step) => step,
        Err(unavailable) => return Ok(Err(Unavailable::ProgramReplay(unavailable))),
    };
    let runtime = match program.runtime_pin()? {
        Ok(runtime) => runtime,
        Err(unavailable) => return Ok(Err(Unavailable::ProgramReplay(unavailable))),
    };
    let pin = ForkExecutionPin::of(&step, runtime);
    let evidence = ForkEvidence::ExecutedProgram { pin: pin.digest() };
    Ok(Ok((evidence, Some(ProgramStep { step, pin }))))
}

impl Runner<'_> {
    /// An engine step's fork as executed, else its kept answer's program run
    /// now and its execution kept before it is scored; a workflow step's fork
    /// as it is.
    pub(super) fn executed(
        &self,
        prepared: &Prepared,
        fork: ContributionForkReceipt,
    ) -> Outcome<ContributionForkReceipt> {
        let Some(frozen) = &prepared.program_step else {
            return Ok(Ok(fork));
        };
        if fork.execution.is_some() {
            return Ok(ran_under(fork, frozen.pin));
        }
        if !self.clock.decision_may_start() {
            return Ok(Err(Unavailable::Unfinished));
        }
        let Some(response) = fork_response(self.vault, prepared.capsule.run, &fork)? else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let executed = match self.program.execute(&frozen.step, &response)? {
            Ok(executed) => executed,
            Err(unavailable) => return Ok(Err(Unavailable::ProgramReplay(unavailable))),
        };
        if executed.runtime != frozen.pin.runtime {
            let drift = ShadowUnavailable::new(Reason::ArtifactDigestMismatch, "runtime");
            return Ok(Err(Unavailable::ProgramReplay(drift)));
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
        let kept = store_fork_execution(self.vault, capsule, &self.pair, &fork, &bodies, |refs| {
            executed.record(answer, pin, &paths, refs)
        })?;
        Ok(match kept {
            Some(kept) => ran_under(kept, pin),
            None => Err(Unavailable::Unreadable),
        })
    }

    /// An engine step's fork's executed program, as its scorer reads it;
    /// `None` for a workflow step's. Unfinished until its execution is kept,
    /// unreadable once a body of it is gone.
    pub(super) fn executed_view(
        &self,
        prepared: &Prepared,
        fork: &ContributionForkReceipt,
    ) -> Outcome<Option<ExecutedForkView>> {
        if prepared.program_step.is_none() {
            return Ok(Ok(None));
        }
        let Some(execution) = &fork.execution else {
            return Ok(Err(Unavailable::Unfinished));
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

/// `fork`, when its kept execution ran on its own answer under `pin`; else
/// the pair diverged.
fn ran_under(
    fork: ContributionForkReceipt,
    pin: ForkExecutionPin,
) -> std::result::Result<ContributionForkReceipt, Unavailable> {
    let ran = fork
        .execution
        .as_ref()
        .is_some_and(|execution| execution.pin == pin && execution.response == fork.response);
    if ran {
        Ok(fork)
    } else {
        Err(Unavailable::ForksDiverged)
    }
}
