//! A callable's contribution (FIX 3608): a skill the run called as a
//! callable, and never had in its task, is judged by running its caller
//! again. The caller's step that first called the skill's load (the
//! earliest such step of the latest lease generation that captured one)
//! runs its own recorded program again from that step's start, twice, in
//! scratch arms of the host's one pinned component, with the step's frozen
//! clock, seed and recorded calls ([`ContributionForkProgram::execute_branch`]).
//! With the load present, the callable the step's replay context froze runs
//! again against its own recorded calls. With the load absent, the call
//! answers what the live host answers when the skill's entity is not found,
//! and the caller's program runs its own fallback. No reply is cut out
//! after its effects happened: each branch makes its own observation.
//!
//! Each branch's observation is rendered by the request builder's own
//! formatter into the one message the next step's captured request showed
//! the caller's console in, whole ([`ConsoleSlot`]); the rest of that
//! request stays as captured, its mask included. The two requests are the
//! pair's two forks, generated on the next step's captured rung and judged
//! by the same frozen anchor, scorer and evidence mode as any pair. The
//! forks' own programs do not run: the branch without the load has no
//! recorded world past its step, so the pair is scored in the `Text` mode.
//!
//! A branch the recorded calls do not answer, a callable whose stored file
//! does not read again as it loaded, a branch that ends its run, and a next
//! request that shows the console otherwise are unavailable for the shadow
//! runner's own reason ([`Unavailable::ProgramReplay`]), never a loss.

use std::cmp::Reverse;
use std::sync::Arc;

use super::super::{
    ContributionForkProgram, ContributionReplayUnavailable as Unavailable, ForkRows,
    ForkScoringIdentity, Outcome, Prepared, Runner, anchor_hash, request_hash,
};
use super::{ExecutedFork, ExecutedStepStatus, Ran, executed_run};
use crate::code_run::shadow_runner::{
    ArmCallableLoad, ArmCallables, PreparedShadowStep, ShadowBodyStore, ShadowUnavailable,
    ShadowUnavailableReason as Reason, prepare_shadow_step_source,
};
use crate::code_run::{
    CapsuleHost, CapsuleRequest, CapturedCallable, CodeRunHistoryTurn, ConsoleSlot,
    StepReplayCapsule, StepReplayContext, capsule_context_body, capsule_request,
};
use crate::engine_executor::{
    ArmTypeFeedback, JsCodeModeRuntime, StepCancellation, observation_output_path,
    run_shadow_callable_branch, script_output_path,
};
use crate::skill_attribution::ContributionTarget;
use crate::{ContentPart, EntityId, LlmRequest, Result, Vault};

/// One branch of a callable's counterfactual (FIX 3608), as the host's
/// program run takes it: the caller step's own recorded program, and how
/// the branch treats the step's recorded callables.
pub struct CallableBranch {
    program: String,
    callables: ArmCallables,
}

/// Runs `branch` for `step`'s captured caller step on `runtime`, a fresh
/// runtime of the component pinned at `runtime_pin`, its bodies in `store`,
/// a scratch store of its own, and reads back whole what it left, as
/// [`super::execute_contribution_fork`] reads a fork's program back. Its
/// program is not type-checked: no reader of a branch's feedback exists.
///
/// # Errors
///
/// The store failing, and a step the executor cannot set up.
pub fn execute_callable_branch(
    step: &PreparedShadowStep,
    branch: &CallableBranch,
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
    let (program, callables) = (&branch.program, &branch.callables);
    let run =
        run_shadow_callable_branch(step, program, callables, runtime, store, cancel, &feedback)?;
    executed_run(step, run, runtime_pin, store)
}

/// The steps a callable's check regenerates from (FIX 3608): the caller's
/// step that called the target's load, the bridge position of that call
/// and the revision it loaded at, and the next step, whose request each
/// branch rebuilds; `None` when that step was not captured.
pub(crate) struct CallableTarget {
    pub(crate) caller: StepReplayCapsule,
    pub(crate) seq: u64,
    pub(crate) revision: String,
    pub(crate) next: Option<StepReplayCapsule>,
}

/// The callable `target`'s check regenerates from among `capsules`, one
/// run's captured steps, read in `txn`: for a loaded skill, the first call
/// of its load that its step's replay context froze, in the earliest such
/// step of the latest lease generation with one. `None` for a used edge,
/// and when no context froze a call of the skill's load.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn callable_target_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    capsules: &[StepReplayCapsule],
    target: ContributionTarget,
) -> Result<Option<CallableTarget>> {
    let ContributionTarget::LoadedSkill(skill) = target else {
        return Ok(None);
    };
    let mut found: Option<(&StepReplayCapsule, CapturedCallable)> = None;
    for capsule in capsules {
        let preferred = found
            .as_ref()
            .is_some_and(|(held, _)| capture_order(held) >= capture_order(capsule));
        if capsule.host != CapsuleHost::EngineStep || preferred {
            continue;
        }
        let Some(bytes) = capsule_context_body(vault, txn, capsule)? else {
            continue;
        };
        let Some(context) = StepReplayContext::decode(&bytes) else {
            continue;
        };
        if context.run != capsule.run || context.step != capsule.step {
            continue;
        }
        let called = context
            .callables
            .into_iter()
            .find(|callable| callable.selected.entity == skill);
        if let Some(callable) = called {
            found = Some((capsule, callable));
        }
    }
    Ok(found.map(|(caller, callable)| CallableTarget {
        next: capsules
            .iter()
            .find(|next| {
                next.lease_generation == caller.lease_generation
                    && next.run == caller.run
                    && next.step == caller.step.saturating_add(1)
            })
            .cloned(),
        caller: caller.clone(),
        seq: callable.seq,
        revision: callable.selected.revision,
    }))
}

/// Which of two captured steps a check prefers: the later lease generation,
/// then the earlier step.
fn capture_order(capsule: &StepReplayCapsule) -> (u32, Reverse<u64>) {
    (capsule.lease_generation, Reverse(capsule.step))
}

impl Runner<'_> {
    /// A callable pair's inputs (FIX 3608), settled before either fork is
    /// paid for: the next step's capsule and rung, the two requests its
    /// caller's branches rebuilt, and the anchor. The target's current
    /// record must be at the revision the call loaded, as an exposure's
    /// must be at the revision the step saw.
    pub(crate) fn prepare_callable(
        &self,
        rows: &ForkRows,
        target: CallableTarget,
    ) -> Outcome<Prepared> {
        let Some(next) = target.next else {
            return Ok(Err(Unavailable::NoCapsule));
        };
        // An erased capsule's content went with its actor (FIX 6144).
        if next.content.actor().is_none() || target.caller.content.actor().is_none() {
            return Ok(Err(Unavailable::Unreadable));
        }
        let Some(binding) = next.binding.clone() else {
            return Ok(Err(Unavailable::CapsuleNotFinalized));
        };
        let current = self
            .vault
            .get_skill_record(&self.candidate.target.removed())?
            .map(|record| format!("{}@{}", record.skill_id, record.version));
        if current.as_deref() != Some(target.revision.as_str()) {
            return Ok(Err(Unavailable::SkillRevisionMoved));
        }
        let Some(captured) = capsule_request(self.vault, &next)? else {
            return Ok(Err(
                if matches!(&next.request, CapsuleRequest::Kept { erased: true, .. }) {
                    Unavailable::Erased
                } else {
                    Unavailable::Unreadable
                },
            ));
        };
        // Only a console the next request showed whole has a slot to
        // render each branch's observation into.
        let caller_step = target.caller.step;
        let Some(console) = next.console.clone().filter(|slot| slot.step == caller_step) else {
            let unshown = ShadowUnavailable::new(Reason::CapturedOutcomeMissing, "console_slot");
            return Ok(Err(Unavailable::ProgramReplay(unshown)));
        };
        let Some(shown) = console.locate(&captured).map(str::to_owned) else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let anchor = match self.scorer.resolve(self.vault, self.candidate)? {
            Ok(anchor) => anchor,
            Err(reason) => return Ok(Err(reason)),
        };
        // Both branches run in this pass, or neither does.
        if !self.clock.decision_may_start() {
            return Ok(Err(Unavailable::Unfinished));
        }
        let observations = match self.branch_observations(&target.caller, target.seq)? {
            Ok(observations) => observations,
            Err(unavailable) => return Ok(Err(Unavailable::ProgramReplay(unavailable))),
        };
        let [with_console, without_console] = observations.map(|observation| {
            let turn = CodeRunHistoryTurn {
                code: String::new(),
                console: observation,
            };
            turn.user_console(caller_step)
        });
        // The branch with the load is the step as it ran: it renders the
        // console the next request showed, or the branches are no pair.
        if with_console != shown {
            let diverged = ShadowUnavailable::new(Reason::BridgeReplayMismatch, "observation");
            return Ok(Err(Unavailable::ProgramReplay(diverged)));
        }
        let Some(without_skill) = with_console_text(&captured, &console, without_console) else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let with_skill = captured;
        let anchor_scoring = ForkScoringIdentity::of(&anchor)?;
        let anchor_hash = anchor_hash(self.candidate, &anchor_scoring)?;
        if [&rows.with_skill, &rows.without_skill]
            .into_iter()
            .flatten()
            .any(|fork| fork.anchor != anchor_hash || fork.capsule_request != next.request_hash)
        {
            return Ok(Err(Unavailable::ForksDiverged));
        }
        // The branch without the load has no recorded world past its step:
        // no fork's program runs, and the pair is scored in the `Text` mode.
        let unrecorded =
            ShadowUnavailable::new(Reason::WholeRunUnsupported, "callable_counterfactual");
        Ok(Ok(Prepared {
            with_skill_hash: request_hash(&with_skill)?,
            without_skill_hash: request_hash(&without_skill)?,
            exposure_revision: target.revision,
            capsule: next,
            binding,
            with_skill,
            without_skill,
            anchor,
            anchor_scoring,
            anchor_hash,
            frozen_program: Some(Err(unrecorded)),
        }))
    }

    /// The observation of `caller`'s step in each branch, the load called
    /// at bridge position `seq` present, then absent: the caller's own
    /// recorded program run again in two scratch arms under the host's one
    /// pin, each to its step's end with its run going on. Only a callable
    /// of the first-party tier runs in an arm.
    fn branch_observations(&self, caller: &StepReplayCapsule, seq: u64) -> Ran<[String; 2]> {
        let step = match prepare_shadow_step_source(self.vault, caller)? {
            Ok(step) => step,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        match step.callable_at(seq) {
            None => {
                return Ok(Err(ShadowUnavailable::new(
                    Reason::SourceMissing,
                    "callable",
                )));
            }
            Some(callable) if !callable.selected.first_party => {
                let tier = ShadowUnavailable::new(Reason::SandboxUnavailable, "callable_tier");
                return Ok(Err(tier));
            }
            Some(_) => {}
        }
        let program = match caller_program(self.vault, &step)? {
            Ok(program) => program,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        let mut programs = Vec::with_capacity(step.callables().len());
        for callable in step.callables() {
            programs.push((callable.seq, callable_source(self.vault, callable)?));
        }
        if !programs
            .iter()
            .any(|(at, source)| *at == seq && source.is_some())
        {
            let unread = ShadowUnavailable::new(Reason::SourceMissing, "callable_program");
            return Ok(Err(unread));
        }
        let runtime = match self.program.runtime_pin()? {
            Ok(runtime) => runtime,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        let mut observations = [String::new(), String::new()];
        let loads = [ArmCallableLoad::Present, ArmCallableLoad::Absent];
        for (observation, load) in observations.iter_mut().zip(loads) {
            let branch = CallableBranch {
                program: program.clone(),
                callables: ArmCallables {
                    treated: seq,
                    load,
                    programs: programs.clone(),
                },
            };
            match branch_observation(self.program, &step, &branch, runtime)? {
                Ok(observed) => *observation = observed,
                Err(unavailable) => return Ok(Err(unavailable)),
            }
        }
        Ok(Ok(observations))
    }
}

/// `branch`'s observation of `step`, run by `program` on the component
/// pinned at `runtime`: its step must end with its run going on, as the
/// caller's live step did, for a next request to exist.
fn branch_observation(
    program: &dyn ContributionForkProgram,
    step: &PreparedShadowStep,
    branch: &CallableBranch,
    runtime: [u8; 32],
) -> Ran<String> {
    let executed = match program.execute_branch(step, branch)? {
        Ok(executed) => executed,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    if executed.runtime != runtime {
        let drift = ShadowUnavailable::new(Reason::ArtifactDigestMismatch, "runtime");
        return Ok(Err(drift));
    }
    if executed.status != (ExecutedStepStatus::StepComplete { done: false }) {
        let ended = ShadowUnavailable::new(Reason::WholeRunUnsupported, "branch_ended");
        return Ok(Err(ended));
    }
    let path = observation_output_path(step.step().step);
    let observation = executed
        .outputs
        .into_iter()
        .find(|(body, _)| body.path == path)
        .map(|(_, bytes)| String::from_utf8(bytes));
    Ok(match observation {
        Some(Ok(text)) => Ok(text),
        Some(Err(_)) => Err(ShadowUnavailable::new(
            Reason::SourceDigestMismatch,
            "observation",
        )),
        None => Err(ShadowUnavailable::new(Reason::SourceMissing, "observation")),
    })
}

/// The program `step`'s run recorded for the step, as it ran: its body,
/// read while it is clean.
fn caller_program(vault: &Vault, step: &PreparedShadowStep) -> Ran<String> {
    let unavailable = |reason| Ok(Err(ShadowUnavailable::new(reason, "caller_program")));
    let path = script_output_path(step.step().step);
    let Some(output) = step
        .window
        .outputs
        .iter()
        .find(|output| output.path == path)
    else {
        return unavailable(Reason::SourceMissing);
    };
    let run = Some(step.step().run);
    if vault
        .code_run_raw_output_taint_state(run, output)?
        .is_tainted()
    {
        return unavailable(Reason::SourceWithheld);
    }
    let Some(bytes) = vault.get_code_run_raw_output(output)? else {
        return unavailable(Reason::SourceMissing);
    };
    match String::from_utf8(bytes) {
        Ok(program) => Ok(Ok(program)),
        Err(_) => unavailable(Reason::SourceDigestMismatch),
    }
}

/// `callable`'s stored file as its load read it: its entity's record at the
/// revision it loaded at, and its runtime package's file at the path its
/// call contract names, while its bytes still hash as they did. `None` for
/// a callable of another tier than the first-party one, which no arm runs,
/// and for one whose file does not read so now.
fn callable_source(vault: &Vault, callable: &CapturedCallable) -> Result<Option<String>> {
    let selected = &callable.selected;
    if !selected.first_party {
        return Ok(None);
    }
    let txn = vault.store.env.read_txn()?;
    let Some(record) = vault.get_skill_record_in_txn(&txn, &selected.entity)? else {
        return Ok(None);
    };
    if format!("{}@{}", record.skill_id, record.version) != selected.revision {
        return Ok(None);
    }
    // A package that does not read as the admitted skill's holds no file of
    // its load.
    let Ok(Some(package)) = vault.runtime_skill_package_in_txn(&txn, &selected.entity, &record)
    else {
        return Ok(None);
    };
    Ok(package
        .files
        .into_iter()
        .find(|file| {
            file.path == selected.reference
                && *blake3::hash(&file.content).as_bytes() == selected.source_hash
        })
        .and_then(|file| String::from_utf8(file.content).ok()))
}

/// `request` with the text of `console`'s part replaced by `text`, and
/// nothing else changed; `None` when that part is not text.
fn with_console_text(
    request: &LlmRequest,
    console: &ConsoleSlot,
    text: String,
) -> Option<LlmRequest> {
    let mut rebuilt = request.clone();
    let message = rebuilt
        .messages
        .get_mut(usize::try_from(console.message).ok()?)?;
    let ContentPart::Text { text: shown } = message
        .content
        .get_mut(usize::try_from(console.part).ok()?)?
    else {
        return None;
    };
    *shown = text;
    Some(rebuilt)
}
