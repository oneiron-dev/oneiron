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
//! A skill body a call's answer delivered to the run's program after its
//! first step (FIX 3608, `vault.skills.get`'s answer) is judged the same
//! way, by the step that made the call: the earliest delivery of the
//! skill's current revision its step's replay context kept, unless a call
//! of its load came first. With the body present, the call answers as its
//! row recorded it. With the body absent, it answers the verb's own
//! not-found refusal, and the caller's program runs its own fallback. A call
//! with no not-found answer of its own (a library page, an archive, a
//! restore, the leader's pattern load) is unavailable.
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
//! The console is the only message the request builder keeps a witness
//! for, and it keeps none in a request that lists the run's results in a
//! brief. So the rest of the next request stays as captured only when no
//! recorded call that the branch without the load never made has an answer
//! that request shows outside the console (FIX 3608). Those calls are the
//! load's own call and its subtree, and the calls past the point where that
//! branch ended its step. A fold verb's change to the run's fold ledger, a
//! board frame a verb's answer carried, and an answer kept as a bound
//! result of the run make the pair unavailable. The recorded kind of each
//! call decides, never its bytes.
//!
//! Two more records make the pair unavailable (FIX 3608). A result name
//! the caller's step bound or rebound, by a store, a spilled reply or a
//! stored reply, stays bound in the run, and the branch without the load
//! may never have bound it. A call in the load's subtree that may change
//! state leaves that state changed for the step's later calls, whose
//! recorded answers a branch reads as they were: nothing recomputes them
//! without the load.
//!
//! A branch the recorded calls do not answer, a callable whose stored file
//! does not read again as it loaded, a branch that ends its run, a next
//! request that shows the console otherwise, a call left out whose answer
//! that request shows elsewhere, a step that bound a result and a subtree
//! that may change state are unavailable for the shadow runner's own
//! reason ([`Unavailable::ProgramReplay`]), never a loss.

use std::cmp::Reverse;
use std::ops::Range;
use std::sync::Arc;

use super::super::{
    ContributionForkProgram, ContributionReplayUnavailable as Unavailable, ForkRows,
    ForkScoringIdentity, Outcome, Prepared, Runner, anchor_hash, request_hash,
};
use super::{ExecutedFork, ExecutedStepStatus, Ran, executed_run};
use crate::code_run::shadow_runner::{
    ArmCallableLoad, ArmCallables, ArmTreatedCall, PreparedShadowStep, ShadowBodyStore,
    ShadowUnavailable, ShadowUnavailableReason as Reason, absent_delivery_outcome,
    prepare_shadow_step_source,
};
use crate::code_run::{
    CapsuleHost, CapsuleRequest, CapturedCallable, CodeRunBridgeCall, CodeRunHistoryTurn,
    ConsoleSlot, SelfEffect, StepReplayCapsule, StepReplayContext, agent_verb_observations_of,
    capsule_context_body, capsule_request, recorded_verb_call,
};
use crate::engine_executor::continuation::continuation_tail_effect;
use crate::engine_executor::{
    ArmTypeFeedback, JsCodeModeRuntime, StepCancellation, bridge_result_output_path,
    observation_output_path, run_shadow_callable_branch, script_output_path,
};
use crate::skill_attribution::ContributionTarget;
use crate::task_verb::sdk::AgentVerb;
use crate::{ContentPart, EntityId, LlmRequest, Result, Vault};

/// One branch of a callable's or a delivery's counterfactual (FIX 3608), as
/// the host's program run takes it: the caller step's own recorded program,
/// and how the branch treats the step's recorded callables and the call it
/// treats.
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

/// The steps a callable's or a delivery's check regenerates from (FIX
/// 3608): the caller's step that made the call the pair treats, the bridge
/// position of that call, what it is (a call of the target's load, or a call
/// whose answer delivered the target's body), the revision it loaded or
/// delivered, and the next step, whose request each branch rebuilds; `None`
/// when that step was not captured.
pub(crate) struct CallerTarget {
    pub(crate) caller: StepReplayCapsule,
    pub(crate) seq: u64,
    pub(crate) kind: ArmTreatedCall,
    pub(crate) revision: String,
    pub(crate) next: Option<StepReplayCapsule>,
}

/// The call `target`'s check regenerates from among `capsules`, one run's
/// captured steps, read in `txn`: for a loaded skill, in the earliest step
/// of the latest lease generation with one, the step's first call that
/// either called the skill's load, as its replay context froze it, or
/// delivered the skill's body at its current revision to the step's
/// program, as its replay context kept it. `None` for a used edge, and when
/// no context holds either.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn caller_target_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    capsules: &[StepReplayCapsule],
    target: ContributionTarget,
) -> Result<Option<CallerTarget>> {
    let ContributionTarget::LoadedSkill(skill) = target else {
        return Ok(None);
    };
    // A delivery is of the skill's own version, the one its check judges.
    let current = vault
        .get_skill_record_in_txn(txn, &skill)?
        .map(|record| format!("{}@{}", record.skill_id, record.version));
    let mut found: Option<(&StepReplayCapsule, (u64, ArmTreatedCall, String))> = None;
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
        if let Some(first) = first_treated_call(context, skill, current.as_deref()) {
            found = Some((capsule, first));
        }
    }
    Ok(found.map(|(caller, (seq, kind, revision))| CallerTarget {
        next: capsules
            .iter()
            .find(|next| {
                next.lease_generation == caller.lease_generation
                    && next.run == caller.run
                    && next.step == caller.step.saturating_add(1)
            })
            .cloned(),
        caller: caller.clone(),
        seq,
        kind,
        revision,
    }))
}

/// The first call of `context`'s step that called `skill`'s load, or that
/// delivered its body at `revision`, the skill's current one (FIX 3608): its
/// bridge position, its kind and the revision it loaded or delivered.
fn first_treated_call(
    context: StepReplayContext,
    skill: EntityId,
    revision: Option<&str>,
) -> Option<(u64, ArmTreatedCall, String)> {
    let called = context
        .callables
        .into_iter()
        .find(|callable| callable.selected.entity == skill)
        .map(|callable| {
            let revision = callable.selected.revision;
            (callable.seq, ArmTreatedCall::Callable, revision)
        });
    let delivered = context
        .deliveries
        .into_iter()
        .find(|delivery| {
            delivery.body.entity == skill && revision == Some(delivery.body.revision.as_str())
        })
        .map(|delivery| {
            let revision = delivery.body.revision;
            (delivery.seq, ArmTreatedCall::Delivery, revision)
        });
    called
        .into_iter()
        .chain(delivered)
        .min_by_key(|(seq, ..)| *seq)
}

/// Which of two captured steps a check prefers: the later lease generation,
/// then the earlier step.
fn capture_order(capsule: &StepReplayCapsule) -> (u32, Reverse<u64>) {
    (capsule.lease_generation, Reverse(capsule.step))
}

impl Runner<'_> {
    /// A callable's or a delivery's pair inputs (FIX 3608), settled before
    /// either fork is paid for: the next step's capsule and rung, the two
    /// requests its caller's branches rebuilt, and the anchor. The target's
    /// current record must be at the revision the call loaded or delivered,
    /// as an exposure's must be at the revision the step saw.
    pub(crate) fn prepare_caller(
        &self,
        rows: &ForkRows,
        target: CallerTarget,
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
        let observations =
            match self.branch_observations(&target.caller, target.seq, target.kind)? {
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
        // The branch without the load or body has no recorded world past
        // its step: no fork's program runs, and the pair is scored in the
        // `Text` mode.
        let counterfactual = match target.kind {
            ArmTreatedCall::Callable => "callable_counterfactual",
            ArmTreatedCall::Delivery => "delivery_counterfactual",
        };
        let unrecorded = ShadowUnavailable::new(Reason::WholeRunUnsupported, counterfactual);
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

    /// The observation of `caller`'s step in each branch, the load called,
    /// or the body delivered, at bridge position `seq` (as `kind` says)
    /// present, then absent: the caller's own recorded program run again in
    /// two scratch arms under the host's one pin, each to its step's end
    /// with its run going on. Only a callable of the first-party tier runs in
    /// an arm, and only a delivery whose call answers a missing skill of its
    /// own ([`undeliverable`]) is left out. The branch without the load or
    /// body must leave out no recorded call whose answer the next request
    /// shows outside the console, and no call that may change state; the
    /// step must bind no result (FIX 3608, [`removed_unrebuilt`]).
    fn branch_observations(
        &self,
        caller: &StepReplayCapsule,
        seq: u64,
        kind: ArmTreatedCall,
    ) -> Ran<[String; 2]> {
        let step = match prepare_shadow_step_source(self.vault, caller)? {
            Ok(step) => step,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        let nested_end = match kind {
            ArmTreatedCall::Callable => match step.callable_at(seq) {
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
                Some(callable) => callable.nested_end,
            },
            ArmTreatedCall::Delivery => {
                let skill = self.candidate.target.removed();
                if let Some(unavailable) = undeliverable(&step, seq, skill) {
                    return Ok(Err(unavailable));
                }
                seq.saturating_add(1)
            }
        };
        // The load's own call and its subtree never happen without it; a
        // delivery's call answers otherwise.
        if let Some(cause) = removed_unrebuilt(&step, seq, nested_end, kind) {
            let shown = ShadowUnavailable::new(Reason::CapturedOutcomeMissing, cause);
            return Ok(Err(shown));
        }
        let program = match caller_program(self.vault, &step)? {
            Ok(program) => program,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        let mut programs = Vec::with_capacity(step.callables().len());
        for callable in step.callables() {
            programs.push((callable.seq, callable_source(self.vault, callable)?));
        }
        if kind == ArmTreatedCall::Callable
            && !programs
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
        let mut matched = [0_u64; 2];
        let loads = [ArmCallableLoad::Present, ArmCallableLoad::Absent];
        let branches = observations.iter_mut().zip(matched.iter_mut()).zip(loads);
        for ((observation, position), load) in branches {
            let branch = CallableBranch {
                program: program.clone(),
                callables: ArmCallables {
                    treated: seq,
                    kind,
                    load,
                    programs: programs.clone(),
                },
            };
            match branch_observation(self.program, &step, &branch, runtime)? {
                Ok((observed, consumed)) => {
                    *observation = observed;
                    *position = consumed;
                }
                Err(unavailable) => return Ok(Err(unavailable)),
            }
        }
        // The caller's fallback may end its step before the calls the live
        // continuation made after the load's: those never happen either.
        let [_, without_matched] = matched;
        let (_, bridge_end) = step.bridge_window();
        if let Some(cause) = shown_outside_console(&step, without_matched..bridge_end) {
            let shown = ShadowUnavailable::new(Reason::CapturedOutcomeMissing, cause);
            return Ok(Err(shown));
        }
        Ok(Ok(observations))
    }
}

/// Why the branch without the load or body treated at bridge position
/// `seq` of `step`, its subtree to `nested_end`, is no counterfactual the
/// next request can be rebuilt for (FIX 3608), as the cause the pair is
/// unavailable for; `None` when nothing in the step's record says so:
///
/// - an answer of the treated call or its subtree that the next request
///   shows outside the console ([`shown_outside_console`]);
/// - a call in a callable's subtree that may change state
///   (`subtree_effect`), or a delivery's call that may (`delivery_effect`),
///   by its recorded kind, as a continuation's tail is judged
///   ([`continuation_tail_effect`]): a later recorded read of the step
///   answers as it read after the change, which that branch never made;
/// - a result name the step bound or rebound (`bound_result`,
///   [`step_bound_result`]).
fn removed_unrebuilt(
    step: &PreparedShadowStep,
    seq: u64,
    nested_end: u64,
    kind: ArmTreatedCall,
) -> Option<&'static str> {
    if let Some(cause) = shown_outside_console(step, seq..nested_end) {
        return Some(cause);
    }
    // A callable's own call is the one the pair treats: its subtree follows.
    // A delivery's call is all the branch answers otherwise.
    let (first, effect) = match kind {
        ArmTreatedCall::Callable => (seq.saturating_add(1), "subtree_effect"),
        ArmTreatedCall::Delivery => (seq, "delivery_effect"),
    };
    let Some(removed) = recorded_calls(step, first..nested_end) else {
        return Some("bridge_window");
    };
    if removed.iter().any(continuation_tail_effect) {
        return Some(effect);
    }
    step_bound_result(step).then_some("bound_result")
}

/// Why the call at bridge position `seq` of `step` is no delivery a branch
/// can leave `skill`'s body out of (FIX 3608): the step's replay context
/// kept no delivery of that body there (`skill_delivery`), or the call has
/// no not-found answer of its own for the live host to give
/// (`delivery_absence`, [`absent_delivery_outcome`]). `None` when it is one.
fn undeliverable(
    step: &PreparedShadowStep,
    seq: u64,
    skill: EntityId,
) -> Option<ShadowUnavailable> {
    if !step.delivered_at(seq, skill) {
        return Some(ShadowUnavailable::new(
            Reason::SourceMissing,
            "skill_delivery",
        ));
    }
    let verb = recorded_calls(step, seq..seq.saturating_add(1))
        .and_then(<[CodeRunBridgeCall]>::first)
        .and_then(recorded_verb_call)
        .and_then(|(verb, _)| AgentVerb::from_name(verb));
    absent_delivery_outcome(verb)
        .is_none()
        .then(|| ShadowUnavailable::new(Reason::WholeRunUnsupported, "delivery_absence"))
}

/// Whether `step`'s record binds a result name at the step's end that the
/// run did not bind, as is, when the step started (FIX 3608): a name a
/// store, a spilled reply or a stored reply bound, or a name rebound to
/// another result. The name the host binds to the step's own observation
/// is left out, since each branch's console stands in for it. A record
/// that holds later steps counts their names too, which leaves the pair
/// unavailable, never wrong.
fn step_bound_result(step: &PreparedShadowStep) -> bool {
    let observation = observation_output_path(step.step().step);
    step.window
        .bindings
        .iter()
        .any(|binding| binding.path != observation && !step.prefix.bindings.contains(binding))
}

/// The recorded calls of `step` at the bridge positions in `rows`; `None`
/// when the step's record does not hold them.
fn recorded_calls(step: &PreparedShadowStep, rows: Range<u64>) -> Option<&[CodeRunBridgeCall]> {
    let start = usize::try_from(rows.start).ok()?;
    let end = usize::try_from(rows.end).ok()?;
    step.window.bridge_calls.get(start..end)
}

/// What the next request shows, outside the caller's console, of an answer
/// of a recorded call of `step` at a bridge position in `rows` (FIX 3608),
/// as the cause the pair is unavailable for. The branch without the load
/// never makes those calls. The request builder keeps a witness of where it
/// put the console only, so a message it built from any other answer of
/// theirs is not rebuilt. Each call's recorded kind decides:
///
/// - a fold verb's call (`fold_ledger`): a change to the run's fold ledger
///   reshapes the turns before the console;
/// - a verb's answer that carried a board frame (`board_frames`): the
///   step's frames message beside its console shows it;
/// - an answer kept as a bound result of the run, a reply spilled as a body
///   or a stored typed reply (`bound_result`): the run keeps it bound, and
///   the branch without the load never bound it.
///
/// `bridge_window` when the step's record does not hold `rows`; `None` when
/// no call there has an answer of those kinds.
fn shown_outside_console(step: &PreparedShadowStep, rows: Range<u64>) -> Option<&'static str> {
    let window = &step.window;
    let Some(calls) = recorded_calls(step, rows) else {
        return Some("bridge_window");
    };
    if calls.iter().any(|call| call.effect == SelfEffect::Fold) {
        return Some("fold_ledger");
    }
    if !agent_verb_observations_of(calls).is_empty() {
        return Some("board_frames");
    }
    // A row is bound as the arm counts its spills: a stored reply the step
    // froze, or a body at its row's result path.
    let bound = |call: &CodeRunBridgeCall| {
        let spilled = bridge_result_output_path(call.seq);
        step.replies.iter().any(|reply| reply.seq == call.seq)
            || window.outputs.iter().any(|output| output.path == spilled)
    };
    calls.iter().any(bound).then_some("bound_result")
}

/// `branch`'s observation of `step`, run by `program` on the component
/// pinned at `runtime`, and the bridge position it matched the step's
/// recorded calls to: its step must end with its run going on, as the
/// caller's live step did, for a next request to exist.
fn branch_observation(
    program: &dyn ContributionForkProgram,
    step: &PreparedShadowStep,
    branch: &CallableBranch,
    runtime: [u8; 32],
) -> Ran<(String, u64)> {
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
    let consumed = executed.consumed;
    let observation = executed
        .outputs
        .into_iter()
        .find(|(body, _)| body.path == path)
        .map(|(_, bytes)| String::from_utf8(bytes));
    Ok(match observation {
        Some(Ok(text)) => Ok((text, consumed)),
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
