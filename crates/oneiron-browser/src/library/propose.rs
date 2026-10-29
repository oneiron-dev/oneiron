//! A proposal's checks (pure move out of `library`): the proposal and
//! proof shapes, the solved-page check on the proposing session, and the
//! no-model replay on a fresh guest that files the program.

use super::live_run;
use super::{
    AdmissionRefusal, Admitted, ReplayGuest, SupersedeOutcome, SupersedeRefusal, WorkflowSeed,
    secret_slots, validate_replay_args,
};
#[cfg(feature = "driver")]
use super::{by_locator, hidden_look, missed};
#[cfg(feature = "driver")]
use crate::{
    BatchInput, BrowserDriver, CheckReceipt, NoWriter, RoutineDecider, SubgoalStatus, SwitchStage,
};
use crate::{BatchOutput, BatchStep, BrowserError, EffectReceipt, ExpectInput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::program::{WorkflowLibrary, WorkflowProgram};

/// Offers a solved run's program to the library. `args` are the values the
/// solved run used: the host checks the page now with them, then replays
/// the program once with no model on a fresh guest, with `replay_args`
/// where the proposal gives them, else with `args` again. A proposal names
/// its program whole, or a site skill's seed by `candidate` (CUA E10).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposeInput {
    #[serde(default)]
    pub subgoal: String,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub steps: Vec<BatchStep>,
    #[serde(default)]
    pub postcondition: Vec<ExpectInput>,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    /// Values held out from `args` for the replay: the same names, at least
    /// one slot the steps or the postcondition use taking another value.
    /// None replays with `args`, and the program is filed as holding none
    /// out.
    #[serde(default)]
    pub replay_args: BTreeMap<String, String>,
    /// The program this one repairs, by the `workflow` ref its card names:
    /// one filed for the same site, live or retired. Once this one is
    /// filed, a live one retires `superseded:<this one's ref>`.
    #[serde(default)]
    pub supersedes: Option<String>,
    /// Where the program came from, when a hub pack seeded it: provenance
    /// only, which grants nothing.
    #[serde(default)]
    pub seed: Option<WorkflowSeed>,
    /// A seed candidate `library.find` or an `open` listed: the host
    /// resolves its exact bytes, whose program and provenance stand in for
    /// the proposal's own; `args`, `replay_args` and `supersedes` stay the
    /// caller's.
    #[serde(default)]
    pub candidate: Option<String>,
}

/// Which check refused a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCheck {
    /// The solved run's page does not meet the postcondition.
    Solved,
    /// The no-model replay did not finish, or did not meet it.
    Replay,
    /// The no-model replay missed while a one-time-code slot gave it the
    /// code the solved run entered, which that run may have spent (FIX
    /// 8028): held out with a fresh code's handle, it may pass.
    SecretReplay,
    /// The `replay_args` given hold nothing out.
    HeldOut,
    /// No fresh guest ran the replay.
    FreshGuest,
    /// The library refused the `supersedes` link.
    Supersedes,
}

/// An admission's answer: the program's ref once filed, or the check that
/// refused it and what it found. The replay comes whole, as it ran on the
/// fresh guest: that guest is gone, so no cursor pages it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProposeOutput {
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_by: Option<WorkflowCheck>,
    /// What the refusing check found, where `unmet` does not say it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<AdmissionRefusal>,
    /// The postcondition checks the page missed, by index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmet: Vec<usize>,
    /// Each check `unmet` names, with what its read found (FIX 8049): the
    /// observed row, the cut it read under, the rebindings it made.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missed: Vec<crate::CheckReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<BatchOutput>,
    /// The fresh guest the replay ran on, and what it took of this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_guest: Option<ReplayGuest>,
    /// What became of the program `supersedes` named, once this one filed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded: Option<SupersedeOutcome>,
}

/// The two checks' evidence, kept with an admitted program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowProof {
    /// The arguments the solved run used, its secret slots' left out.
    pub args: BTreeMap<String, String>,
    /// The values held out from `args` that the replay used, its secret
    /// slots' left out; empty when it replayed with `args`.
    pub replay_args: BTreeMap<String, String>,
    /// Whether the replay ran with values held out from the solved run's.
    pub held_out: bool,
    /// Where the program came from, when a hub pack seeded it.
    pub seed: Option<WorkflowSeed>,
    /// The page the solved run ended on, which met the postcondition.
    pub solved_url: String,
    pub solved_title: String,
    /// The no-model replay's effect receipts and routine decisions, each
    /// handle a row showed there kept as `[secret]`.
    pub replay_receipts: Vec<EffectReceipt>,
    pub replay_decisions: Vec<serde_json::Value>,
    /// The page the replay ended on, which met the postcondition again.
    pub replay_url: String,
    /// The fresh guest the replay ran on.
    pub replay_guest: ReplayGuest,
}

#[cfg(feature = "driver")]
/// A proposal its solved page met, ready to replay on a fresh guest: the
/// program and its site, the replay's own steps and checks filled from its
/// values, and what the proof and the library keep of the proposal.
pub(crate) struct Solved {
    site: String,
    program: WorkflowProgram,
    steps: Vec<BatchStep>,
    checks: Vec<ExpectInput>,
    args: BTreeMap<String, String>,
    replay_args: BTreeMap<String, String>,
    held_out: bool,
    seed: Option<WorkflowSeed>,
    supersedes: Option<String>,
    solved_url: String,
    solved_title: String,
}

#[cfg(feature = "driver")]
impl Solved {
    /// The program's site and the `supersedes` link the proposal names,
    /// for the link's read before the replay (FIX 7876).
    pub(crate) fn link(&self) -> Option<(&str, &str)> {
        Some((&self.site, self.supersedes.as_deref()?))
    }
}

#[cfg(feature = "driver")]
/// A refusal by `check`, with what it found.
fn refused(check: WorkflowCheck, refusal: Option<AdmissionRefusal>) -> ProposeOutput {
    ProposeOutput {
        admitted: false,
        workflow: None,
        refused_by: Some(check),
        refusal,
        unmet: Vec::new(),
        missed: Vec::new(),
        replay: None,
        replay_guest: None,
        superseded: None,
    }
}

/// A proposal refused before its replay because the library refuses its
/// `supersedes` link to `workflow` (FIX 7876).
#[cfg(feature = "driver")]
pub(crate) fn supersedes_refused(workflow: String, why: SupersedeRefusal) -> ProposeOutput {
    let refusal = AdmissionRefusal::Supersedes { workflow, why };
    refused(WorkflowCheck::Supersedes, Some(refusal))
}

#[cfg(feature = "driver")]
/// Checks missed, split into their indexes and their receipts.
fn split_missed(missed: Vec<(usize, CheckReceipt)>) -> (Vec<usize>, Vec<CheckReceipt>) {
    missed.into_iter().unzip()
}

#[cfg(feature = "driver")]
/// A proposal's first check, on the proposing session's own page: the live
/// handles it names put back to their locators, its secrets put in slots,
/// its shape and its held-out values checked, then the solved page read
/// against the postcondition filled from `args`. A refusal is the
/// proposal's answer.
pub(crate) fn check_solved<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    input: ProposeInput,
) -> Result<Result<Solved, ProposeOutput>, BrowserError> {
    let (mut steps, mut postcondition) = (input.steps, input.postcondition);
    let (mut args, mut replay_args) = (input.args, input.replay_args);
    // What the steps' targets held, read before handles go back to locators.
    let targets = secret_slots::Targets::read(&*driver, &steps, &postcondition);
    by_locator(&*driver, &mut steps, &mut postcondition);
    // The independent check: the host reads the solved run's page itself.
    let solved = driver.observe(hidden_look())?;
    let mut program = WorkflowProgram {
        subgoal: input.subgoal,
        params: input.params,
        secret_params: Vec::new(),
        steps,
        postcondition,
    };
    targets.slot(
        &*driver,
        &solved.rows,
        &mut program,
        &mut args,
        &mut replay_args,
    )?;
    let site = program.site()?;
    let (_, solved_checks) = program.fill(&args)?;
    let held_out = match validate_replay_args(&program, &args, &replay_args) {
        Ok(held_out) => held_out,
        Err(refusal) => return Ok(Err(refused(WorkflowCheck::HeldOut, Some(refusal)))),
    };
    // The replay fills its steps and its checks from its own values.
    let values = if held_out { &replay_args } else { &args };
    let (steps, checks) = program.fill(values)?;
    let missed = missed(driver, &solved_checks)?;
    if !missed.is_empty() {
        let (unmet, missed) = split_missed(missed);
        return Ok(Err(ProposeOutput {
            unmet,
            missed,
            ..refused(WorkflowCheck::Solved, None)
        }));
    }
    Ok(Ok(Solved {
        site,
        program,
        steps,
        checks,
        args,
        replay_args,
        held_out,
        seed: input.seed,
        supersedes: input.supersedes,
        solved_url: solved.url,
        solved_title: solved.title,
    }))
}

#[cfg(feature = "driver")]
/// A proposal's answer when no fresh guest ran its replay: the host gives
/// none, or one did not start or take the carried cookies, at `stage`.
pub(crate) fn no_fresh_guest(stage: SwitchStage, error: &BrowserError) -> ProposeOutput {
    let refusal = AdmissionRefusal::FreshGuest {
        stage,
        code: error.code().to_owned(),
        detail: error.to_string(),
    };
    refused(WorkflowCheck::FreshGuest, Some(refusal))
}

#[cfg(feature = "driver")]
/// A proposal's second check, on the fresh guest the host started for it
/// (`fresh`, as `guest` records it): the no-model replay with its own
/// values, and its own checks read on that guest's page. Then the library
/// files the program, as the successor of the program its `supersedes`
/// names.
pub(crate) fn replay_and_file<D: BrowserDriver + ?Sized>(
    fresh: &mut D,
    decider: &mut dyn RoutineDecider,
    library: &mut dyn WorkflowLibrary,
    solved: Solved,
    guest: ReplayGuest,
) -> Result<ProposeOutput, BrowserError> {
    let Solved {
        site,
        program,
        steps,
        checks,
        args,
        replay_args,
        held_out,
        seed,
        supersedes,
        solved_url,
        solved_title,
    } = solved;
    let step_count = steps.len();
    let mut replay = fresh.batch_with(
        BatchInput {
            subgoal: Some(program.subgoal.clone()),
            steps,
            base: None,
            until_ms: None,
            no_model: true,
        },
        decider,
        // A replay asks no model, so a Fill's generation goes up unasked.
        &NoWriter,
    )?;
    // A replay that went up for no progress after its last step still
    // meets its checks, read now (FIX 8507).
    let at_end = live_run::no_progress_at_end(&replay, step_count);
    let missed = if replay.status == SubgoalStatus::Done || at_end {
        missed(fresh, &checks)?
    } else {
        Vec::new()
    };
    if at_end && missed.is_empty() {
        live_run::met_after_all(fresh, &mut replay);
    }
    if replay.status != SubgoalStatus::Done || !missed.is_empty() {
        let (check, refusal) = secret_slots::replay_check(&program, &args, &replay_args, held_out);
        let (unmet, missed) = split_missed(missed);
        return Ok(ProposeOutput {
            unmet,
            missed,
            replay: Some(replay),
            replay_guest: Some(guest),
            ..refused(check, refusal)
        });
    }
    let replayed = fresh.observe(hidden_look())?;
    let withheld = secret_slots::values(&program, &args, &replay_args);
    let (replay_receipts, replay_decisions) =
        secret_slots::unbound(replay.receipts.clone(), replay.decisions.clone(), &withheld);
    let proof = WorkflowProof {
        args: secret_slots::public(&program, args),
        replay_args: secret_slots::public(&program, replay_args),
        held_out,
        seed,
        solved_url,
        solved_title,
        replay_receipts,
        replay_decisions,
        replay_url: replayed.url,
        replay_guest: guest,
    };
    let output = match library.admit(&site, &program, &proof, supersedes.as_deref())? {
        Admitted::Filed {
            workflow,
            superseded,
        } => ProposeOutput {
            admitted: true,
            workflow: Some(workflow),
            refused_by: None,
            refusal: None,
            unmet: Vec::new(),
            missed: Vec::new(),
            replay: None,
            replay_guest: None,
            superseded,
        },
        Admitted::Refused(why) => {
            let workflow = supersedes.unwrap_or_default();
            let refusal = AdmissionRefusal::Supersedes { workflow, why };
            refused(WorkflowCheck::Supersedes, Some(refusal))
        }
    };
    Ok(ProposeOutput {
        replay: Some(replay),
        replay_guest: Some(proof.replay_guest),
        ..output
    })
}
