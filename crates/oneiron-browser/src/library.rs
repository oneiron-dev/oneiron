//! The replay library (OF-598; EIRI-ARCH-0002 "The replay library"): a
//! solved browser run, kept as a parameterised program for its site.
//!
//! A program joins the library only after two checks. First the host checks
//! that the run succeeded: the program's postcondition, read on the page
//! itself, never the program's own "done". Then the program replays once
//! with no model (a routine step takes only a rule's answer), on a fresh
//! guest the host starts for it and never on the solved run's page, and the
//! replay meets the postcondition again on that guest's page. A proposal
//! that gives held-out values (`replay_args`) replays with them, so the
//! program is shown to work past its solved run's values (`held_out`).
//! Repeated work on a site tries the library first: opening a page lists
//! the site's programs, each card with its lineage's recent outcomes. A
//! library run is live: every effect in it still crosses its gated door,
//! and a run that misses its postcondition goes back to the planner with
//! the checks it missed and the page it left. A program that stops working
//! leaves by retire, and a later solved run that passes both checks files
//! it afresh, or files its repair as its successor (`supersedes`), which
//! retires it in the same write.
//!
//! A program's `{{name}}` slots take the run's arguments as data, in the
//! batch's own fields; nothing is spliced into code.
//!
//! A program names elements by locator only, never by a live handle (a
//! handle names one node of one session's page). A proposal's handles the
//! session minted are put back to their rows' locators before the program
//! is checked; each step resolves its locators on the page as it runs.

mod admission;

pub use admission::{
    AdmissionRefusal, Admitted, RecentCounts, ReplayGuest, SupersedeOutcome, SupersedeRefusal,
    WorkflowSeed, validate_replay_args,
};

#[cfg(feature = "driver")]
use crate::{BatchInput, BrowserDriver, ObserveInput, RoutineDecider, SwitchStage};
use crate::{
    BatchOutput, BatchStep, BrowserError, EffectReceipt, ExpectInput, ObservationBase,
    SubgoalStatus, is_live_handle,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A parameterised program: one subgoal's batch on one site, its `{{name}}`
/// slots filled from a run's arguments, and the postcondition that says it
/// worked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowProgram {
    pub subgoal: String,
    /// The names the steps' and checks' `{{name}}` slots take.
    pub params: Vec<String>,
    /// The batch. Its first step opens the page that names its site.
    pub steps: Vec<BatchStep>,
    /// What the page shows when the program worked: every check must hold.
    pub postcondition: Vec<ExpectInput>,
}

/// Offers a solved run's program to the library. `args` are the values the
/// solved run used: the host checks the page now with them, then replays
/// the program once with no model on a fresh guest, with `replay_args`
/// where the proposal gives them, else with `args` again.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposeInput {
    pub subgoal: String,
    #[serde(default)]
    pub params: Vec<String>,
    pub steps: Vec<BatchStep>,
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
}

/// Which check refused a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCheck {
    /// The solved run's page does not meet the postcondition.
    Solved,
    /// The no-model replay did not finish, or did not meet it.
    Replay,
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
    /// The arguments the solved run used.
    pub args: BTreeMap<String, String>,
    /// The values held out from `args` that the replay used; empty when it
    /// replayed with `args`.
    pub replay_args: BTreeMap<String, String>,
    /// Whether the replay ran with values held out from the solved run's.
    pub held_out: bool,
    /// Where the program came from, when a hub pack seeded it.
    pub seed: Option<WorkflowSeed>,
    /// The page the solved run ended on, which met the postcondition.
    pub solved_url: String,
    pub solved_title: String,
    /// The no-model replay's effect receipts and routine decisions.
    pub replay_receipts: Vec<EffectReceipt>,
    pub replay_decisions: Vec<serde_json::Value>,
    /// The page the replay ended on, which met the postcondition again.
    pub replay_url: String,
    /// The fresh guest the replay ran on.
    pub replay_guest: ReplayGuest,
}

/// Lists the library's programs for a site: `site` (a host, as
/// `www.example.com`), or the open page's.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryFindInput {
    #[serde(default)]
    pub site: Option<String>,
    /// Words the program's subgoal holds, ignoring case.
    #[serde(default)]
    pub subgoal: Option<String>,
}

/// One library program as a planner reads it: its lifetime runs and
/// failures, its lineage's recent outcomes, how its admission proved it,
/// and where it came from.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LibraryCard {
    pub workflow: String,
    pub site: String,
    pub subgoal: String,
    pub params: Vec<String>,
    pub runs: u32,
    pub failures: u32,
    /// The newest outcomes of its lineage: its own, and those of the
    /// programs it supersedes.
    pub recent: RecentCounts,
    /// Whether its admission replayed with values held out from the solved
    /// run's; one that held none out was shown on those values only.
    pub held_out: bool,
    /// The program this one repaired, by its `workflow` ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<WorkflowSeed>,
    /// When it was filed, or last refiled, as the vault records time.
    pub filed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryFindOutput {
    pub site: String,
    pub workflows: Vec<LibraryCard>,
}

/// Runs a library program live with `args`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryRunInput {
    pub workflow: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    /// The observation the run's last observation edits, as `observe`'s
    /// `base`; by default the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
}

/// A library run: its batch, and the postcondition checks the page missed.
/// A miss sets `NEEDS_AGENT`: the run goes back to the planner.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryRunOutput {
    pub workflow: String,
    pub status: SubgoalStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmet: Vec<usize>,
    pub batch: BatchOutput,
}

/// Takes a program out of the library: no later `open` or `find` lists it,
/// and no run can start it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryRetireInput {
    pub workflow: String,
    /// Why it leaves; the library keeps it with the retire.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The program a retire took out, as its card read then.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryRetireOutput {
    pub retired: LibraryCard,
}

/// Lists the programs retires took out of the library for a site: `site`
/// (a host, as `www.example.com`), or the open page's.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryRetiredInput {
    #[serde(default)]
    pub site: Option<String>,
}

/// One retired program: the card it had when a retire took it out, when,
/// and why.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RetiredCard {
    pub card: LibraryCard,
    pub retired_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A site's retired programs, the newest retire first.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryRetiredOutput {
    pub site: String,
    pub retired: Vec<RetiredCard>,
}

/// Where library programs are kept: the engine's vault, behind the session.
pub trait WorkflowLibrary: Send {
    /// The programs filed for `site`, those whose subgoal holds `subgoal`.
    fn find(&mut self, site: &str, subgoal: Option<&str>)
    -> Result<Vec<LibraryCard>, BrowserError>;
    fn program(&mut self, workflow: &str) -> Result<Option<WorkflowProgram>, BrowserError>;
    /// Files a program both checks passed, as the successor of the program
    /// `supersedes` names when it names one: its ref and what became of
    /// that program, or the link's refusal, with nothing filed.
    fn admit(
        &mut self,
        site: &str,
        program: &WorkflowProgram,
        proof: &WorkflowProof,
        supersedes: Option<&str>,
    ) -> Result<Admitted, BrowserError>;
    /// Counts one library run, and whether it met its postcondition.
    fn record_run(&mut self, workflow: &str, met: bool) -> Result<(), BrowserError>;
    /// Takes a program out of the library for `reason`; `None` when none is
    /// filed under `workflow`.
    fn retire(
        &mut self,
        workflow: &str,
        reason: Option<&str>,
    ) -> Result<Option<LibraryCard>, BrowserError>;
    /// The programs retires took out for `site`, the newest first.
    fn retired(&mut self, _site: &str) -> Result<Vec<RetiredCard>, BrowserError> {
        Err(BrowserError::Library(
            "this library keeps no retired programs".to_owned(),
        ))
    }
}

impl BatchStep {
    /// Every element the step names, by handle or locator.
    fn targets(&self) -> Vec<&String> {
        match self {
            Self::Click { target } | Self::Type { target, .. } | Self::Select { target, .. } => {
                vec![target]
            }
            Self::WaitFor { targets, .. } => targets.iter().collect(),
            Self::Expect { target, .. }
            | Self::Key { target, .. }
            | Self::Scroll { target, .. } => target.iter().collect(),
            Self::Decide(step) => step.targets.iter().collect(),
            Self::Open { .. } | Self::Screenshot { .. } | Self::Hotkey { .. } => Vec::new(),
        }
    }

    /// The same, to put back to locators.
    #[cfg(feature = "driver")]
    fn targets_mut(&mut self) -> Vec<&mut String> {
        match self {
            Self::Click { target } | Self::Type { target, .. } | Self::Select { target, .. } => {
                vec![target]
            }
            Self::WaitFor { targets, .. } => targets.iter_mut().collect(),
            Self::Expect { target, .. }
            | Self::Key { target, .. }
            | Self::Scroll { target, .. } => target.iter_mut().collect(),
            Self::Decide(step) => step.targets.iter_mut().collect(),
            Self::Open { .. } | Self::Screenshot { .. } | Self::Hotkey { .. } => Vec::new(),
        }
    }
}

impl WorkflowProgram {
    /// The site the program runs on, once its shape holds: a subgoal,
    /// distinct named parameters, one or more steps opening with a page
    /// whose host takes no slot, one or more checks, and no live handle
    /// among the elements they name (a program names elements by locator).
    pub fn site(&self) -> Result<String, BrowserError> {
        let invalid = |why: &str| Err(BrowserError::Input(why.to_owned()));
        if self.subgoal.trim().is_empty() {
            return invalid("a program names its subgoal");
        }
        if self.params.iter().any(|name| !slot_name(name))
            || (1..self.params.len()).any(|at| self.params[..at].contains(&self.params[at]))
        {
            return invalid(
                "a program names distinct parameters, each a-z, 0-9 and _ from a letter",
            );
        }
        if self.steps.is_empty() {
            return invalid("a program holds one or more steps");
        }
        if self.postcondition.is_empty() {
            return invalid("a program's postcondition holds one or more checks");
        }
        let live = self
            .steps
            .iter()
            .flat_map(BatchStep::targets)
            .chain(
                self.postcondition
                    .iter()
                    .filter_map(|check| check.target.as_ref()),
            )
            .map(String::as_str)
            .any(is_live_handle);
        if live {
            return invalid(
                "a program names its elements by locator; a live handle this session did not mint never joins the library",
            );
        }
        match &self.steps[0] {
            BatchStep::Open { url } => site_of(url).map_or_else(
                || invalid("a program opens an http or https page whose host takes no slot"),
                Ok,
            ),
            _ => invalid("a program's first step opens its page"),
        }
    }

    /// The steps and checks with every slot filled from `args`, which name
    /// exactly the program's parameters.
    pub fn fill(
        &self,
        args: &BTreeMap<String, String>,
    ) -> Result<(Vec<BatchStep>, Vec<ExpectInput>), BrowserError> {
        if args.len() != self.params.len() || self.params.iter().any(|p| !args.contains_key(p)) {
            return Err(BrowserError::Input(format!(
                "the program takes exactly the arguments {:?}",
                self.params
            )));
        }
        let encoded = |error: serde_json::Error| BrowserError::Input(error.to_string());
        let mut steps = serde_json::to_value(&self.steps).map_err(encoded)?;
        let mut checks = serde_json::to_value(&self.postcondition).map_err(encoded)?;
        fill_slots(&mut steps, args)?;
        fill_slots(&mut checks, args)?;
        let decoded = |error: serde_json::Error| {
            BrowserError::Input(format!("a filled slot breaks the program: {error}"))
        };
        Ok((
            serde_json::from_value(steps).map_err(decoded)?,
            serde_json::from_value(checks).map_err(decoded)?,
        ))
    }
}

/// The site of an http or https URL: its host (and port), lower-cased. None
/// for another scheme, or a host that takes a slot.
#[must_use]
pub fn site_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    (!host.is_empty() && !host.contains("{{")).then(|| host.to_ascii_lowercase())
}

fn slot_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Fills every `{{name}}` slot in `value`'s strings from `args`.
fn fill_slots(
    value: &mut serde_json::Value,
    args: &BTreeMap<String, String>,
) -> Result<(), BrowserError> {
    match value {
        serde_json::Value::String(text) if text.contains("{{") => {
            let mut filled = String::with_capacity(text.len());
            let mut rest = text.as_str();
            while let Some(open) = rest.find("{{") {
                filled.push_str(&rest[..open]);
                let after = &rest[open + 2..];
                let close = after
                    .find("}}")
                    .ok_or_else(|| BrowserError::Input("a {{ slot is never closed".to_owned()))?;
                let name = after[..close].trim();
                let arg = args.get(name).ok_or_else(|| {
                    BrowserError::Input(format!("slot {{{{{name}}}}} is no parameter"))
                })?;
                filled.push_str(arg);
                rest = &after[close + 2..];
            }
            filled.push_str(rest);
            *text = filled;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                fill_slots(item, args)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values_mut() {
                fill_slots(field, args)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(feature = "driver")]
/// The checks the page as it is now misses, by index.
fn unmet<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    checks: &[ExpectInput],
) -> Result<Vec<usize>, BrowserError> {
    let mut missed = Vec::new();
    for (index, check) in checks.iter().enumerate() {
        if !driver.expect(check.clone())?.met {
            missed.push(index);
        }
    }
    Ok(missed)
}

#[cfg(feature = "driver")]
/// Puts every live handle `driver` minted among `steps` and `checks` back to
/// its row's locator.
fn by_locator<D: BrowserDriver + ?Sized>(
    driver: &D,
    steps: &mut [BatchStep],
    checks: &mut [ExpectInput],
) {
    let targets = steps
        .iter_mut()
        .flat_map(BatchStep::targets_mut)
        .chain(checks.iter_mut().filter_map(|check| check.target.as_mut()));
    for target in targets {
        if let Some(info) = driver.handle_info(target.as_str()) {
            *target = info.locator;
        }
    }
}

#[cfg(feature = "driver")]
/// A read the caller never sees: whole, and never its base.
fn hidden_look() -> ObserveInput {
    ObserveInput {
        full: true,
        ..ObserveInput::default()
    }
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
/// A refusal by `check`, with what it found.
fn refused(check: WorkflowCheck, refusal: Option<AdmissionRefusal>) -> ProposeOutput {
    ProposeOutput {
        admitted: false,
        workflow: None,
        refused_by: Some(check),
        refusal,
        unmet: Vec::new(),
        replay: None,
        replay_guest: None,
        superseded: None,
    }
}

#[cfg(feature = "driver")]
/// A proposal's first check, on the proposing session's own page: the live
/// handles it names put back to their locators, its shape and its held-out
/// values checked, then the solved page read against the postcondition
/// filled from `args`. A refusal is the proposal's answer.
pub(crate) fn check_solved<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    input: ProposeInput,
) -> Result<Result<Solved, ProposeOutput>, BrowserError> {
    let (mut steps, mut postcondition) = (input.steps, input.postcondition);
    by_locator(&*driver, &mut steps, &mut postcondition);
    let program = WorkflowProgram {
        subgoal: input.subgoal,
        params: input.params,
        steps,
        postcondition,
    };
    let site = program.site()?;
    let (_, solved_checks) = program.fill(&input.args)?;
    let held_out = match validate_replay_args(&program, &input.args, &input.replay_args) {
        Ok(held_out) => held_out,
        Err(refusal) => return Ok(Err(refused(WorkflowCheck::HeldOut, Some(refusal)))),
    };
    // The replay fills its steps and its checks from its own values.
    let values = if held_out {
        &input.replay_args
    } else {
        &input.args
    };
    let (steps, checks) = program.fill(values)?;
    // The independent check: the host reads the solved run's page itself.
    let solved = driver.observe(hidden_look())?;
    let missed = unmet(driver, &solved_checks)?;
    if !missed.is_empty() {
        return Ok(Err(ProposeOutput {
            unmet: missed,
            ..refused(WorkflowCheck::Solved, None)
        }));
    }
    Ok(Ok(Solved {
        site,
        program,
        steps,
        checks,
        args: input.args,
        replay_args: input.replay_args,
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
    let code = error.code().to_owned();
    let refusal = AdmissionRefusal::FreshGuest { stage, code };
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
    let replay = fresh.batch_with(
        BatchInput {
            subgoal: Some(program.subgoal.clone()),
            steps,
            base: None,
            until_ms: None,
            no_model: true,
        },
        decider,
    )?;
    let missed = if replay.status == SubgoalStatus::Done {
        unmet(fresh, &checks)?
    } else {
        Vec::new()
    };
    if replay.status != SubgoalStatus::Done || !missed.is_empty() {
        return Ok(ProposeOutput {
            unmet: missed,
            replay: Some(replay),
            replay_guest: Some(guest),
            ..refused(WorkflowCheck::Replay, None)
        });
    }
    let replayed = fresh.observe(hidden_look())?;
    let proof = WorkflowProof {
        args,
        replay_args,
        held_out,
        seed,
        solved_url,
        solved_title,
        replay_receipts: replay.receipts.clone(),
        replay_decisions: replay.decisions.clone(),
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

#[cfg(feature = "driver")]
/// Runs a library program live, then checks its postcondition on the page.
pub(crate) fn run<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    library: &mut dyn WorkflowLibrary,
    decider: &mut dyn RoutineDecider,
    input: LibraryRunInput,
) -> Result<LibraryRunOutput, BrowserError> {
    let program = library
        .program(&input.workflow)?
        .ok_or_else(|| BrowserError::NoWorkflow(input.workflow.clone()))?;
    let (steps, checks) = program.fill(&input.args)?;
    let mut batch = driver.batch_with(
        BatchInput {
            subgoal: Some(program.subgoal.clone()),
            steps,
            base: input.base.clone(),
            until_ms: None,
            no_model: false,
        },
        decider,
    )?;
    let missed = if batch.status == SubgoalStatus::Done {
        unmet(driver, &checks)?
    } else {
        Vec::new()
    };
    if !missed.is_empty() {
        // A missed postcondition goes back to the planner, with the page.
        batch.status = SubgoalStatus::NeedsAgent;
        batch.error = Some("postcondition_unmet".to_owned());
        batch.observation = Some(driver.observe(ObserveInput {
            base: input.base,
            ..ObserveInput::default()
        })?);
    }
    library.record_run(&input.workflow, batch.status == SubgoalStatus::Done)?;
    Ok(LibraryRunOutput {
        workflow: input.workflow,
        status: batch.status,
        unmet: missed,
        batch,
    })
}
