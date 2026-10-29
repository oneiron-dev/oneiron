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
//! the checks it missed and the page it left. A run is strict, where only a
//! rule answers its routine steps, or assisted (CUA E2); a program whose
//! strict runs miss three times in a row retires `drift`. A program that
//! stops working leaves by retire, and a later solved run that passes both
//! checks files it afresh, or files its repair as its successor
//! (`supersedes`), which retires it in the same write.
//!
//! A program's `{{name}}` slots take the run's arguments as data, in the
//! batch's own fields; nothing is spliced into code. A secret takes a typed
//! slot (FIX 8028, `secret_slots`): neither the program nor its proof holds
//! a secret, or the handle a run found it as.
//!
//! A program names elements by locator only, never by a live handle (a
//! handle names one node of one session's page). A proposal's handles the
//! session minted are put back to their rows' locators before the program
//! is checked; each step resolves its locators on the page as it runs.

mod admission;
mod cards;
mod draft;
#[cfg(feature = "driver")]
mod durable;
mod live_run;
mod secret_slots;
mod targets;

pub(crate) use secret_slots::handle_form;

#[cfg(feature = "driver")]
pub(crate) use draft::draft_with_secrets;
#[cfg(feature = "driver")]
pub(crate) use durable::durable_draft;

pub use admission::{
    AdmissionRefusal, Admitted, RecentCounts, ReplayGuest, SupersedeOutcome, SupersedeRefusal,
    WorkflowSeed, validate_replay_args,
};
pub use cards::{
    LibraryCard, LibraryFindInput, LibraryFindOutput, LibraryRetireInput, LibraryRetireOutput,
    LibraryRetiredInput, LibraryRetiredOutput, RetiredCard,
};
pub use draft::{
    DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput, DraftPage, DraftStep,
    PressedThrough, SlotCandidate, SlotField, draft_from_steps,
};
#[cfg(feature = "driver")]
pub use live_run::filled_checks;
#[cfg(feature = "driver")]
pub(crate) use live_run::run;
pub use live_run::{
    FiledWorkflow, LibraryRunMode, RunOutcome, default_mode, effective_mode, model_free,
};
pub use secret_slots::SecretParam;

#[cfg(feature = "driver")]
use crate::CheckReceipt;
#[cfg(feature = "driver")]
use crate::{BatchInput, BrowserDriver, NoWriter, ObserveInput, RoutineDecider, SwitchStage};
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
    /// Those of `params` that take a secret, each with its kind: a step's
    /// or a check's `secret: "{{name}}"`, filled with a handle the run holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_params: Vec<SecretParam>,
    /// The batch. Its first step opens the page that names its site.
    pub steps: Vec<BatchStep>,
    /// What the page shows when the program worked: every check must hold.
    pub postcondition: Vec<ExpectInput>,
}

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

/// Runs a library program live with `args`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryRunInput {
    pub workflow: String,
    /// A secret slot's names a handle this run holds, or is its own text.
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    /// The observation the run's last observation edits, as `observe`'s
    /// `base`; by default the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
    /// Strict or assisted; by default the program's own ([`default_mode`]).
    #[serde(default)]
    pub mode: Option<LibraryRunMode>,
    /// Secret slots' arguments in typed form (FIX 8346): a name here takes
    /// the place of the same name in `args`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_args: BTreeMap<String, SecretArg>,
}

/// A secret slot's argument, typed (FIX 8346): `{"handle": "sc12"}` names
/// a handle this run holds; `{"text": "sc12"}` is the slot's own text,
/// typed or checked as text even in a handle's form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretArg {
    Handle(String),
    Text(String),
}

/// A library run: its batch, and the postcondition checks the page missed.
/// A miss sets `NEEDS_AGENT`: the run goes back to the planner, with the
/// batch's `failed_receipt` naming each missed check and what the page
/// showed for it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryRunOutput {
    pub workflow: String,
    pub status: SubgoalStatus,
    /// The mode the run ran in.
    pub mode: LibraryRunMode,
    /// Whether no model answered any of the run's routine decisions, as
    /// their receipts show ([`model_free`]); never read from the mode.
    pub model_free: bool,
    /// The first decision whose record shows neither the rungs that ran nor
    /// a strict denial: no evidence proves the run model-free, so
    /// `model_free` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_free_unproven: Option<usize>,
    /// The postcondition checks the page missed, by index; each, with what
    /// its read found, is in the batch's `failed_receipt`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmet: Vec<usize>,
    pub batch: BatchOutput,
}

/// Where library programs are kept: the engine's vault, behind the session.
pub trait WorkflowLibrary: Send {
    /// The programs filed for `site`, those whose subgoal holds `subgoal`
    /// and, with `type_ref` (`node_id@tree_version`), whose task type is
    /// that node at that version; one in another form is refused.
    fn find(
        &mut self,
        site: &str,
        subgoal: Option<&str>,
        type_ref: Option<&str>,
    ) -> Result<Vec<LibraryCard>, BrowserError>;
    /// The program filed under `workflow`, with its admission's proof.
    fn program(&mut self, workflow: &str) -> Result<Option<FiledWorkflow>, BrowserError>;
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
    /// Counts one library run: whether it met its postcondition, and, for
    /// a strict run, its strict misses in a row, the third retiring it
    /// `drift` in the same write.
    fn record_run(&mut self, workflow: &str, outcome: &RunOutcome) -> Result<(), BrowserError>;
    /// Takes a program out of the library for `reason`; `None` when none is
    /// filed under `workflow`.
    fn retire(
        &mut self,
        workflow: &str,
        reason: Option<&str>,
    ) -> Result<Option<LibraryCard>, BrowserError>;
    /// Whether the library's record proves `workflow` retired (FIX 8073);
    /// false where none does, or the library keeps no retires.
    fn is_retired(&mut self, _workflow: &str) -> Result<bool, BrowserError> {
        Ok(false)
    }
    /// The refusal a proposal's `supersedes` link would meet at its filing,
    /// read before its fresh guest starts (FIX 7876): a ref that does not
    /// parse, or names no program of `site` the proposer may succeed. The
    /// filing's own write checks it again; none read here passes nothing.
    fn supersedes_refused(
        &mut self,
        _site: &str,
        _supersedes: &str,
    ) -> Result<Option<SupersedeRefusal>, BrowserError> {
        Ok(None)
    }
    /// The programs retires took out for `site`, the newest first.
    fn retired(&mut self, _site: &str) -> Result<Vec<RetiredCard>, BrowserError> {
        Err(BrowserError::Library(
            "this library keeps no retired programs".to_owned(),
        ))
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
        if !secret_slots::distinct(self) {
            return invalid("a program's secret slots are distinct parameters of its own");
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
    /// exactly the program's parameters; a secret slot's handle stays a
    /// secret, any other value of it is plain text (`secret_slot_arg_policy`).
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
        let mut steps: Vec<BatchStep> = serde_json::from_value(steps).map_err(decoded)?;
        let mut checks: Vec<ExpectInput> = serde_json::from_value(checks).map_err(decoded)?;
        secret_slots::bind(&mut steps, &mut checks);
        Ok((steps, checks))
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

/// The origin (scheme, host and port) of the page `program` opens first,
/// parsed as a draft parses its span's (CUA E8a): the origin of the solved
/// group its filing covers. None when its first step opens no such page.
#[cfg(feature = "driver")]
#[must_use]
pub fn program_origin(program: &WorkflowProgram) -> Option<String> {
    let Some(BatchStep::Open { url }) = program.steps.first() else {
        return None;
    };
    let origin = url::Url::parse(url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
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
            *text = fill_text(text, args).map_err(|gap| match gap {
                SlotGap::Unclosed => BrowserError::Input("a {{ slot is never closed".to_owned()),
                SlotGap::Missing(name) => {
                    BrowserError::Input(format!("slot {{{{{name}}}}} is no parameter"))
                }
            })?;
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

/// A slot [`fill_text`] could not fill: one `args` holds no value for, by
/// its name, or one never closed.
pub(crate) enum SlotGap {
    Missing(String),
    Unclosed,
}

/// `text` with every `{{name}}` slot filled from `args`: the one slot
/// filler a program's fields and a Fill's template share (CUA E6).
pub(crate) fn fill_text(text: &str, args: &BTreeMap<String, String>) -> Result<String, SlotGap> {
    let mut filled = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        filled.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = after.find("}}").ok_or(SlotGap::Unclosed)?;
        let name = after[..close].trim();
        let arg = args
            .get(name)
            .ok_or_else(|| SlotGap::Missing(name.to_owned()))?;
        filled.push_str(arg);
        rest = &after[close + 2..];
    }
    filled.push_str(rest);
    Ok(filled)
}

#[cfg(feature = "driver")]
/// The checks the page as it is now misses, by index, each with what its
/// read found.
fn missed<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    checks: &[ExpectInput],
) -> Result<Vec<(usize, CheckReceipt)>, BrowserError> {
    let mut missed = Vec::new();
    for (index, check) in checks.iter().enumerate() {
        let observed = driver.expect(check.clone())?;
        if !observed.met {
            let expect = check.clone();
            missed.push((index, CheckReceipt { expect, observed }));
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
