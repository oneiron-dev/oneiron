//! The replay library (OF-598; EIRI-ARCH-0002 "The replay library"): a
//! solved browser run, kept as a parameterised program for its site.
//!
//! A program joins the library only after two checks. First the host checks
//! that the run succeeded: the program's postcondition, read on the page
//! itself, never the program's own "done". Then the program replays once
//! with no model (a routine step takes only a rule's answer) and the replay
//! meets the postcondition again. Repeated work on a site tries the library
//! first: opening a page lists the site's programs. A library run is live:
//! every effect in it still crosses its gated door, and a run that misses
//! its postcondition goes back to the planner with the checks it missed and
//! the page it left.
//!
//! A program's `{{name}}` slots take the run's arguments as data, in the
//! batch's own fields; nothing is spliced into code.

use crate::{
    BATCH_MAX_STEPS, BatchOutput, BatchStep, BrowserError, EffectReceipt, ExpectInput,
    SubgoalStatus,
};
#[cfg(feature = "driver")]
use crate::{BatchInput, BrowserDriver, ObserveInput, RoutineDecider};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Parameters one program may take.
pub const WORKFLOW_MAX_PARAMS: usize = 16;
/// Checks one postcondition may hold.
pub const WORKFLOW_MAX_CHECKS: usize = 16;
/// The longest subgoal a program is filed under, in bytes.
pub const WORKFLOW_SUBGOAL_BYTES: usize = 512;

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
/// solved run used; the host checks the page now, then replays the program
/// with them once, with no model.
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
}

/// Which check refused a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCheck {
    /// The solved run's page does not meet the postcondition.
    Solved,
    /// The no-model replay did not finish, or did not meet it.
    Replay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeOutput {
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_by: Option<WorkflowCheck>,
    /// The postcondition checks the page missed, by index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmet: Vec<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<BatchOutput>,
}

/// The two checks' evidence, kept with an admitted program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowProof {
    /// The arguments the solved run and its replay used.
    pub args: BTreeMap<String, String>,
    /// The page the solved run ended on, which met the postcondition.
    pub solved_url: String,
    pub solved_title: String,
    /// The no-model replay's effect receipts and routine decisions.
    pub replay_receipts: Vec<EffectReceipt>,
    pub replay_decisions: Vec<serde_json::Value>,
    /// The page the replay ended on, which met the postcondition again.
    pub replay_url: String,
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

/// One library program as a planner reads it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LibraryCard {
    pub workflow: String,
    pub site: String,
    pub subgoal: String,
    pub params: Vec<String>,
    pub runs: u32,
    pub failures: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

/// A library run: its batch, and the postcondition checks the page missed.
/// A miss sets `NEEDS_AGENT`: the run goes back to the planner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LibraryRunOutput {
    pub workflow: String,
    pub status: SubgoalStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmet: Vec<usize>,
    pub batch: BatchOutput,
}

/// Where library programs are kept: the engine's vault, behind the session.
pub trait WorkflowLibrary: Send {
    /// The programs filed for `site`, those whose subgoal holds `subgoal`.
    fn find(&mut self, site: &str, subgoal: Option<&str>)
    -> Result<Vec<LibraryCard>, BrowserError>;
    fn program(&mut self, workflow: &str) -> Result<Option<WorkflowProgram>, BrowserError>;
    /// Files a program both checks passed; returns its ref.
    fn admit(
        &mut self,
        site: &str,
        program: &WorkflowProgram,
        proof: &WorkflowProof,
    ) -> Result<String, BrowserError>;
    /// Counts one library run, and whether it met its postcondition.
    fn record_run(&mut self, workflow: &str, met: bool) -> Result<(), BrowserError>;
}

impl WorkflowProgram {
    /// The site the program runs on, once its shape holds: a subgoal, named
    /// parameters, 1 to [`BATCH_MAX_STEPS`] steps opening with a page whose
    /// host takes no slot, and 1 to [`WORKFLOW_MAX_CHECKS`] checks.
    pub fn site(&self) -> Result<String, BrowserError> {
        let invalid = |why: &str| Err(BrowserError::Input(why.to_owned()));
        if self.subgoal.trim().is_empty() || self.subgoal.len() > WORKFLOW_SUBGOAL_BYTES {
            return invalid("a program's subgoal is 1 to 512 bytes");
        }
        if self.params.len() > WORKFLOW_MAX_PARAMS
            || self.params.iter().any(|name| !slot_name(name))
            || (1..self.params.len()).any(|at| self.params[..at].contains(&self.params[at]))
        {
            return invalid(
                "a program names at most 16 distinct parameters, each a-z, 0-9 and _ from a letter",
            );
        }
        if self.steps.is_empty() || self.steps.len() > BATCH_MAX_STEPS {
            return invalid("a program holds 1 to 64 steps");
        }
        if self.postcondition.is_empty() || self.postcondition.len() > WORKFLOW_MAX_CHECKS {
            return invalid("a program's postcondition holds 1 to 16 checks");
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
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    (!host.is_empty() && !host.contains("{{")).then(|| host.to_ascii_lowercase())
}

fn slot_name(name: &str) -> bool {
    name.len() <= 32
        && name.starts_with(|c: char| c.is_ascii_lowercase())
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
                let arg = args
                    .get(name)
                    .ok_or_else(|| BrowserError::Input(format!("slot {{{{{name}}}}} is no parameter")))?;
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
/// Offers a solved run's program: the solved page first, then one no-model
/// replay, then the library files it.
pub(crate) fn propose<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    library: &mut dyn WorkflowLibrary,
    decider: &mut dyn RoutineDecider,
    input: ProposeInput,
) -> Result<ProposeOutput, BrowserError> {
    let program = WorkflowProgram {
        subgoal: input.subgoal,
        params: input.params,
        steps: input.steps,
        postcondition: input.postcondition,
    };
    let site = program.site()?;
    let (steps, checks) = program.fill(&input.args)?;
    let refused = |check, unmet, replay| ProposeOutput {
        admitted: false,
        workflow: None,
        refused_by: Some(check),
        unmet,
        replay,
    };
    // The independent check: the host reads the solved run's page itself.
    let solved = driver.observe(ObserveInput::default())?;
    let missed = unmet(driver, &checks)?;
    if !missed.is_empty() {
        return Ok(refused(WorkflowCheck::Solved, missed, None));
    }
    let replay = driver.batch_with(
        BatchInput {
            subgoal: Some(program.subgoal.clone()),
            steps,
            until_ms: None,
            no_model: true,
        },
        decider,
    )?;
    if replay.status != SubgoalStatus::Done {
        return Ok(refused(WorkflowCheck::Replay, Vec::new(), Some(replay)));
    }
    let missed = unmet(driver, &checks)?;
    if !missed.is_empty() {
        return Ok(refused(WorkflowCheck::Replay, missed, Some(replay)));
    }
    let replayed = driver.observe(ObserveInput::default())?;
    let proof = WorkflowProof {
        args: input.args,
        solved_url: solved.url,
        solved_title: solved.title,
        replay_receipts: replay.receipts.clone(),
        replay_decisions: replay.decisions.clone(),
        replay_url: replayed.url,
    };
    let workflow = library.admit(&site, &program, &proof)?;
    Ok(ProposeOutput {
        admitted: true,
        workflow: Some(workflow),
        refused_by: None,
        unmet: Vec::new(),
        replay: Some(replay),
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
        batch.observation = Some(driver.observe(ObserveInput::default())?);
    }
    library.record_run(&input.workflow, batch.status == SubgoalStatus::Done)?;
    Ok(LibraryRunOutput {
        workflow: input.workflow,
        status: batch.status,
        unmet: missed,
        batch,
    })
}
