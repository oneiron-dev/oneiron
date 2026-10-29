//! A library program's shape and where programs are kept: the program
//! itself, the [`WorkflowLibrary`] door, and the site helpers a program's
//! shape check reads. Moved out of `library` whole (pure move).

use super::{Admitted, LibraryCard, RetiredCard, SupersedeRefusal, fill_slots, secret_slots};
use crate::{BatchStep, BrowserError, ExpectInput, is_live_handle};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::live_run::{FiledWorkflow, RunOutcome};
use super::propose::WorkflowProof;
use super::secret_slots::SecretParam;

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
