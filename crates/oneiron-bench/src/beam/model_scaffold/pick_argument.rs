//! `beam measure --picks-for` (census L9-32; Engine ruling
//! L9-32-PICK-WRITER, Sat 14 Nov 07:43): the argument of
//! `vault.agents.optional_memory.set` built from a saved measure report's
//! reader picks, so the owner applies a bench pick in one reviewed step. It
//! reads the report `beam measure <plan.json>` printed and makes no model
//! call.
//!
//! The default is no optional recall (ZERO-RETRIEVAL = A), and each task
//! family whose pick differs from it is listed. A pick without optional
//! memory is `none`; a pick with a budget takes the pack view its engine-pack
//! arm served. Refused: a report with no picks, picks of more than one
//! reader, a recalling pick whose arm served no engine pack (it names no
//! setting a pack can apply), a 0-token budget (0 is no limit), and, with no
//! regime named, a family the two regimes pick differently.

use std::collections::BTreeMap;
use std::path::Path;

use oneiron::EntityId;
use oneiron::agent_def::{AgentOptionalMemorySetRequest, OptionalMemoryChoice, OptionalMemoryView};
use serde::Deserialize;

use super::paired::Regime;
use crate::beam::model::ArmKind;
use crate::beam::{BeamError, BeamResult};

/// The fields of a saved measure report this reads.
#[derive(Deserialize)]
struct SavedReport {
    picks: Vec<SavedPick>,
}

/// One saved [`super::paired::ReaderPick`].
#[derive(Deserialize)]
struct SavedPick {
    regime: Regime,
    answerer: String,
    answerer_params_sha256: String,
    task_family: String,
    arm: ArmKind,
    optional_memory_tokens: Option<u64>,
    tier: Option<String>,
}

fn refusal(reason: impl Into<String>) -> BeamError {
    BeamError::PickArgument {
        reason: reason.into(),
    }
}

/// The parsed `measure --picks-for` arguments: `--picks-for <definition
/// hex> --expected-version <version> [--regime <regime>] <report.json>`.
pub(in crate::beam) struct PicksFor<'a> {
    definition: &'a str,
    expected_version: &'a str,
    regime: Option<&'a str>,
    report: &'a Path,
}

impl<'a> PicksFor<'a> {
    /// Reads the flags after `measure`; `None` when they are not this form.
    pub(in crate::beam) fn parse(args: &'a [String]) -> Option<Self> {
        let mut definition = None;
        let mut expected_version = None;
        let mut regime = None;
        let mut report = None;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            let slot = match arg.as_str() {
                "--picks-for" => &mut definition,
                "--expected-version" => &mut expected_version,
                "--regime" => &mut regime,
                _ if report.is_none() && !arg.starts_with("--") => {
                    report = Some(Path::new(arg.as_str()));
                    continue;
                }
                _ => return None,
            };
            if slot.is_some() {
                return None;
            }
            *slot = Some(rest.next()?.as_str());
        }
        Some(Self {
            definition: definition?,
            expected_version: expected_version?,
            regime,
            report: report?,
        })
    }

    /// The setter's argument, from the report at `self.report`.
    pub(in crate::beam) fn run(&self) -> BeamResult<AgentOptionalMemorySetRequest> {
        let text = std::fs::read_to_string(self.report).map_err(|error| {
            refusal(format!(
                "cannot read the report {}: {error}",
                self.report.display()
            ))
        })?;
        let regime = self
            .regime
            .map(|name| {
                serde_json::from_value::<Regime>(serde_json::Value::from(name)).map_err(|_| {
                    refusal(format!(
                        "--regime {name} is neither fixed_answer_cap nor fixed_total_tokens"
                    ))
                })
            })
            .transpose()?;
        optional_memory_argument(&text, self.definition, self.expected_version, regime)
    }
}

/// The argument for definition `definition` at `expected_version`, from the
/// report JSON `report`; `regime` keeps that regime's picks only.
fn optional_memory_argument(
    report: &str,
    definition: &str,
    expected_version: &str,
    regime: Option<Regime>,
) -> BeamResult<AgentOptionalMemorySetRequest> {
    let agent_def_ref =
        EntityId::from_hex(definition).map_err(|source| BeamError::InvalidEntityId {
            id: definition.to_owned(),
            source,
        })?;
    if expected_version.trim().is_empty() {
        return Err(refusal("--expected-version is empty"));
    }
    let picks: Vec<SavedPick> = serde_json::from_str::<SavedReport>(report)?
        .picks
        .into_iter()
        .filter(|pick| regime.is_none_or(|regime| pick.regime == regime))
        .collect();
    let Some(first) = picks.first() else {
        return Err(refusal("the report holds no reader pick for that regime"));
    };
    if picks.iter().any(|pick| {
        (pick.answerer.as_str(), pick.answerer_params_sha256.as_str())
            != (
                first.answerer.as_str(),
                first.answerer_params_sha256.as_str(),
            )
    }) {
        return Err(refusal(
            "the report picks for more than one reader; measure one reader per report",
        ));
    }
    let mut families: BTreeMap<String, OptionalMemoryChoice> = BTreeMap::new();
    for pick in &picks {
        let choice = choice(pick)?;
        if let Some(other) = families.insert(pick.task_family.clone(), choice)
            && other != choice
        {
            return Err(refusal(format!(
                "the two regimes pick differently for task family {}; name one with --regime",
                pick.task_family
            )));
        }
    }
    let default = OptionalMemoryChoice::None;
    families.retain(|_, choice| *choice != default);
    Ok(AgentOptionalMemorySetRequest {
        agent_def_ref,
        expected_version: expected_version.to_owned(),
        default,
        families,
    })
}

fn choice(pick: &SavedPick) -> BeamResult<OptionalMemoryChoice> {
    let Some(tokens) = pick.optional_memory_tokens else {
        return Ok(OptionalMemoryChoice::None);
    };
    if tokens == 0 {
        return Err(refusal(format!(
            "task family {} picks a 0-token budget, which a pack reads as no limit",
            pick.task_family
        )));
    }
    let view = match pick.tier.as_deref() {
        Some("summary") => OptionalMemoryView::Summary,
        Some("standard") => OptionalMemoryView::Standard,
        Some("full") => OptionalMemoryView::Full,
        Some(other) => {
            return Err(refusal(format!(
                "task family {} names pack view {other}",
                pick.task_family
            )));
        }
        None => {
            return Err(refusal(format!(
                "task family {} picks arm {}, which served no engine pack, so no pack setting \
                 matches it",
                pick.task_family,
                pick.arm.as_str()
            )));
        }
    };
    Ok(OptionalMemoryChoice::Budget { tokens, view })
}
