//! Owner-registered CUSTOM field projections. Payloads and IDs remain app reports.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AgUiDecodedEvent;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgUiObservationKind {
    Action,
    Failure,
    Repair,
    Outcome,
}

/// JSON pointers address the whole CUSTOM event, not an assumed payload schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgUiCustomMapping {
    pub name: String,
    pub kind: AgUiObservationKind,
    pub id: Option<String>,
    pub thread_id: Option<String>,
    pub run_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub failure_id: Option<String>,
    pub repair_id: Option<String>,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgUiAppObservation {
    pub ordinal: usize,
    pub name: String,
    pub kind: AgUiObservationKind,
    pub id: Option<String>,
    pub thread_id: Option<String>,
    pub run_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub failure_id: Option<String>,
    pub repair_id: Option<String>,
    pub outcome: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgUiRepairLinkStatus {
    Linked,
    MissingLink,
    AmbiguousLink,
    NamespaceMismatch,
    MissingOutcome,
}

/// Ordinals address occurrences in this source only. Repeated IDs stay ambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgUiRepairLink {
    pub outcome_ordinal: usize,
    pub repair_ordinal: Option<usize>,
    pub failure_ordinal: Option<usize>,
    pub status: AgUiRepairLinkStatus,
}

pub(super) fn validate_mappings(mappings: &[AgUiCustomMapping]) -> Result<()> {
    let mut names = BTreeSet::new();
    for mapping in mappings {
        if mapping.name.is_empty() || !names.insert(&mapping.name) {
            return Err(Error::InvalidClaimBody(
                "AG-UI CUSTOM names must be nonempty and unique",
            ));
        }
        for pointer in [
            &mapping.id,
            &mapping.thread_id,
            &mapping.run_id,
            &mapping.tool_call_id,
            &mapping.failure_id,
            &mapping.repair_id,
            &mapping.outcome,
        ]
        .into_iter()
        .flatten()
        {
            if (!pointer.is_empty() && !pointer.starts_with('/'))
                || pointer
                    .as_bytes()
                    .windows(2)
                    .any(|pair| pair[0] == b'~' && !matches!(pair[1], b'0' | b'1'))
                || pointer.ends_with('~')
            {
                return Err(Error::InvalidClaimBody(
                    "AG-UI mapping requires JSON pointers",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn observations(
    events: &[AgUiDecodedEvent],
    mappings: &[AgUiCustomMapping],
) -> Vec<AgUiAppObservation> {
    events
        .iter()
        .enumerate()
        .filter_map(|(ordinal, event)| {
            if event.event_type() != Some("CUSTOM") {
                return None;
            }
            let name = event.raw().get("name")?.as_str()?;
            let mapping = mappings.iter().find(|mapping| mapping.name == name)?;
            let string = |pointer: &Option<String>| {
                pointer
                    .as_ref()
                    .and_then(|pointer| event.raw().pointer(pointer))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            };
            Some(AgUiAppObservation {
                ordinal,
                name: name.to_owned(),
                kind: mapping.kind,
                id: string(&mapping.id),
                thread_id: string(&mapping.thread_id),
                run_id: string(&mapping.run_id),
                tool_call_id: string(&mapping.tool_call_id),
                failure_id: string(&mapping.failure_id),
                repair_id: string(&mapping.repair_id),
                outcome: mapping
                    .outcome
                    .as_ref()
                    .and_then(|pointer| event.raw().pointer(pointer))
                    .filter(|value| !value.is_null())
                    .cloned(),
            })
        })
        .collect()
}

fn same_namespace(left: &AgUiAppObservation, right: &AgUiAppObservation) -> bool {
    left.thread_id.is_some()
        && left.run_id.is_some()
        && left.thread_id == right.thread_id
        && left.run_id == right.run_id
        && left.tool_call_id == right.tool_call_id
}

fn resolve<'a>(
    observations: &'a [AgUiAppObservation],
    from: &AgUiAppObservation,
    id: Option<&str>,
    kind: AgUiObservationKind,
) -> std::result::Result<&'a AgUiAppObservation, AgUiRepairLinkStatus> {
    let id = id.ok_or(AgUiRepairLinkStatus::MissingLink)?;
    let mut matches = observations
        .iter()
        .filter(|row| row.id.as_deref() == Some(id) && same_namespace(from, row));
    let Some(first) = matches.next() else {
        return Err(
            if observations
                .iter()
                .any(|row| row.id.as_deref() == Some(id) && row.kind == kind)
            {
                AgUiRepairLinkStatus::NamespaceMismatch
            } else {
                AgUiRepairLinkStatus::MissingLink
            },
        );
    };
    if matches.next().is_some() {
        return Err(AgUiRepairLinkStatus::AmbiguousLink);
    }
    if first.kind != kind {
        return Err(AgUiRepairLinkStatus::MissingLink);
    }
    Ok(first)
}

pub(super) fn repair_links(observations: &[AgUiAppObservation]) -> Vec<AgUiRepairLink> {
    observations
        .iter()
        .filter(|row| row.kind == AgUiObservationKind::Outcome)
        .map(|outcome| {
            let mut link = AgUiRepairLink {
                outcome_ordinal: outcome.ordinal,
                repair_ordinal: None,
                failure_ordinal: None,
                status: AgUiRepairLinkStatus::MissingLink,
            };
            let resolved = (|| {
                if outcome.outcome.is_none() {
                    return Err(AgUiRepairLinkStatus::MissingOutcome);
                }
                resolve(
                    observations,
                    outcome,
                    outcome.id.as_deref(),
                    AgUiObservationKind::Outcome,
                )?;
                let repair = resolve(
                    observations,
                    outcome,
                    outcome.repair_id.as_deref(),
                    AgUiObservationKind::Repair,
                )?;
                link.repair_ordinal = Some(repair.ordinal);
                let failure = resolve(
                    observations,
                    repair,
                    repair.failure_id.as_deref(),
                    AgUiObservationKind::Failure,
                )?;
                link.failure_ordinal = Some(failure.ordinal);
                Ok(())
            })();
            link.status = resolved.err().unwrap_or(AgUiRepairLinkStatus::Linked);
            link
        })
        .collect()
}
