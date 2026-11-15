//! Owner-registered CUSTOM field projections. Payloads and IDs remain app reports.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AgUiDecodedEvent;
use crate::{Error, Result};

#[doc(hidden)]
pub use oneiron_verb_wire::ingest::ag_ui::observations::{AgUiCustomMapping, AgUiObservationKind};

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

/// A row's id and namespace: its thread, run and tool call. Rows match a
/// link only in the namespace of the row it is resolved from, which must
/// name a thread and a run.
type NamespacedId<'a> = (&'a str, &'a str, &'a str, Option<&'a str>);

/// The rows of one capture by id, built in one pass, so every link of the
/// capture resolves in time linear in its rows, never by a scan of them all
/// per link.
struct ObservationIndex<'a> {
    observations: &'a [AgUiAppObservation],
    /// The first row with each id in each namespace, and whether a second
    /// one follows it.
    by_namespace: HashMap<NamespacedId<'a>, (usize, bool)>,
    /// The kinds of the rows with each id, in any namespace.
    kinds_by_id: HashMap<&'a str, Vec<AgUiObservationKind>>,
}

impl<'a> ObservationIndex<'a> {
    fn new(observations: &'a [AgUiAppObservation]) -> Self {
        let mut by_namespace: HashMap<NamespacedId<'a>, (usize, bool)> = HashMap::new();
        let mut kinds_by_id: HashMap<&'a str, Vec<AgUiObservationKind>> = HashMap::new();
        for (index, row) in observations.iter().enumerate() {
            let Some(id) = row.id.as_deref() else {
                continue;
            };
            let kinds = kinds_by_id.entry(id).or_default();
            if !kinds.contains(&row.kind) {
                kinds.push(row.kind);
            }
            if let Some(key) = namespaced(row, id) {
                by_namespace
                    .entry(key)
                    .and_modify(|(_, repeated)| *repeated = true)
                    .or_insert((index, false));
            }
        }
        Self {
            observations,
            by_namespace,
            kinds_by_id,
        }
    }

    /// The one row with `id` in `from`'s namespace, if it is of `kind`.
    fn resolve(
        &self,
        from: &'a AgUiAppObservation,
        id: Option<&'a str>,
        kind: AgUiObservationKind,
    ) -> std::result::Result<&'a AgUiAppObservation, AgUiRepairLinkStatus> {
        let id = id.ok_or(AgUiRepairLinkStatus::MissingLink)?;
        let Some(&(first, repeated)) =
            namespaced(from, id).and_then(|key| self.by_namespace.get(&key))
        else {
            return Err(
                if self
                    .kinds_by_id
                    .get(id)
                    .is_some_and(|kinds| kinds.contains(&kind))
                {
                    AgUiRepairLinkStatus::NamespaceMismatch
                } else {
                    AgUiRepairLinkStatus::MissingLink
                },
            );
        };
        if repeated {
            return Err(AgUiRepairLinkStatus::AmbiguousLink);
        }
        let row = &self.observations[first];
        if row.kind != kind {
            return Err(AgUiRepairLinkStatus::MissingLink);
        }
        Ok(row)
    }
}

/// `id` in `row`'s namespace; none when the row names no thread or no run.
fn namespaced<'a>(row: &'a AgUiAppObservation, id: &'a str) -> Option<NamespacedId<'a>> {
    Some((
        id,
        row.thread_id.as_deref()?,
        row.run_id.as_deref()?,
        row.tool_call_id.as_deref(),
    ))
}

pub(super) fn repair_links(observations: &[AgUiAppObservation]) -> Vec<AgUiRepairLink> {
    let index = ObservationIndex::new(observations);
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
                index.resolve(outcome, outcome.id.as_deref(), AgUiObservationKind::Outcome)?;
                let repair = index.resolve(
                    outcome,
                    outcome.repair_id.as_deref(),
                    AgUiObservationKind::Repair,
                )?;
                link.repair_ordinal = Some(repair.ordinal);
                let failure = index.resolve(
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
