//! What a full goal proposal changes against the goal it revises, computed
//! by the engine when the proposal is stored. The interview shows it to the
//! human; a floor the proposal drops or relaxes is named here, never left to
//! the proposal's prose.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::{GoalAxis, GoalExplorationBudget, GoalPreference, GoalRecord};

/// One text field before and after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalTextChange {
    pub before: String,
    pub after: String,
}

/// One axis kept by name whose measure or bound moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalAxisChange {
    pub name: String,
    pub before: GoalAxis,
    pub after: GoalAxis,
}

/// The axes of one class, matched by name: a renamed axis is one removed
/// and one added; an axis moved to another class is removed from one class
/// and added to the other. Each list is in name order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalAxisChanges {
    pub added: Vec<GoalAxis>,
    pub removed: Vec<GoalAxis>,
    pub changed: Vec<GoalAxisChange>,
}

/// One preference kept by its pair whose reason moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalPreferenceChange {
    pub prefer: String,
    pub over: String,
    pub before: String,
    pub after: String,
}

/// The learned preferences, matched by their (prefer, over) pair, in pair
/// order. A pair held once on each side whose reason moved is changed; a
/// pair held more than once on either side is matched entry by entry, and
/// each entry with no equal partner is removed or added.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalPreferenceChanges {
    pub added: Vec<GoalPreference>,
    pub removed: Vec<GoalPreference>,
    pub changed: Vec<GoalPreferenceChange>,
}

/// The exploration budget before and after, all four fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalBudgetChange {
    pub before: GoalExplorationBudget,
    pub after: GoalExplorationBudget,
}

/// Every field of a goal record a proposal changes against its base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalRecordDiff {
    pub goal: Option<GoalTextChange>,
    pub why: Option<GoalTextChange>,
    pub primary_axes: GoalAxisChanges,
    /// Floor axes never regress (ARCH-0053): a proposal that drops or
    /// relaxes one shows it here by name, with its bound before and after.
    pub floor_axes: GoalAxisChanges,
    pub cost_axes: GoalAxisChanges,
    pub preferences: GoalPreferenceChanges,
    pub exploration_budget: Option<GoalBudgetChange>,
}

impl GoalRecordDiff {
    /// What `proposed` changes against `base`.
    pub(crate) fn between(base: &GoalRecord, proposed: &GoalRecord) -> Self {
        Self {
            goal: text_change(&base.goal, &proposed.goal),
            why: text_change(&base.why, &proposed.why),
            primary_axes: axis_changes(&base.primary_axes, &proposed.primary_axes),
            floor_axes: axis_changes(&base.floor_axes, &proposed.floor_axes),
            cost_axes: axis_changes(&base.cost_axes, &proposed.cost_axes),
            preferences: preference_changes(&base.preferences, &proposed.preferences),
            exploration_budget: (base.exploration_budget != proposed.exploration_budget).then(
                || GoalBudgetChange {
                    before: base.exploration_budget.clone(),
                    after: proposed.exploration_budget.clone(),
                },
            ),
        }
    }
}

fn text_change(before: &str, after: &str) -> Option<GoalTextChange> {
    (before != after).then(|| GoalTextChange {
        before: before.to_owned(),
        after: after.to_owned(),
    })
}

fn axis_changes(before: &[GoalAxis], after: &[GoalAxis]) -> GoalAxisChanges {
    let before: BTreeMap<&str, &GoalAxis> = before
        .iter()
        .map(|axis| (axis.name.as_str(), axis))
        .collect();
    let after: BTreeMap<&str, &GoalAxis> = after
        .iter()
        .map(|axis| (axis.name.as_str(), axis))
        .collect();
    let mut changes = GoalAxisChanges::default();
    for (name, old) in &before {
        match after.get(name) {
            None => changes.removed.push((*old).clone()),
            Some(new) if new != old => changes.changed.push(GoalAxisChange {
                name: (*name).to_owned(),
                before: (*old).clone(),
                after: (*new).clone(),
            }),
            Some(_) => {}
        }
    }
    for (name, new) in &after {
        if !before.contains_key(name) {
            changes.added.push((*new).clone());
        }
    }
    changes
}

fn preference_changes(
    before: &[GoalPreference],
    after: &[GoalPreference],
) -> GoalPreferenceChanges {
    let before = preference_pairs(before);
    let after = preference_pairs(after);
    let mut changes = GoalPreferenceChanges::default();
    for (pair, old) in &before {
        let new = after.get(pair).map_or(&[][..], Vec::as_slice);
        match (old.as_slice(), new) {
            // One entry on each side: its reason moved, or nothing did.
            ([old], [new]) => {
                if old.reason != new.reason {
                    changes.changed.push(GoalPreferenceChange {
                        prefer: pair.0.clone(),
                        over: pair.1.clone(),
                        before: old.reason.clone(),
                        after: new.reason.clone(),
                    });
                }
            }
            // Otherwise every entry without an equal partner on the other
            // side is removed or added, duplicates counted.
            _ => {
                let mut unmatched: Vec<&GoalPreference> = new.iter().collect();
                for entry in old {
                    match unmatched.iter().position(|candidate| *candidate == entry) {
                        Some(index) => {
                            unmatched.remove(index);
                        }
                        None => changes.removed.push(entry.clone()),
                    }
                }
                changes.added.extend(unmatched.into_iter().cloned());
            }
        }
    }
    for (pair, new) in &after {
        if !before.contains_key(pair) {
            changes.added.extend(new.iter().cloned());
        }
    }
    changes
}

/// Every entry of `preferences` under its (prefer, over) pair. A record may
/// hold one pair more than once (the goal validator asks only for nonblank,
/// non-self pairs), so each pair keeps every entry, in record order.
fn preference_pairs(
    preferences: &[GoalPreference],
) -> BTreeMap<(String, String), Vec<GoalPreference>> {
    let mut pairs: BTreeMap<(String, String), Vec<GoalPreference>> = BTreeMap::new();
    for preference in preferences {
        pairs
            .entry((preference.prefer.clone(), preference.over.clone()))
            .or_default()
            .push(preference.clone());
    }
    pairs
}
