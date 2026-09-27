//! Goal-axis replay scores. A host supplies the goal axes; scores are normalized
//! to 0..=1 with larger always better (including cost axes).
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalAxisKind {
    Primary,
    Floor,
    Cost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalAxisSpec {
    pub name: String,
    pub kind: GoalAxisKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalAxisScore {
    pub kind: GoalAxisKind,
    pub before: f32,
    pub after: f32,
}

pub(super) fn score_goal_axes(
    scorer: &dyn HeldOutReplayScorer,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
) -> Result<BTreeMap<String, GoalAxisScore>> {
    let axes = scorer.goal_axes(before)?;
    if axes.is_empty()
        || axes.len() > 32
        || !axes.iter().any(|axis| axis.kind == GoalAxisKind::Primary)
    {
        return Err(invalid("goal axes require 1..=32 axes with a primary axis"));
    }
    let mut scored = BTreeMap::new();
    for axis in axes {
        if axis.name.is_empty()
            || axis.name.len() > 64
            || !axis
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            || scored.contains_key(&axis.name)
        {
            return Err(invalid(
                "goal axis names must be distinct bounded identifiers",
            ));
        }
        let old = validate_score(scorer.score_goal_axis(before, &axis)?)?;
        let new = validate_score(scorer.score_goal_axis(after, &axis)?)?;
        scored.insert(
            axis.name,
            GoalAxisScore {
                kind: axis.kind,
                before: old,
                after: new,
            },
        );
    }
    Ok(scored)
}

pub(super) fn validate_goal_vector(axes: &BTreeMap<String, GoalAxisScore>) -> Result<()> {
    if axes.is_empty()
        || axes.len() > 32
        || !axes.values().any(|axis| axis.kind == GoalAxisKind::Primary)
    {
        return Err(invalid("a judged verdict requires a primary goal axis"));
    }
    for (name, axis) in axes {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(invalid("invalid goal axis name"));
        }
        validate_score(axis.before)?;
        validate_score(axis.after)?;
    }
    Ok(())
}

pub(super) fn dominates(axes: &BTreeMap<String, GoalAxisScore>) -> bool {
    axes.values().all(|axis| axis.after >= axis.before)
        && axes.values().any(|axis| axis.after > axis.before)
}

pub(super) fn floor_regressed(axes: &BTreeMap<String, GoalAxisScore>) -> bool {
    axes.values()
        .any(|axis| axis.kind == GoalAxisKind::Floor && axis.after < axis.before)
}

pub(super) fn is_tradeoff(axes: &BTreeMap<String, GoalAxisScore>) -> bool {
    axes.values().any(|axis| axis.after > axis.before)
        && axes.values().any(|axis| axis.after < axis.before)
}
