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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// A vault-owned revision. Rewriting even the same axes advances the revision,
/// so a previously earned admission never silently inherits a new human ruling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GoalDefinition {
    pub(super) revision: String,
    pub(super) axes: Vec<GoalAxisSpec>,
}

const GOAL_PREFIX: &[u8] = b"skill_optimize/goal/v1\0";
const DEFAULT_GOAL_REVISION: &str = "scalar-default-v1";

fn goal_key(skill: &EntityId) -> Vec<u8> {
    [GOAL_PREFIX, skill.as_bytes()].concat()
}

fn validate_axes(axes: &[GoalAxisSpec]) -> Result<()> {
    if axes.is_empty()
        || axes.len() > 32
        || !axes.iter().any(|axis| axis.kind == GoalAxisKind::Primary)
    {
        return Err(invalid("goal axes require 1..=32 axes with a primary axis"));
    }
    let mut names = BTreeSet::new();
    for axis in axes {
        if axis.name.is_empty()
            || axis.name.len() > 64
            || !axis
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            || !names.insert(&axis.name)
        {
            return Err(invalid(
                "goal axis names must be distinct bounded identifiers",
            ));
        }
    }
    Ok(())
}

pub(super) fn goal_definition_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<GoalDefinition> {
    let Some(raw) = vault.store.vault_meta.get(txn, &goal_key(skill))? else {
        return Ok(GoalDefinition {
            revision: DEFAULT_GOAL_REVISION.to_owned(),
            axes: vec![GoalAxisSpec {
                name: "held_out".to_owned(),
                kind: GoalAxisKind::Primary,
            }],
        });
    };
    let definition: GoalDefinition =
        serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("skill goal definition"))?;
    validate_axes(&definition.axes).map_err(|_| Error::CorruptedIndex("skill goal definition"))?;
    if EntityId::from_hex(&definition.revision).is_err() {
        return Err(Error::CorruptedIndex("skill goal definition"));
    }
    Ok(definition)
}

/// The authenticated human sets the goal axes used by the optimizer for this
/// exact skill. Every change invalidates outstanding score permissions.
/// # Errors
/// Storage errors or an invalid/unauthorized goal definition.
pub fn set_skill_edit_goal_axes(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    skill: &EntityId,
    axes: Vec<GoalAxisSpec>,
) -> Result<String> {
    validate_axes(&axes)?;
    vault.with_write_txn(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        vault.read_skill_record_in_txn(txn, skill)?;
        let definition = GoalDefinition {
            revision: vault.store.clock.entity_id()?.to_hex(),
            axes,
        };
        let encoded = serde_json::to_vec(&definition)
            .map_err(|_| invalid("goal definition encode failed"))?;
        vault
            .store
            .vault_meta
            .put(txn, &goal_key(skill), &encoded)?;
        Ok(definition.revision)
    })
}

pub(super) fn score_goal_axes(
    scorer: &dyn HeldOutReplayScorer,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
    definition: &GoalDefinition,
) -> Result<BTreeMap<String, GoalAxisScore>> {
    if scorer.goal_axes(before)? != definition.axes {
        return Err(invalid(
            "scorer goal axes differ from the authenticated goal definition",
        ));
    }
    let mut scored = BTreeMap::new();
    for axis in &definition.axes {
        let old = validate_score(scorer.score_goal_axis(before, axis)?)?;
        let new = validate_score(scorer.score_goal_axis(after, axis)?)?;
        scored.insert(
            axis.name.clone(),
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
