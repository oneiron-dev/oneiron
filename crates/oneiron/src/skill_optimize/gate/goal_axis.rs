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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GoalDefinition {
    pub(super) goal_id: EntityId,
    pub(super) revision: String,
    pub(super) axes: Vec<GoalAxisSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoalOverride {
    revision: String,
    axes: Vec<GoalAxisSpec>,
}

const GOAL_PREFIX: &[u8] = b"skill_optimize/goal/v1\0";
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

fn read_current_goal_skill(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<SkillRecord> {
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("skill goal entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
        return Err(invalid("goal binding target is not a skill"));
    }
    crate::skill::decode_skill_record(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
}

fn manifest_axes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(Vec<GoalAxisSpec>, Vec<crate::gate::SkillEditGoalPolicy>)> {
    let resolved = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let policies = resolved
        .skill_edit_goal_policies()
        .ok_or(invalid(
            "no trusted skill edit goal policy manifest is in force",
        ))?
        .to_vec();
    let mut axes: Vec<GoalAxisSpec> = Vec::new();
    for policy in &policies {
        for axis in &policy.axes {
            if let Some(existing) = axes.iter().find(|existing| existing.name == axis.name) {
                if existing.kind != axis.kind {
                    return Err(invalid("conflicting manifest goal axis kinds"));
                }
            } else {
                axes.push(axis.clone());
            }
        }
    }
    validate_axes(&axes)?;
    Ok((axes, policies))
}

pub(super) fn goal_definition_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<GoalDefinition> {
    let (mut axes, policies) = manifest_axes_in_txn(vault, txn)?;
    let record = read_current_goal_skill(vault, txn, skill)?;
    let goal_id = SkillGoalId::of(skill, &record)?.entity();
    let override_row = vault
        .store
        .vault_meta
        .get(txn, &goal_key(&goal_id))?
        .map(|raw| {
            serde_json::from_slice::<GoalOverride>(&raw)
                .map_err(|_| Error::CorruptedIndex("skill goal definition"))
        })
        .transpose()?;
    if let Some(definition) = &override_row {
        validate_axes(&definition.axes)
            .map_err(|_| Error::CorruptedIndex("skill goal definition"))?;
        if EntityId::from_hex(&definition.revision).is_err() {
            return Err(Error::CorruptedIndex("skill goal definition"));
        }
        for axis in &definition.axes {
            if let Some(existing) = axes.iter().find(|existing| existing.name == axis.name) {
                if existing.kind != axis.kind {
                    return Err(invalid("holder goal override conflicts with vault policy"));
                }
            } else {
                axes.push(axis.clone());
            }
        }
    }
    validate_axes(&axes)?;
    let mut hash = Sha256::new();
    hash.update(b"skill_optimize:effective_goal:v1\0");
    hash.update(
        serde_json::to_vec(&policies).map_err(|_| invalid("goal policy hash encode failed"))?,
    );
    if let Some(row) = override_row {
        hash.update(row.revision.as_bytes());
    }
    Ok(GoalDefinition {
        goal_id,
        revision: bytes_to_hex_lower(&hash.finalize()),
        axes,
    })
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
        let (required, _) = manifest_axes_in_txn(vault, txn)?;
        if !required.iter().all(|axis| axes.contains(axis)) {
            return Err(invalid(
                "holder goal override cannot widen or remove vault goal axes",
            ));
        }
        let record = read_current_goal_skill(vault, txn, skill)?;
        let goal_id = SkillGoalId::of(skill, &record)?.entity();
        let definition = GoalOverride {
            revision: vault.store.clock.entity_id()?.to_hex(),
            axes,
        };
        let encoded = serde_json::to_vec(&definition)
            .map_err(|_| invalid("goal definition encode failed"))?;
        vault
            .store
            .vault_meta
            .put(txn, &goal_key(&goal_id), &encoded)?;
        Ok(goal_definition_in_txn(vault, txn, skill)?.revision)
    })
}

pub(super) fn score_goal_axes(
    scorer: &dyn HeldOutReplayScorer,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
    definition: &GoalDefinition,
) -> Result<BTreeMap<String, GoalAxisScore>> {
    let declared = scorer.goal_axes(before)?;
    let scalar_only = declared.is_empty()
        && definition.axes.len() == 1
        && definition.axes[0].kind == GoalAxisKind::Primary;
    if !scalar_only && declared != definition.axes {
        return Err(invalid(
            "scorer goal axes differ from the authenticated goal definition",
        ));
    }
    let mut scored = BTreeMap::new();
    for axis in &definition.axes {
        let old = validate_score(if scalar_only {
            scorer.score(before)?
        } else {
            scorer.score_goal_axis(before, axis)?
        })?;
        let new = validate_score(if scalar_only {
            scorer.score(after)?
        } else {
            scorer.score_goal_axis(after, axis)?
        })?;
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
