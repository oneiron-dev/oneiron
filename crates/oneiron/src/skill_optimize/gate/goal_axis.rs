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
/// Immutable local admission binding; unlike a predecessor body, it survives
/// a person's erasure of old instructions.
const GOAL_OWNER_PREFIX: &[u8] = b"skill_optimize/goal_owner/v1\0";

fn goal_key(skill: &EntityId) -> Vec<u8> {
    [GOAL_PREFIX, skill.as_bytes()].concat()
}

fn goal_owner_key(skill: &EntityId) -> Vec<u8> {
    [GOAL_OWNER_PREFIX, skill.as_bytes()].concat()
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

fn read_goal_lineage_skill(
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
        .ok_or(Error::CorruptedIndex("skill goal lineage entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
        return Err(invalid("skill goal lineage predecessor is not a skill"));
    }
    crate::skill::decode_skill_record(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
}

/// Resolve the immutable optimize-of chain to the human-governed skill identity.
/// A missing or malformed predecessor fails closed, never to the scalar default.
fn goal_owner_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, skill: &EntityId) -> Result<EntityId> {
    let mut id = *skill;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(id) {
            return Err(invalid("cyclic skill goal lineage"));
        }
        let record = read_goal_lineage_skill(vault, txn, &id)?;
        if let Some(raw) = vault.store.vault_meta.get(txn, &goal_owner_key(&id))? {
            let root = EntityId::from_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("skill goal owner binding"))?,
            )
            .map_err(|_| Error::CorruptedIndex("skill goal owner binding"))?;
            if root == id
                || provenance_str(&record, PROVENANCE_BIRTH_KEY).as_deref()
                    != Some(SKILL_OPTIMIZE_BIRTH_PATH)
            {
                return Err(Error::CorruptedIndex("skill goal owner binding"));
            }
            return Ok(root);
        }
        if provenance_str(&record, PROVENANCE_BIRTH_KEY).as_deref()
            != Some(SKILL_OPTIMIZE_BIRTH_PATH)
        {
            return Ok(id);
        }
        let parent = target_of(&record)?;
        let prior = read_goal_lineage_skill(vault, txn, &parent)?;
        if prior.skill_id != record.skill_id {
            return Err(invalid("skill goal lineage crosses skill identity"));
        }
        id = parent;
    }
}

/// Pin the admitted successor to its goal identity in the same transaction
/// as activation. The binding remains usable when historical bodies are erased.
pub(super) fn bind_successor_goal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    successor: &EntityId,
    predecessor: &EntityId,
) -> Result<()> {
    let root = goal_owner_in_txn(vault, txn, predecessor)?;
    let key = goal_owner_key(successor);
    if let Some(existing) = vault.store.vault_meta.get(txn, &key)? {
        if existing.as_ref() != root.as_bytes() {
            return Err(Error::CorruptedIndex("skill goal owner binding"));
        }
    } else {
        vault.store.vault_meta.put(txn, &key, root.as_bytes())?;
    }
    Ok(())
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
    let root = goal_owner_in_txn(vault, txn, skill)?;
    let override_row = vault
        .store
        .vault_meta
        .get(txn, &goal_key(&root))?
        .map(|raw| {
            serde_json::from_slice::<GoalDefinition>(&raw)
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
        let root = goal_owner_in_txn(vault, txn, skill)?;
        let definition = GoalDefinition {
            revision: vault.store.clock.entity_id()?.to_hex(),
            axes,
        };
        let encoded = serde_json::to_vec(&definition)
            .map_err(|_| invalid("goal definition encode failed"))?;
        vault
            .store
            .vault_meta
            .put(txn, &goal_key(&root), &encoded)?;
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
