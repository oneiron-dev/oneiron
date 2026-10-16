//! Goal-axis replay scores. A host supplies the goal axes; scores are normalized
//! to 0..=1 with larger always better (including cost axes).
use super::*;
use crate::learning::honesty::HONESTY_AXIS;
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
    /// The project goal record this goal is joined to, if any.
    pub(super) project: Option<super::project_goal::ProjectGoalJoin>,
}

/// A skill's effective goal, for a host scorer to declare the axes the gate
/// will ask it about ([`HeldOutReplayNotes::goal_axes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillEditGoal {
    pub goal_id: EntityId,
    pub revision: String,
    pub axes: Vec<GoalAxisSpec>,
    /// The joined project and the goal claim in force, if any.
    pub project: Option<(EntityId, EntityId)>,
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
        || !axes
            .iter()
            .any(|axis| axis.name == HONESTY_AXIS && axis.kind == GoalAxisKind::Floor)
    {
        return Err(invalid(
            "goal axes require a primary axis and the honesty floor",
        ));
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
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
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
    match axes.iter().find(|axis| axis.name == HONESTY_AXIS) {
        Some(axis) if axis.kind != GoalAxisKind::Floor => {
            return Err(invalid("honesty is a floor, never a payoff or cost axis"));
        }
        Some(_) => {}
        None => axes.push(GoalAxisSpec {
            name: HONESTY_AXIS.into(),
            kind: GoalAxisKind::Floor,
        }),
    }
    validate_axes(&axes)?;
    Ok((axes, policies))
}

/// The portable goal identity of `skill`, without resolving its axes.
pub(super) fn goal_id_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<EntityId> {
    let record = read_current_goal_skill(vault, txn, skill)?;
    Ok(SkillGoalId::of(skill, &record)?.entity())
}

pub(super) fn goal_definition_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<GoalDefinition> {
    let (mut axes, policies) = manifest_axes_in_txn(vault, txn)?;
    let goal_id = goal_id_in_txn(vault, txn, skill)?;
    // The project's goal record joins the vault's axes. A kind that disagrees
    // with policy is a conflict to resolve, not an axis to pick a side on.
    let project = super::project_goal::project_goal_in_txn(vault, txn, &goal_id)?;
    if let Some(join) = &project {
        for axis in super::project_goal::project_axes(&join.record) {
            if let Some(existing) = axes.iter().find(|existing| existing.name == axis.name) {
                if existing.kind != axis.kind {
                    return Err(invalid("project goal axis conflicts with vault policy"));
                }
            } else {
                axes.push(axis);
            }
        }
    }
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
    hash.update(b"skill_optimize:effective_goal:v2\0");
    hash.update(serde_json::to_vec(&axes).map_err(|_| invalid("goal axes hash encode failed"))?);
    hash.update(
        serde_json::to_vec(&policies).map_err(|_| invalid("goal policy hash encode failed"))?,
    );
    if let Some(row) = override_row {
        hash.update(row.revision.as_bytes());
    }
    // A new goal claim, or a rebind, is a new goal: the interview's revision
    // re-rules every pending ask and standing acceptance.
    if let Some(join) = &project {
        hash.update(b"\0project_goal\0");
        hash.update(join.project.as_bytes());
        hash.update(join.goal_claim.as_bytes());
        hash.update(join.binding_revision.as_bytes());
    }
    // The goal record holds its learned preferences (ARCH-0053 §10a): a new
    // rule, band or pick is a new goal revision.
    if let Some(preferences) = super::tradeoff::preferences_bytes_in_txn(vault, txn, &goal_id)? {
        hash.update(b"\0tradeoff_preferences\0");
        hash.update(preferences);
    }
    Ok(GoalDefinition {
        goal_id,
        revision: bytes_to_hex_lower(&hash.finalize()),
        axes,
        project,
    })
}

/// The effective goal the gate rules `skill` under.
/// # Errors
/// No trusted goal policy, an unreadable skill, override or project goal,
/// conflicting axes, or storage errors.
pub fn skill_edit_goal(vault: &Vault, skill: &EntityId) -> Result<SkillEditGoal> {
    let txn = vault.store.env.read_txn()?;
    let definition = goal_definition_in_txn(vault, &txn, skill)?;
    Ok(SkillEditGoal {
        goal_id: definition.goal_id,
        revision: definition.revision,
        axes: definition.axes,
        project: definition
            .project
            .map(|join| (join.project, join.goal_claim)),
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
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let (required, _) = manifest_axes_in_txn(vault, txn)?;
        if !required.iter().all(|axis| axes.contains(axis)) {
            return Err(invalid(
                "holder goal override cannot widen or remove vault goal axes",
            ));
        }
        let goal_id = goal_id_in_txn(vault, txn, skill)?;
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

/// `measured` holds the axes a bound live report measured; each is taken as
/// measured, never judged again.
pub(super) fn score_goal_axes(
    scorer: &dyn HeldOutReplayNotes,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
    definition: &GoalDefinition,
    mut measured: BTreeMap<String, GoalAxisScore>,
) -> Result<BTreeMap<String, GoalAxisScore>> {
    let task_axes: Vec<_> = definition
        .axes
        .iter()
        .filter(|axis| axis.name != HONESTY_AXIS)
        .cloned()
        .collect();
    let declared = scorer.goal_axes(before)?;
    let scalar_only =
        declared.is_empty() && task_axes.len() == 1 && task_axes[0].kind == GoalAxisKind::Primary;
    if !scalar_only && declared != task_axes {
        return Err(invalid(
            "scorer task axes differ from the authenticated goal definition",
        ));
    }
    let mut scored = BTreeMap::new();
    for axis in &definition.axes {
        if let Some(score) = measured.remove(&axis.name) {
            scored.insert(axis.name.clone(), score);
            continue;
        }
        let (old, new) = if axis.name == HONESTY_AXIS {
            let honesty = super::measurement::measure_honesty(scorer, before, after)?;
            (honesty.before, honesty.after)
        } else if scalar_only {
            (
                validate_score(scorer.score(before)?)?,
                validate_score(scorer.score(after)?)?,
            )
        } else {
            (
                validate_score(scorer.score_goal_axis(before, axis)?)?,
                validate_score(scorer.score_goal_axis(after, axis)?)?,
            )
        };
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
        || !axes
            .get(HONESTY_AXIS)
            .is_some_and(|axis| axis.kind == GoalAxisKind::Floor)
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
