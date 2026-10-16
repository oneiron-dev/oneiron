//! The join between a skill's goal and a project's goal record (ARCH-0053
//! "The goal record"). The project's axes become gate axes, its stated
//! preferences become ladder rules, and its board is the responsible role a
//! tradeoff ask goes to, up through the parent boards to the vault owners.
//!
//! The human owns the goal record through the goal-intake interview. "The
//! loop may propose goal changes. It never makes them": a learned pick is
//! applied to this skill's own preferences at once, and reaches the project's
//! record only as a [`ProjectGoalRevisionProposal`] the interview may fold.
use std::collections::VecDeque;

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::workspace_roster::{GoalAxis, GoalPreference, GoalRecord};
use serde::{Deserialize, Serialize};

const BINDING_PREFIX: &[u8] = b"skill_optimize/project_goal/v1\0";
const PROPOSAL_PREFIX: &[u8] = b"skill_optimize/project_goal_proposal/v1\0";
const DISMISSED_PREFIX: &[u8] = b"skill_optimize/project_goal_dismissed/v1\0";
const LABEL: &str = "skill project goal row";
/// Bound on the parent walk; a lineage this deep ends at the vault owners.
const MAX_ROLE_WALK: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectGoalBinding {
    project: EntityId,
    bound_by: EntityId,
    /// Minted on every write, so a rebind is a new goal revision.
    revision: EntityId,
}

/// The project goal a skill's goal is joined to, read in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectGoalJoin {
    pub(super) project: EntityId,
    pub(super) goal_claim: EntityId,
    pub(super) binding_revision: EntityId,
    pub(super) record: GoalRecord,
}

fn binding_key(goal_id: &EntityId) -> Vec<u8> {
    [BINDING_PREFIX, goal_id.as_bytes()].concat()
}

fn proposal_key(project: &EntityId, id: &EntityId) -> Vec<u8> {
    [PROPOSAL_PREFIX, project.as_bytes(), id.as_bytes()].concat()
}

fn dismissed_key(project: &EntityId, question_digest: &str) -> Vec<u8> {
    [
        DISMISSED_PREFIX,
        project.as_bytes(),
        question_digest.as_bytes(),
    ]
    .concat()
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| invalid("project goal row encoding failed"))
}

/// The project goal joined to `goal_id`, if one is bound. A bound project
/// whose goal record cannot be read is an error, never an unbound goal: the
/// gate does not fall back to fewer axes than the human set.
pub(super) fn project_goal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    goal_id: &EntityId,
) -> Result<Option<ProjectGoalJoin>> {
    let Some(raw) = vault.store.vault_meta.get(txn, &binding_key(goal_id))? else {
        return Ok(None);
    };
    let binding: ProjectGoalBinding =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL))?;
    let (goal_claim, record) = vault
        .project_intake_goal_in_txn(txn, binding.project)?
        .ok_or(invalid("the skill's project has no readable goal record"))?;
    Ok(Some(ProjectGoalJoin {
        project: binding.project,
        goal_claim,
        binding_revision: binding.revision,
        record,
    }))
}

/// The project's axes as gate axes: primary, floor and cost, in that order.
pub(super) fn project_axes(record: &GoalRecord) -> Vec<GoalAxisSpec> {
    let kinded = |axes: &[GoalAxis], kind: GoalAxisKind| {
        axes.iter()
            .map(|axis| GoalAxisSpec {
                name: axis.name.clone(),
                kind,
            })
            .collect::<Vec<_>>()
    };
    let mut axes = kinded(&record.primary_axes, GoalAxisKind::Primary);
    axes.extend(kinded(&record.floor_axes, GoalAxisKind::Floor));
    axes.extend(kinded(&record.cost_axes, GoalAxisKind::Cost));
    axes
}

/// Join a skill's goal to a project's goal record, or unbind it with `None`.
/// The project must hold a goal record now. Returns the new goal revision:
/// every pending ask and standing acceptance is re-ruled under the join.
/// # Errors
/// An unauthenticated owner, a project with no goal record, project axes that
/// conflict with vault policy or are not gate axis identifiers, or storage
/// errors.
pub fn set_skill_goal_project(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    skill: &EntityId,
    project: Option<EntityId>,
) -> Result<String> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let key = binding_key(&goal_id_in_txn(vault, txn, skill)?);
        match project {
            Some(project) => {
                if vault.project_intake_goal_in_txn(txn, project)?.is_none() {
                    return Err(invalid(
                        "a skill goal joins only a project with a goal record",
                    ));
                }
                let binding = ProjectGoalBinding {
                    project,
                    bound_by: actor,
                    revision: vault.store.clock.entity_id()?,
                };
                vault.store.vault_meta.put(txn, &key, &encode(&binding)?)?;
            }
            None => {
                vault.store.vault_meta.delete(txn, &key)?;
            }
        }
        Ok(goal_definition_in_txn(vault, txn, skill)?.revision)
    })
}

/// The project a skill's goal is joined to, if any.
/// # Errors
/// An unreadable skill or binding row, or storage errors.
pub fn skill_goal_project(vault: &Vault, skill: &EntityId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let goal_id = goal_id_in_txn(vault, &txn, skill)?;
    let Some(raw) = vault.store.vault_meta.get(&txn, &binding_key(&goal_id))? else {
        return Ok(None);
    };
    let binding: ProjectGoalBinding =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL))?;
    Ok(Some(binding.project))
}

/// The project's stated preferences that name exact goal axes, as ladder
/// rules. "Prefer A over B" approves a vector that gains A and loses B, and
/// rejects one that gains B and loses A; `+` joins several axes on a side.
/// A preference that names no exact axis set stays prose for the leader.
pub(super) fn project_rules(
    join: &ProjectGoalJoin,
    axes: &[GoalAxisSpec],
) -> Vec<(TradeoffRule, String)> {
    let names = |side: &str| -> Option<BTreeSet<String>> {
        let set: BTreeSet<String> = side.split('+').map(|name| name.trim().to_owned()).collect();
        set.iter()
            .all(|name| axes.iter().any(|axis| &axis.name == name))
            .then_some(set)
    };
    let mut rules = Vec::new();
    for (index, preference) in join.record.preferences.iter().enumerate() {
        let (Some(prefer), Some(over)) = (names(&preference.prefer), names(&preference.over))
        else {
            continue;
        };
        if !prefer.is_disjoint(&over) {
            continue;
        }
        rules.push((
            TradeoffRule {
                gains: prefer.clone(),
                losses: over.clone(),
                choice: TradeoffChoice::Approve,
            },
            format!("project_preference:{index}"),
        ));
        rules.push((
            TradeoffRule {
                gains: over,
                losses: prefer,
                choice: TradeoffChoice::Reject,
            },
            format!("project_preference:{index}:reverse"),
        ));
    }
    rules
}

/// One rung of the responsible-role chain a tradeoff ask climbs. Live people
/// and live bound agents are members (ROLES-EVERYWHERE): a pick by either
/// becomes the role's preference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffRole {
    /// The person who authored the goal's tradeoff preferences.
    Author(EntityId),
    /// The live people on a project's effective board: the humans who set
    /// its goal.
    Board {
        project: EntityId,
        people: BTreeSet<EntityId>,
    },
    /// The vault's live owners, where every chain ends.
    VaultOwner(BTreeSet<EntityId>),
}

impl TradeoffRole {
    /// Whether `person` answers for this role.
    #[must_use]
    pub fn holds(&self, person: &EntityId) -> bool {
        match self {
            Self::Author(author) => author == person,
            Self::Board { people, .. } | Self::VaultOwner(people) => people.contains(person),
        }
    }

    pub(super) fn first(&self) -> Option<EntityId> {
        match self {
            Self::Author(author) => Some(*author),
            Self::Board { people, .. } | Self::VaultOwner(people) => people.first().copied(),
        }
    }
}

fn live_people_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: impl IntoIterator<Item = EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut people = BTreeSet::new();
    for id in ids {
        let agent = crate::write_envelope::WriteActor::new(id, crate::edge::EdgeActorClass::Agent);
        if crate::consent::person_is_live_in_txn(vault, txn, &id)?
            || vault.verify_write_actor_in_txn(txn, &agent).is_ok()
        {
            people.insert(id);
        }
    }
    Ok(people)
}

/// The chain a tradeoff ask climbs, read in one snapshot. A project-bound goal
/// starts at its project's effective board and walks up the parents; an
/// unbound goal starts at the person who authored its preferences. Every
/// chain ends at the vault's owners.
/// # Errors
/// A chain with no live person on it, or storage errors.
pub(super) fn responsible_roles_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<&ProjectGoalJoin>,
    author: Option<EntityId>,
) -> Result<Vec<TradeoffRole>> {
    let mut roles = Vec::new();
    match project {
        Some(join) => {
            let mut queue = VecDeque::from([join.project]);
            let mut seen = BTreeSet::new();
            while let Some(project) = queue.pop_front() {
                if seen.len() >= MAX_ROLE_WALK || !seen.insert(project) {
                    continue;
                }
                let Some((_, effective)) = vault.effective_project_in_txn(txn, project)? else {
                    continue;
                };
                let board = effective
                    .board
                    .iter()
                    .filter_map(|hex| EntityId::from_hex(hex).ok());
                let people = live_people_in_txn(vault, txn, board)?;
                if !people.is_empty() {
                    roles.push(TradeoffRole::Board { project, people });
                }
                queue.extend(
                    effective
                        .parents
                        .iter()
                        .filter_map(|hex| EntityId::from_hex(hex).ok()),
                );
            }
        }
        None => {
            if let Some(author) = author
                && crate::consent::person_is_live_in_txn(vault, txn, &author)?
            {
                roles.push(TradeoffRole::Author(author));
            }
        }
    }
    let owners = live_people_in_txn(vault, txn, crate::policy_model::owners_in_txn(vault, txn)?)?;
    if !owners.is_empty() {
        roles.push(TradeoffRole::VaultOwner(owners));
    }
    if roles.is_empty() {
        return Err(invalid(
            "no live person holds a role that can answer this tradeoff",
        ));
    }
    Ok(roles)
}

/// A preference the loop learned and proposes for a project's goal record.
/// It never writes the record: the goal-intake interview may fold it into
/// the next revision, and a new goal claim leaves it as history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalRevisionProposal {
    pub project: EntityId,
    /// The goal claim in force when the pick was made.
    pub goal_claim: EntityId,
    pub preference: GoalPreference,
    pub question_digest: String,
    pub picked_by: EntityId,
    pub at: u64,
}

/// A vault owner set a proposal aside under the goal claim in force. A
/// separate marker: the proposal row stays as history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectGoalDismissal {
    goal_claim: EntityId,
    dismissed_by: EntityId,
    at: u64,
}

/// Whether the proposal for `question_digest` was dismissed under `goal_claim`.
fn dismissed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
    goal_claim: &EntityId,
    question_digest: &str,
) -> Result<bool> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(txn, &dismissed_key(project, question_digest))?
    else {
        return Ok(false);
    };
    let row: ProjectGoalDismissal =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL))?;
    Ok(row.goal_claim == *goal_claim)
}

fn proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
) -> Result<Vec<ProjectGoalRevisionProposal>> {
    let prefix = [PROPOSAL_PREFIX, project.as_bytes()].concat();
    let mut rows = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(txn, &prefix)? {
        let (_, raw) = row?;
        rows.push(rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL))?);
    }
    Ok(rows)
}

/// Record a learned pick as a proposed preference for the joined project's
/// goal, unless the record already states it, it is already proposed under
/// the goal in force, or a vault owner dismissed this question's proposal
/// under that goal.
pub(super) fn propose_learned_preference_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    join: &ProjectGoalJoin,
    question: &SkillTradeoffQuestion,
    choice: TradeoffChoice,
    picked_by: EntityId,
    at: u64,
) -> Result<()> {
    let (prefer, over) = match choice {
        TradeoffChoice::Approve => (&question.gains, &question.losses),
        TradeoffChoice::Reject => (&question.losses, &question.gains),
    };
    let side = |axes: &BTreeSet<String>| axes.iter().cloned().collect::<Vec<_>>().join("+");
    let preference = GoalPreference {
        prefer: side(prefer),
        over: side(over),
        reason: format!(
            "learned from a tradeoff pick on skill proposal {}",
            question.proposal.to_hex()
        ),
    };
    let same = |stated: &GoalPreference| {
        stated.prefer == preference.prefer && stated.over == preference.over
    };
    let question_digest = question.digest()?;
    if join.record.preferences.iter().any(same)
        || proposals_in_txn(vault, txn, &join.project)?
            .iter()
            .any(|row| row.goal_claim == join.goal_claim && same(&row.preference))
        || dismissed_in_txn(
            vault,
            txn,
            &join.project,
            &join.goal_claim,
            &question_digest,
        )?
    {
        return Ok(());
    }
    let row = ProjectGoalRevisionProposal {
        project: join.project,
        goal_claim: join.goal_claim,
        preference,
        question_digest,
        picked_by,
        at,
    };
    let key = proposal_key(&join.project, &vault.store.clock.entity_id()?);
    vault.store.vault_meta.put(txn, &key, &encode(&row)?)?;
    Ok(())
}

/// The preferences the loop proposes for a project's goal in force and no
/// vault owner dismissed, oldest first, for the goal-intake interview to show
/// the human.
/// # Errors
/// An unreadable project goal or proposal row, or storage errors.
pub fn project_goal_revision_proposals(
    vault: &Vault,
    project: EntityId,
) -> Result<Vec<ProjectGoalRevisionProposal>> {
    let txn = vault.store.env.read_txn()?;
    project_goal_revision_proposals_in_txn(vault, &txn, project)
}

/// [`project_goal_revision_proposals`] in the caller's snapshot, for a reader
/// that reads the goal and its proposals together.
pub(crate) fn project_goal_revision_proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> Result<Vec<ProjectGoalRevisionProposal>> {
    let Some((goal_claim, _)) = vault.project_intake_goal_in_txn(txn, project)? else {
        return Ok(Vec::new());
    };
    let mut open = Vec::new();
    for row in proposals_in_txn(vault, txn, &project)? {
        if row.goal_claim == goal_claim
            && !dismissed_in_txn(vault, txn, &project, &goal_claim, &row.question_digest)?
        {
            open.push(row);
        }
    }
    Ok(open)
}

/// Set aside the proposal one tradeoff question made for a project's goal:
/// the interview no longer shows it, and the loop does not propose it again
/// under that goal. The proposal stays as history. Only a live vault owner
/// dismisses, as only one commits the goal record it would revise. The goal
/// claim is read again in the write; an identical retry writes nothing and
/// returns `false`.
/// # Errors
/// An unauthenticated owner, a goal claim other than the one in force, no
/// proposal for that question under it, or storage errors.
pub fn dismiss_project_goal_revision_proposal(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    project: EntityId,
    expected_goal: EntityId,
    question_digest: &str,
    at: u64,
) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let goal_claim = vault
            .project_intake_goal_in_txn(txn, project)?
            .map(|(goal_claim, _)| goal_claim);
        if goal_claim != Some(expected_goal) {
            return Err(invalid("the project's goal changed before the dismissal"));
        }
        if !proposals_in_txn(vault, txn, &project)?
            .iter()
            .any(|row| row.goal_claim == expected_goal && row.question_digest == question_digest)
        {
            return Err(invalid(
                "no revision proposal for that question under the goal in force",
            ));
        }
        if dismissed_in_txn(vault, txn, &project, &expected_goal, question_digest)? {
            return Ok(false);
        }
        let row = ProjectGoalDismissal {
            goal_claim: expected_goal,
            dismissed_by: actor,
            at,
        };
        vault.store.vault_meta.put(
            txn,
            &dismissed_key(&project, question_digest),
            &encode(&row)?,
        )?;
        Ok(true)
    })
}
