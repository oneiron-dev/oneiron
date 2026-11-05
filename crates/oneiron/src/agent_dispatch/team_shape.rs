//! The team-shape skill's engine half (ARCH-0079 #planner, OF-541): the
//! closed shape vocabulary the planner commits to.
//!
//! The skill itself is a workflow skill (`skills/team-shape/SKILL.md`,
//! seeded into the hub like every bootstrap skill and revised by the loop
//! from receipts). The planner loads it at spawn through the ordinary pack
//! door and reads its content, its task-type tree and the planner card; the
//! estimates are the vault's (`team::planner_card`), never a parallel table
//! here. Its first lesson is *solo first*: models carry weak priors about
//! collaboration and a naive team often loses to one agent, so when one
//! agent already succeeds often, adding agents tends to hurt (RESEARCH-0366).
//! Solo is a shape, not a pattern skill.

use crate::entity_id::EntityId;
use crate::error::Result;

pub use crate::skill::team_shape_catalog::TEAM_SHAPE_SKILL_NAME;

/// The team-shape fallback namespace: the pure derived id the seeded tree,
/// the no-installed-skill case and the upkeep held-out partition read from.
/// A project's fork is found from the root in force by lineage.
///
/// The installed root is [`team_shape_root_in_txn`]: the installed holder
/// (loadable, or the Superseded lineage anchor) when the default-hub
/// skill is present, else this namespace.
///
/// # Errors
///
/// Only an id derivation failure.
pub fn team_shape_skill() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[TEAM_SHAPE_SKILL_NAME.as_bytes()],
    )
}

/// The team-shape root in force in `txn`: the installed default-hub holder
/// (loadable, or the Superseded lineage anchor), else the pure fallback
/// namespace [`team_shape_skill`]. Absent keeps today's seeded-tree,
/// fork, lineage and supersession behavior bit for bit.
///
/// # Errors
///
/// Storage errors, or an id derivation failure.
pub(crate) fn team_shape_root_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<EntityId> {
    if let Some(holder) = vault.default_hub_skill_in_txn(txn, TEAM_SHAPE_SKILL_NAME)? {
        return Ok(holder);
    }
    team_shape_skill()
}

/// The team-shape workflow default in its own read transaction: the
/// current active head in force for the vault, else the pure fallback
/// namespace [`team_shape_skill`] when no head exists (same absent
/// behavior as today). Workflow constructors read this, never the
/// frozen lineage anchor: the pack loader reads the exact id and
/// requires it loadable without following succession.
///
/// # Errors
///
/// Storage errors, or an id derivation failure.
pub(crate) fn team_shape_default(vault: &crate::Vault) -> Result<EntityId> {
    let txn = vault.store.env.read_txn()?;
    if let Some(head) = super::task_type_tree::team_shape_skill_in_force_in_txn(vault, &txn, None)?
    {
        return Ok(head);
    }
    team_shape_skill()
}

/// The skill's lessons, in the order the SKILL.md teaches them. The planner
/// puts the ones that fired into the spawn receipt's `why`.
pub const TEAM_SHAPE_LESSONS: [&str; 6] = [
    "solo first: when one agent already succeeds often, adding agents tends to hurt",
    "a team must beat solo at equal budget, not at ten times the spend",
    "committee narrows ideas: strong for researching what exists, late on generative work",
    "vote judges between finished options; debate only on request",
    "market needs a referee signed before the work: a test, a holdout, a pinned judge",
    "width has no count cap; the budget is the cap, and the plan states it before launch",
];

pub use crate::team::team_shape::{CoordinationPattern, TeamShape};
