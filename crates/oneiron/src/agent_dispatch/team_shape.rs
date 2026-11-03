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

/// The installed team-shape skill: the bootstrap-derived vault skill. A
/// project's fork is found from it by lineage.
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
