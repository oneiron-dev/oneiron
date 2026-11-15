//! Wire type of the owner's lifecycle door for a stored skill (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.lifecycle.set`. `oneiron`
//! re-exports it.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

use super::skills::SkillLibraryLifecycle;

/// `vault.skills.lifecycle.set`: the owner moves one stored skill to
/// `lifecycle` through the ordinary skill update law. Archiving
/// (`vault.skills.archive`), restoring an archived skill
/// (`vault.skills.restore`) and supersession keep their own doors.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLifecycleSetRequest {
    /// The stored skill.
    pub entity: EntityId,
    /// The lifecycle it moves to.
    pub lifecycle: SkillLibraryLifecycle,
}
