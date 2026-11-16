//! Wire types of a run's own skill pack load (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.pack.load`, on the caller's
//! attached live run. `oneiron` re-exports each item.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

use super::skills::SkillLibraryFile;

/// `vault.skills.pack.load`'s spec: the stored skill the caller's attached
/// run loads. The run, its lease and its agent come from the live-run
/// attachment, never from this request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackLoadRequest {
    /// The stored skill to load.
    pub skill: EntityId,
}

/// One pack load, stamped once on the run's attempt manifest.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillPackLoaded {
    /// The entity whose body loaded: the skill asked for, or the open
    /// proposal its exploration trial routed this attempt to.
    pub entity: EntityId,
    pub skill_id: String,
    pub version: String,
    /// The pack's exact files; `None` for a native record-only skill.
    pub files: Option<Vec<SkillLibraryFile>>,
}
