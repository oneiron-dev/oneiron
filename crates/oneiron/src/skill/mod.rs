//! SKILL entity: lifecycle machine, governance tier, canonical identity, codec, and Vault doors.
//!
//! Owns the ARCH-0053 §6 lifecycle machine, the ONE-1448 governance-tier axis,
//! the ARCH-0053 §7 canonical content identity, and the SKILL record codec plus
//! its Vault doors. The three birth roads enter through `put_skill_record`:
//! `skill_convert`, `skill_hub`, and `skill_optimize`.

mod codec;
mod doors;
mod identity;
mod lifecycle;
mod record;
mod validate;

#[cfg(test)]
mod tests;

pub use self::codec::{decode_skill_record, encode_skill_record};
pub(crate) use self::codec::{is_legacy_opaque_skill_body, validate_skill_record_bytes};
pub use self::identity::{
    SKILL_CONTENT_HASH_HEX_LEN, SKILL_TREE_HASH_DOMAIN, SKILL_TREE_PATH_MAX_BYTES,
    SkillContentHash, canonical_skill_tree_hash, cross_check_declared_content_hash,
};
pub use self::lifecycle::{SkillGovernanceTier, SkillLifecycle};
pub use self::record::{
    SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_MAX_DEPENDENCIES,
    SKILL_RECORD_BODY_KEYS, SKILL_VERSION_MAX_BYTES, SkillDependency, SkillRecord,
};
pub(crate) use self::validate::{validate_hub_sync_skill_update, validate_skill_update};

// The flat skill.rs module provided these names to the sibling test module
// through `use super::*`: its own private crate/std import header, and every
// skill-internal item the tests name bare. After the directory split the seam
// re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::record::{
    KEY_APPROVAL_STATUS, KEY_CONFIDENCE, KEY_CONTENT_HASH, KEY_DEP_SKILL_ID, KEY_DEPENDENCIES,
    KEY_DESC, KEY_FORKED_FROM, KEY_GENERATED, KEY_HUMAN_AUTHORED, KEY_LIFECYCLE_STATUS,
    KEY_PROVENANCE, KEY_SKILL_ID, KEY_SOURCE, KEY_VERSION,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSource};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_SKILL;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
