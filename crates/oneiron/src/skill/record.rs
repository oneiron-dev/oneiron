//! Skill record vocabulary, defined below the skill behavior layer.

pub(super) use crate::write_envelope::skill_record::record::{
    KEY_APPROVAL_STATUS, KEY_CALL, KEY_CONFIDENCE, KEY_CONTENT_HASH, KEY_DEP_MIN_VERSION,
    KEY_DEP_SKILL_ID, KEY_DEPENDENCIES, KEY_DESC, KEY_FORKED_FROM, KEY_GENERATED,
    KEY_GOVERNANCE_TIER, KEY_HUMAN_AUTHORED, KEY_LIFECYCLE_STATUS, KEY_PROVENANCE, KEY_ROLE,
    KEY_SKILL_ID, KEY_SOURCE, KEY_VERSION,
};
pub use crate::write_envelope::skill_record::record::{
    SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_RECORD_BODY_KEYS,
    SKILL_VERSION_MAX_BYTES, SkillDependency, SkillRecord,
};
