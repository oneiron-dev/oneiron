//! Stored skill records, canonical identity, call contracts and pure validation.

pub(crate) mod admission;
pub(crate) mod identity;
pub(crate) mod record;
pub(crate) mod codec;
pub(crate) mod lifecycle;
pub(crate) mod role;
pub(crate) mod validate;
pub(crate) mod resident;

pub use identity::{
    SKILL_CONTENT_HASH_HEX_LEN, SKILL_TREE_PATH_MAX_BYTES, SKILL_TREE_HASH_DOMAIN, SkillContentHash, canonical_skill_tree_hash, cross_check_declared_content_hash,
};
pub use record::{
    SKILL_RECORD_BODY_KEYS, SKILL_DEPENDENCY_KEYS, SKILL_ID_MAX_BYTES, SKILL_VERSION_MAX_BYTES, SKILL_DESC_MAX_BYTES, SkillDependency, SkillRecord,
};
pub use codec::{
    encode_skill_record, decode_skill_record,
};
pub use lifecycle::{
    SkillLifecycle, SkillGovernanceTier,
};
pub use role::{
    SkillRole, SkillCallContract,
};
pub(crate) use codec::{is_legacy_opaque_skill_body, validate_skill_record_bytes};
pub(crate) use resident::resident_of;
pub(crate) use validate::{validate_hub_sync_skill_update, validate_skill_update};
pub(crate) use admission::skill_loadable;
