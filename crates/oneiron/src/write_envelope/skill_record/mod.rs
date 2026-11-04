//! Stored skill records, canonical identity, call contracts and pure validation.

pub(crate) mod admission;
pub(crate) mod codec;
pub(crate) mod identity;
pub(crate) mod lifecycle;
pub(crate) mod record;
pub(crate) mod resident;
pub(crate) mod role;
pub(crate) mod validate;

pub(crate) use admission::skill_loadable;
pub use codec::{decode_skill_record, encode_skill_record};
pub(crate) use codec::{is_legacy_opaque_skill_body, validate_skill_record_bytes};
pub use identity::{
    SKILL_CONTENT_HASH_HEX_LEN, SKILL_TREE_HASH_DOMAIN, SKILL_TREE_PATH_MAX_BYTES,
    SkillContentHash, canonical_skill_tree_hash, cross_check_declared_content_hash,
};
pub use lifecycle::{SkillGovernanceTier, SkillLifecycle};
pub use record::{
    SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_RECORD_BODY_KEYS,
    SKILL_VERSION_MAX_BYTES, SkillDependency, SkillRecord,
};
pub(crate) use resident::resident_of;
pub use role::{SkillCallContract, SkillRole};
pub(crate) use validate::{validate_hub_sync_skill_update, validate_skill_update};
