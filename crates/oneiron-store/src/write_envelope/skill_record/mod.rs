//! Stored skill records, canonical identity, call contracts and pure validation.

pub(crate) mod admission;
pub mod codec;
mod fork_pin;
pub mod identity;
pub mod lifecycle;
pub mod record;
pub mod resident;
pub mod role;
pub mod validate;

pub use admission::skill_loadable;
pub use codec::{decode_skill_record, encode_skill_record};
pub use codec::{is_legacy_opaque_skill_body, validate_skill_record_bytes};
pub use fork_pin::{fork_parent_pin, retain_fork_parent_pin};
pub use identity::{
    SKILL_CONTENT_HASH_HEX_LEN, SKILL_TREE_HASH_DOMAIN, SKILL_TREE_PATH_MAX_BYTES,
    SkillContentHash, canonical_skill_tree_hash, cross_check_declared_content_hash,
};
pub use lifecycle::{SkillGovernanceTier, SkillLifecycle};
pub use record::{
    SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_RECORD_BODY_KEYS,
    SKILL_VERSION_MAX_BYTES, SkillDependency, SkillRecord,
};
pub use resident::resident_of;
pub use role::{SkillCallContract, SkillRole};
pub use validate::{validate_hub_sync_skill_update, validate_skill_update};
