//! Skill record vocabulary, defined below the skill behavior layer.

pub use crate::write_envelope::skill_record::identity::{
    SKILL_CONTENT_HASH_HEX_LEN, SKILL_TREE_HASH_DOMAIN, SKILL_TREE_PATH_MAX_BYTES,
    SkillContentHash, canonical_skill_tree_hash, cross_check_declared_content_hash,
};
