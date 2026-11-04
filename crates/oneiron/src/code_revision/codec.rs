//! Code revision and fork codecs are defined with their record values.

pub(crate) use crate::store::code_revision_record::codec::CODE_REVISION_CLAIM_PREDICATE;
pub use crate::store::code_revision_record::codec::{
    CODE_REVISION_FORK_KEYS, CODE_REVISION_RECORD_KEYS, decode_code_revision,
    decode_code_revision_fork, encode_code_revision, encode_code_revision_fork,
};
pub(super) use crate::store::code_revision_record::codec::{
    CODE_REVISION_HASH_LEN, KEY_FINALIZED_AT, KEY_PARENT_REVISION_ID, KEY_PROVENANCE_CLAIM_ID,
    KEY_REVERTED_TO_REVISION_ID, KEY_REVISION_ID, KEY_SESSION_ID, encode_value, entity_value,
    hash_from_value, optional_entity_from_value, optional_entity_value, optional_hash_from_value,
    optional_hash_value, u64_value, validate_code_revision_fork_shape,
    validate_code_revision_shape,
};
