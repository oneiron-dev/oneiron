//! Canonical metadata values and codecs are defined in the store layer.

pub use crate::store::code_commit_metadata::CodeCommitMetadata;
pub(super) use crate::store::code_revision_record::commit_metadata::{
    from_value, to_value, validate,
};
