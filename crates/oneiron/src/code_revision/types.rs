//! Code-revision domain values and their constructors.

use crate::code_document::CodeDocumentFrontier;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use std::collections::BTreeMap;

use super::codec::CODE_REVISION_HASH_LEN;
use crate::error::ArtifactError;

pub use crate::store::code_revision_record::{CodeRevision, CodeRevisionFork, CodeRevisionKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodeRevisionIntegrityRecord {
    pub(super) revision_id: EntityId,
    pub(super) session_id: EntityId,
    pub(super) parent_revision_id: Option<EntityId>,
    pub(super) reverted_to_revision_id: Option<EntityId>,
    pub(super) provenance_claim_id: Option<EntityId>,
    pub(super) artifact_hash: [u8; CODE_REVISION_HASH_LEN],
    pub(super) parent_fold: Option<[u8; CODE_REVISION_HASH_LEN]>,
    pub(super) reverted_to_fold: Option<[u8; CODE_REVISION_HASH_LEN]>,
    pub(super) revision_fold: [u8; CODE_REVISION_HASH_LEN],
    pub(super) finalized_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodeRevisionFrontierRecord {
    pub(super) session_id: EntityId,
    pub(super) revision_id: EntityId,
    pub(super) revision_fold: [u8; CODE_REVISION_HASH_LEN],
    pub(super) finalized_at: u64,
}
