//! Code-revision domain values and their constructors.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec::CODE_REVISION_HASH_LEN;
use crate::error::ArtifactError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeRevisionKind {
    Commit,
    Revert,
}

impl CodeRevisionKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Revert => "revert",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "commit" => Ok(Self::Commit),
            "revert" => Ok(Self::Revert),
            _ => Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision kind must be commit or revert",
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRevision {
    pub revision_id: EntityId,
    pub kind: CodeRevisionKind,
    pub session_id: EntityId,
    pub parent_revision_id: Option<EntityId>,
    pub reverted_to_revision_id: Option<EntityId>,
    pub provenance_claim_id: Option<EntityId>,
    pub finalized_at: u64,
}

impl CodeRevision {
    #[must_use]
    pub fn commit(revision_id: EntityId, session_id: EntityId, finalized_at: u64) -> Self {
        Self {
            revision_id,
            kind: CodeRevisionKind::Commit,
            session_id,
            parent_revision_id: None,
            reverted_to_revision_id: None,
            provenance_claim_id: None,
            finalized_at,
        }
    }

    #[must_use]
    pub fn commit_child(
        revision_id: EntityId,
        session_id: EntityId,
        parent_revision_id: EntityId,
        finalized_at: u64,
    ) -> Self {
        let mut revision = Self::commit(revision_id, session_id, finalized_at);
        revision.parent_revision_id = Some(parent_revision_id);
        revision
    }

    #[must_use]
    pub fn revert(
        revision_id: EntityId,
        session_id: EntityId,
        parent_revision_id: EntityId,
        reverted_to_revision_id: EntityId,
        finalized_at: u64,
    ) -> Self {
        Self {
            revision_id,
            kind: CodeRevisionKind::Revert,
            session_id,
            parent_revision_id: Some(parent_revision_id),
            reverted_to_revision_id: Some(reverted_to_revision_id),
            provenance_claim_id: None,
            finalized_at,
        }
    }

    #[must_use]
    pub fn with_provenance_claim_id(mut self, provenance_claim_id: EntityId) -> Self {
        self.provenance_claim_id = Some(provenance_claim_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRevisionFork {
    pub fork_session_id: EntityId,
    pub parent_session_id: EntityId,
    pub base_revision_id: EntityId,
    pub forked_at: u64,
}

impl CodeRevisionFork {
    #[must_use]
    pub fn new(
        fork_session_id: EntityId,
        parent_session_id: EntityId,
        base_revision_id: EntityId,
        forked_at: u64,
    ) -> Self {
        Self {
            fork_session_id,
            parent_session_id,
            base_revision_id,
            forked_at,
        }
    }
}

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
