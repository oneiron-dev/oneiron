//! The proposal-delta channel a guest write becomes instead of a direct mutation.

use super::{
    contract::SandboxGuestTier,
    paths::{SandboxMount, SandboxVirtualPath},
};
use crate::{ClaimApprovalStatus, ClaimCandidate, EntityId, Error, Result};

/// Single write intent emitted by a propose-only guest.
#[derive(Debug, Clone, PartialEq)]
pub enum SandboxProposalWrite {
    FileWrite(SandboxFileWriteProposal),
    FileEdit(SandboxFileEditProposal),
    FileDelete(SandboxFileDeleteProposal),
    FileRename(SandboxFileRenameProposal),
    DirectoryOpaque(SandboxDirectoryOpaqueProposal),
    ClaimCandidate(SandboxClaimProposal),
}

impl SandboxProposalWrite {
    #[must_use]
    pub const fn kind(&self) -> SandboxProposalKind {
        match self {
            Self::FileWrite(_) => SandboxProposalKind::FileWrite,
            Self::FileEdit(_) => SandboxProposalKind::FileEdit,
            Self::FileDelete(_) => SandboxProposalKind::FileDelete,
            Self::FileRename(_) => SandboxProposalKind::FileRename,
            Self::DirectoryOpaque(_) => SandboxProposalKind::DirectoryOpaque,
            Self::ClaimCandidate(_) => SandboxProposalKind::ClaimCandidate,
        }
    }
}

/// Coarse proposal kind used for review routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxProposalKind {
    FileWrite,
    FileEdit,
    FileDelete,
    FileRename,
    DirectoryOpaque,
    ClaimCandidate,
}

impl SandboxProposalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileWrite => "file_write",
            Self::FileEdit => "file_edit",
            Self::FileDelete => "file_delete",
            Self::FileRename => "file_rename",
            Self::DirectoryOpaque => "directory_opaque",
            Self::ClaimCandidate => "claim_candidate",
        }
    }
}

/// One proposed file write under the virtual `/mnt` ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileWriteProposal {
    pub path: SandboxVirtualPath,
    pub bytes: Vec<u8>,
}

impl SandboxFileWriteProposal {
    #[must_use]
    pub const fn new(path: SandboxVirtualPath, bytes: Vec<u8>) -> Self {
        Self { path, bytes }
    }
}

/// A requested removal of a file. Review resolves document identity from this path;
/// this does not erase the file's historical revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileDeleteProposal {
    pub path: SandboxVirtualPath,
}

/// A requested path move of one document, preserving its identity at review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileRenameProposal {
    pub from: SandboxVirtualPath,
    pub to: SandboxVirtualPath,
}

/// Overlay directory hides lower-layer entries not replaced in the upper layer.
/// Review must resolve the affected lower files at the pinned base frontier;
/// this marker alone never grants authority to delete a directory or its history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDirectoryOpaqueProposal {
    pub path: SandboxVirtualPath,
}

/// A whole-file guest output lowered against the exact bytes supplied at boot.
/// Review sees a bounded document operation, never an implicit replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileEditProposal {
    pub path: SandboxVirtualPath,
    pub base_content_hash: [u8; 32],
    pub edit: crate::code_document::CodeFileEdit,
}
impl SandboxFileWriteProposal {
    pub fn lower_to_edit(&self, base: &[u8]) -> Result<Option<SandboxFileEditProposal>> {
        if base == self.bytes {
            return Ok(None);
        }
        let old = std::str::from_utf8(base)
            .map_err(|_| Error::InvalidClaimBody("code edit base is not UTF-8"))?;
        let new = std::str::from_utf8(&self.bytes)
            .map_err(|_| Error::InvalidClaimBody("code edit output is not UTF-8"))?;
        Ok(Some(SandboxFileEditProposal {
            path: self.path.clone(),
            base_content_hash: *blake3::hash(base).as_bytes(),
            edit: crate::code_document::CodeFileEdit::between(self.path.relative_path(), old, new),
        }))
    }
}

/// One proposed memory claim from a propose-only guest.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxClaimProposal {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
}

impl SandboxClaimProposal {
    #[must_use]
    pub fn new(id: EntityId, candidate: ClaimCandidate) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
        }
    }
}

/// Reviewable delta emitted for one foreign/untrusted write intent.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxProposalDelta {
    id: EntityId,
    tier: SandboxGuestTier,
    approval: ClaimApprovalStatus,
    write: SandboxProposalWrite,
}

impl SandboxProposalDelta {
    pub(super) fn new(tier: SandboxGuestTier, write: SandboxProposalWrite) -> Result<Self> {
        if !matches!(
            tier,
            SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted
        ) {
            return Err(Error::InvalidClaimBody(
                "sandbox proposal deltas are only for propose-only tiers",
            ));
        }

        // Proposal variants are public input too, not only backend output.
        // Validate at this door so a caller cannot bypass the backend's checks.
        match &write {
            SandboxProposalWrite::FileDelete(delete) if !workspace_file(&delete.path) => {
                return Err(Error::InvalidClaimBody(
                    "sandbox deletion must name a workspace file",
                ));
            }
            SandboxProposalWrite::FileRename(rename)
                if !workspace_file(&rename.from)
                    || !workspace_file(&rename.to)
                    || rename.from == rename.to =>
            {
                return Err(Error::InvalidClaimBody(
                    "sandbox rename must name distinct workspace files",
                ));
            }
            SandboxProposalWrite::DirectoryOpaque(opaque)
                if opaque.path.mount() != SandboxMount::Workspace =>
            {
                return Err(Error::InvalidClaimBody(
                    "opaque directory must be in workspace",
                ));
            }
            _ => {}
        }

        Ok(Self {
            id: EntityId::now(),
            tier,
            approval: ClaimApprovalStatus::Proposed,
            write,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SandboxProposalKind {
        self.write.kind()
    }

    #[must_use]
    pub const fn id(&self) -> EntityId {
        self.id
    }

    #[must_use]
    pub const fn tier(&self) -> SandboxGuestTier {
        self.tier
    }

    #[must_use]
    pub const fn approval(&self) -> ClaimApprovalStatus {
        self.approval
    }

    #[must_use]
    pub const fn write(&self) -> &SandboxProposalWrite {
        &self.write
    }
}

fn workspace_file(path: &SandboxVirtualPath) -> bool {
    path.mount() == SandboxMount::Workspace && !path.relative_path().is_empty()
}
