//! The proposal-delta channel a guest write becomes instead of a direct mutation.

use super::{
    contract::SandboxGuestTier,
    paths::{SandboxMount, SandboxVirtualPath},
};
use crate::{ClaimApprovalStatus, ClaimCandidate, EntityId, Error, Result};
use std::io::Read;

mod body;
pub use body::{SandboxProposalBody, SandboxProposalBodyReader, SandboxProposalBodyWriter};

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

/// One proposed file write under the virtual `/mnt` ABI. Its bytes are a
/// spooled body, never an in-memory copy of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileWriteProposal {
    pub path: SandboxVirtualPath,
    pub body: SandboxProposalBody,
}

impl SandboxFileWriteProposal {
    #[must_use]
    pub const fn new(path: SandboxVirtualPath, body: SandboxProposalBody) -> Self {
        Self { path, body }
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
    /// The same operation as [`crate::code_document::CodeFileEdit::between`],
    /// read from the body in frames: the shared prefix and suffix are
    /// compared where they lie, and only the changed span is read whole.
    pub fn lower_to_edit(&self, base: &[u8]) -> Result<Option<SandboxFileEditProposal>> {
        let body = &self.body;
        if body.is(base) {
            return Ok(None);
        }
        let old = std::str::from_utf8(base)
            .map_err(|_| Error::InvalidClaimBody("code edit base is not UTF-8"))?;
        let shared = usize::try_from(body.len()).map_or(base.len(), |len| len.min(base.len()));
        let mut frame = vec![0; LOWER_FRAME];
        let mut reader = body.reader();
        let mut prefix = 0;
        while prefix < shared {
            let want = LOWER_FRAME.min(shared - prefix);
            reader.read_exact(&mut frame[..want])?;
            let same = frame[..want]
                .iter()
                .zip(&base[prefix..prefix + want])
                .take_while(|(a, b)| a == b)
                .count();
            prefix += same;
            if same < want {
                break;
            }
        }
        // Equal bytes share their char boundaries, so one boundary in the
        // base is a boundary in the body too.
        while !old.is_char_boundary(prefix) {
            prefix -= 1;
        }
        let mut suffix = 0;
        while suffix < shared - prefix {
            let want = LOWER_FRAME.min(shared - prefix - suffix);
            let tail = body.read_range(body.len() - (suffix + want) as u64, want)?;
            let same = tail
                .iter()
                .rev()
                .zip(base[..base.len() - suffix].iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            suffix += same;
            if same < want {
                break;
            }
        }
        while !old.is_char_boundary(base.len() - suffix) {
            suffix -= 1;
        }
        let changed = usize::try_from(body.len() - (prefix + suffix) as u64)
            .map_err(|_| Error::InvalidClaimBody("code edit span exceeds host memory"))?;
        // The prefix and suffix are the base's own text; the body is UTF-8
        // exactly when its changed span is.
        let replacement = String::from_utf8(body.read_range(prefix as u64, changed)?)
            .map_err(|_| Error::InvalidClaimBody("code edit output is not UTF-8"))?;
        let expected = &old[prefix..old.len() - suffix];
        let start = old[..prefix].chars().count();
        Ok(Some(SandboxFileEditProposal {
            path: self.path.clone(),
            base_content_hash: *blake3::hash(base).as_bytes(),
            edit: crate::code_document::CodeFileEdit {
                path: self.path.relative_path().to_owned(),
                start,
                end: start + expected.chars().count(),
                expected: expected.to_owned(),
                replacement,
                new_path: None,
            },
        }))
    }
}

/// One comparison buffer while a write is lowered; never a size bound.
const LOWER_FRAME: usize = 1024 * 1024;

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
