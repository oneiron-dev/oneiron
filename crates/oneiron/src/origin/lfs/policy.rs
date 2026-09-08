//! Policy-only admission seam: path classes, admission verdicts, classifier trait and default.

use crate::entity_id::EntityId;
use crate::error::Result;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
/// What a repository path's bytes ARE, which is what decides where they live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LfsAssetClass {
    /// A large asset the repository carries: it belongs in the LFS plane.
    RepositoryLarge,
    /// An asset a build produces or consumes: it stays ordinary Git content.
    BuildRequired,
}

impl LfsAssetClass {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryLarge => "repository-large",
            Self::BuildRequired => "build-required",
        }
    }
}

/// What the caller must do with one pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LfsAdmission {
    /// The pointer's bytes belong in the LFS plane, and the pointer publishes
    /// only once those bytes are present.
    StoreInLfs,
    /// The pointer stays ordinary Git content: no LFS publication, and no
    /// durable ref attachment.
    KeepInGit,
}

impl LfsAdmission {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreInLfs => "store-in-lfs",
            Self::KeepInGit => "keep-in-git",
        }
    }
}

/// The classification seam.
///
/// A path is classified by WHAT IT IS. Implementations must never consult a
/// byte count: a size threshold would silently reclassify a build input the
/// day it grew, which is exactly the failure this seam exists to prevent.
pub trait LfsPathPolicy: Send + Sync {
    /// Classifies one repository path within one repository.
    fn classify(&self, repo_id: EntityId, path: &str) -> Result<LfsAssetClass>;
}

/// The v1 default: every path is [`LfsAssetClass::RepositoryLarge`].
///
/// A configuration-driven classifier belongs to the ticket that makes the
/// server configuration a claimed file; until then the honest default is the
/// one that stores what a push declared as LFS and refuses to guess.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRepositoryLargeLfsPathPolicy;

impl LfsPathPolicy for DefaultRepositoryLargeLfsPathPolicy {
    fn classify(&self, _repo_id: EntityId, _path: &str) -> Result<LfsAssetClass> {
        Ok(LfsAssetClass::RepositoryLarge)
    }
}
