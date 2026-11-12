//! Policy-only admission seam: path classes, admission verdicts, classifier trait and default.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
/// What a repository path's bytes ARE: the owner's word for a path, kept in
/// the origin's LFS path policy (`vault.code.origin.lfs_path_policy.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LfsAssetClass {
    /// A large asset the repository carries: it belongs in the LFS plane.
    RepositoryLarge,
    /// An asset a build produces or consumes: its bytes must be there
    /// wherever the repository builds, so a pushed LFS pointer to it keeps
    /// its object, required and attached, like a repository-large one
    /// (Engine CODECUSTODY-LFS Q2 = A). A file pushed as ordinary Git bytes
    /// stays ordinary Git bytes; nothing is rewritten.
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

/// What the caller must do with one pushed pointer, whatever its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsAdmission {
    /// The pointer's bytes belong in the LFS plane, and the pointer publishes
    /// only once those bytes are present.
    StoreInLfs,
}

impl LfsAdmission {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreInLfs => "store-in-lfs",
        }
    }
}

/// The classification seam.
///
/// A path is classified by WHAT IT IS. Implementations must never consult a
/// byte count: a size threshold would silently reclassify a build input the
/// day it grew, which is exactly the failure this seam exists to prevent.
pub trait LfsPathPolicy: Send + Sync {
    /// Classifies one repository's exact path bytes, without a text conversion.
    fn classify(&self, repo_id: EntityId, path: &[u8]) -> Result<LfsAssetClass>;
}

/// The default: every path is [`LfsAssetClass::RepositoryLarge`], as is
/// every path no rule of an origin's owner-set path policy matches.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRepositoryLargeLfsPathPolicy;

impl LfsPathPolicy for DefaultRepositoryLargeLfsPathPolicy {
    fn classify(&self, _repo_id: EntityId, _path: &[u8]) -> Result<LfsAssetClass> {
        Ok(LfsAssetClass::RepositoryLarge)
    }
}
