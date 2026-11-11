//! A local folder hub (FIX 21922): a Git object database in a directory on
//! the engine host, read at one pinned commit through the Git object reader
//! under the local-only Git profile. No checkout, no working-tree read, no
//! plain-tree read and no network: a commit or object the directory lacks
//! fails the read. It serves skills only; packs and the model catalog refuse.
use super::git_fetch::GitEndpointSkillHubAdapter;
use super::{HubIndexEntry, HubPackage, HubRef, SkillHubAdapter, SkillHubKind};
use crate::{entity_id::EntityId, error::Result};

/// The refusal of every pack door and of the model catalog on a local folder hub.
pub(super) const LOCAL_DIR_SKILLS_ONLY: &str = "a local folder hub serves skills only";

/// The refusal of every local folder hub policy or pin but a pinned commit.
pub(super) const LOCAL_DIR_COMMIT_ONLY: &str =
    "a local folder hub reads only a pinned-commit ref at a full commit";

/// The transport of a configured local folder hub. The injected
/// [`super::LocalDirSkillHubAdapter`] holds packages in memory; this one reads
/// the configured directory's Git objects. It does not implement the pack
/// source contract, so no pack door can read through it.
pub struct LocalDirEndpointSkillHubAdapter {
    git: GitEndpointSkillHubAdapter,
}

impl LocalDirEndpointSkillHubAdapter {
    /// `endpoint` must name an existing absolute directory and
    /// `expected_commit` a full commit id. The stored endpoint is the
    /// canonical directory, the one owner configuration stores.
    pub fn new(hub_id: EntityId, endpoint: &str, expected_commit: &str) -> Result<Self> {
        Ok(Self {
            git: GitEndpointSkillHubAdapter::new_local(hub_id, endpoint, expected_commit)?,
        })
    }

    /// The commit every read resolves to, for tracking and provenance.
    #[must_use]
    pub fn resolved_commit(&self) -> &str {
        self.git.resolved_commit()
    }
}

impl SkillHubAdapter for LocalDirEndpointSkillHubAdapter {
    fn hub_id(&self) -> EntityId {
        self.git.hub_id()
    }

    fn kind(&self) -> SkillHubKind {
        SkillHubKind::LocalDir
    }

    fn endpoint(&self) -> Option<&str> {
        self.git.endpoint()
    }

    /// The package at the configured commit; any other pin refuses.
    fn fetch_package(&self, reference: &HubRef) -> Result<HubPackage> {
        self.git.fetch_package(reference)
    }

    /// The skill folders at the configured commit, read from local objects.
    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        self.git.discover()
    }
}
