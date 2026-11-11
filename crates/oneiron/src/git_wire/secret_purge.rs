//! The object collection of the owner's confirmed secret purge (FIX 7608
//! slice 10): once the purge moved a served store's refs to their masked
//! copies, every reflog entry is dropped and every object no ref reaches
//! is deleted, so a purged blob stays only where a ref or keep-ref still
//! reaches it. Both commands are pinned argvs with no caller argument, run
//! under the repository coordinator; nothing else in the engine calls
//! them.

use super::argv::FrozenGitArgv;
use super::{GitWire, GitWireRepo, GitWireResult, lock_repository};

impl GitWire<'_> {
    /// `reflog expire --expire=now --all`, then `gc --prune=now --quiet`, in
    /// `repo`, both under one hold of its coordinator.
    ///
    /// # Errors
    /// The coordinator, or either git command, failed.
    pub(crate) fn collect_purged_objects(&self, repo: &GitWireRepo) -> GitWireResult<()> {
        let _guard = lock_repository(&repo.common_dir)?;
        self.run_mutation(repo, &FrozenGitArgv::expire_reflogs())?;
        self.run_mutation(repo, &FrozenGitArgv::collect_objects())?;
        Ok(())
    }
}
