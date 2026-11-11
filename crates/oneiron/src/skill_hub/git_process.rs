//! Private disposable object store; all Git processes use the GitWire boundary.
use crate::{
    entity_id::EntityId,
    error::{ArtifactError, CodeError, Error, Result},
};
use std::{fs, path::PathBuf};
pub(super) struct GitScratch {
    root: PathBuf,
    /// Every call runs the local-only profile of a local folder hub (FIX 21922).
    local_only: bool,
}
impl GitScratch {
    pub(super) fn new() -> Result<Self> {
        Self::new_with_mode(false)
    }
    /// A scratch store whose every Git call reads a local repository only.
    pub(super) fn new_local() -> Result<Self> {
        Self::new_with_mode(true)
    }
    fn new_with_mode(local_only: bool) -> Result<Self> {
        let root = fs::canonicalize(std::env::temp_dir())?
            .join(format!("oneiron-hub-{}", EntityId::now().to_hex()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root)?;
        let scratch = Self { root, local_only };
        scratch.run(&["init", "--bare", "--quiet", "repo"], 4096)?;
        Ok(scratch)
    }
    pub(super) fn run(&self, args: &[&str], limit: usize) -> Result<Vec<u8>> {
        let read = if self.local_only {
            crate::git_wire::read_local_hub_git(&self.root, args, limit)
        } else {
            crate::git_wire::read_hub_git(&self.root, args, limit)
        };
        read.map_err(|error| {
            // Carry the inner refusal text: it names the op and the cause.
            let detail = match error {
                Error::Code(CodeError::RepoMutationFailed(detail)) => detail,
                other => other.to_string(),
            };
            Error::Artifact(ArtifactError::SkillHubGitRead(format!(
                "Git package read failed or exceeded its budget: {detail}"
            )))
        })
    }
}
impl Drop for GitScratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
