//! Private disposable object store; all Git processes use the GitWire boundary.
use crate::{
    entity_id::EntityId,
    error::{ArtifactError, CodeError, Error, Result},
};
use std::{fs, path::PathBuf};
pub(super) struct GitScratch {
    root: PathBuf,
}
impl GitScratch {
    pub(super) fn new() -> Result<Self> {
        let root = fs::canonicalize(std::env::temp_dir())?
            .join(format!("oneiron-hub-{}", EntityId::now().to_hex()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root)?;
        let scratch = Self { root };
        scratch.run(&["init", "--bare", "--quiet", "repo"], 4096)?;
        Ok(scratch)
    }
    pub(super) fn run(&self, args: &[&str], limit: usize) -> Result<Vec<u8>> {
        crate::git_wire::read_hub_git(&self.root, args, limit).map_err(|error| {
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
