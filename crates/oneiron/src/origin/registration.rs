//! Owner registration of a new, empty served origin. Git initialization is
//! staged outside the write transaction; only the final name is installed
//! while the caller's owner credential is live in the acting transaction.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitRefName, GitWire, lock_repository};

use super::smart_http::{
    ORIGIN_REPO_DIR_SUFFIX, origin_serving_root, validate_repo_name,
};

impl Vault {
    /// Registers one new bare repository under its smart-HTTP served name.
    /// Existing names are refused, never reinitialized or adopted. No ref or
    /// publication is created: the first push still takes the credential door.
    /// As for every unconfigured served repository, this vault is its origin
    /// until the owner cuts its authority epoch with `set_served_origin_authority`.
    pub fn register_served_origin_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        repo_name: &str,
        default_branch: &str,
    ) -> Result<EntityId> {
        owner.revalidate(self)?;
        validate_repo_name(repo_name)?;
        let branch = GitRefName::parse_full(format!("refs/heads/{default_branch}"))?;
        let root = origin_serving_root(self)?;
        // A staging name starts with '.', which no smart-HTTP route admits.
        let staged = tempfile::Builder::new()
            .prefix(".register-")
            .tempdir_in(&root)?;
        let args: Vec<String> = [
            "init".to_owned(),
            "--bare".to_owned(),
            "--object-format=sha1".to_owned(),
            "--ref-format=files".to_owned(),
            "--template=".to_owned(),
            format!("--initial-branch={}", &branch.as_str()["refs/heads/".len()..]),
            ".".to_owned(),
        ]
        .into();
        let initialized = crate::git_wire::run_bridged_git_argv(staged.path(), &args)?;
        if !initialized.success {
            return Err(Error::InvalidConfig(crate::git_wire::redact_bridged_failure(
                &args,
                initialized.exit_code,
                &initialized.stderr,
            )));
        }
        let destination = root.join(format!("{repo_name}{ORIGIN_REPO_DIR_SUFFIX}"));
        let _guard = lock_repository(&root)?;
        let txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        match std::fs::symlink_metadata(&destination) {
            Ok(_) => return Err(Error::ConcurrentWrite("origin repository name is already registered")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::rename(staged.path(), &destination)?;
        txn.commit()?;
        let identity = GitWire::new(self)?.repository_identity(&destination)?;
        super::lfs::lfs_repo_id(&identity.as_hex())
    }
}
