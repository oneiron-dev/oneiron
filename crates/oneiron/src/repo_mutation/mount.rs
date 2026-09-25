//! One immutable read path for committed head, recovery forks and codebase snapshots.
use super::git::{
    canonical_repo_ref_for_root, git_common_dir, resolve_mutable_repo_root,
    validate_relative_repo_path,
};
use super::oplog::{repo_mutation_repo_key_hash, repo_mutation_snapshot_key};
use super::snapshot::{StoredRepoSnapshotEntryKind, decode_snapshot, snapshot_recorded_for_repo};
use super::types::RepoForkHash;
use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::git_wire::{GitWire, lock_repository};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoMountRef {
    Head,
    Fork(RepoForkHash),
    Snapshot(EntityId),
}

/// An owned view. Callers cannot mutate either its bytes or its source.
#[derive(Debug, Clone)]
pub struct RepoMount {
    files: BTreeMap<String, Vec<u8>>,
}
impl RepoMount {
    pub const fn is_read_only(&self) -> bool {
        true
    }
    pub fn list_files(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }
    pub fn read_file(&self, path: &str) -> Result<Option<&[u8]>> {
        validate_relative_repo_path(path)?;
        Ok(self.files.get(path).map(Vec::as_slice))
    }
}
impl Vault {
    pub fn mount_repo_ref(&self, repo_ref: &RepoRef, reference: RepoMountRef) -> Result<RepoMount> {
        if let RepoMountRef::Snapshot(id) = reference {
            let mount = self
                .mount_codebase_snapshot(&id)?
                .ok_or(Error::EntityNotFound)?;
            if repo_mutation_repo_key_hash(&mount.snapshot().repo_ref)
                != repo_mutation_repo_key_hash(repo_ref)
            {
                return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                    "snapshot belongs to another repo",
                )));
            }
            let mut files = BTreeMap::new();
            for path in mount.list_files() {
                files.insert(
                    path.to_owned(),
                    mount
                        .read_file(path)?
                        .ok_or(Error::CorruptedIndex("snapshot file missing"))?,
                );
            }
            return Ok(RepoMount { files });
        }
        let root = resolve_mutable_repo_root(repo_ref)?;
        let canonical = canonical_repo_ref_for_root(repo_ref, &root)?;
        let _guard = lock_repository(&git_common_dir(&root)?)?;
        match reference {
            RepoMountRef::Head => {
                let git = GitWire::new(self)?;
                let repo = git.open_repo(canonical, &root)?;
                let head = git.resolve_commit(&repo, "HEAD")?;
                let files = crate::origin::tree::read_tree_files(&git, &repo, &head)?
                    .into_iter()
                    .map(|(path, file)| (path, file.content))
                    .collect();
                Ok(RepoMount { files })
            }
            RepoMountRef::Fork(hash) => {
                if !snapshot_recorded_for_repo(self, &canonical, hash)? {
                    return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                        "fork is not recorded for this repo",
                    )));
                }
                let txn = self.store.env.read_txn()?;
                let raw = self
                    .store
                    .vault_meta
                    .get(&txn, &repo_mutation_snapshot_key(hash))?
                    .ok_or(Error::EntityNotFound)?;
                if *blake3::hash(&raw).as_bytes() != hash
                    && super::support::sha256_bytes(&raw) != hash
                {
                    return Err(Error::CorruptedIndex("fork hash mismatch"));
                }
                let snapshot = decode_snapshot(&raw)?;
                let mut files = BTreeMap::new();
                for entry in snapshot.entries {
                    validate_relative_repo_path(&entry.path)?;
                    let bytes = match entry.kind {
                        StoredRepoSnapshotEntryKind::File => entry.content,
                        StoredRepoSnapshotEntryKind::Symlink => entry
                            .symlink_target
                            .ok_or(Error::CorruptedIndex("symlink target missing"))?
                            .into_bytes(),
                    };
                    if files.insert(entry.path, bytes).is_some() {
                        return Err(Error::CorruptedIndex("duplicate fork path"));
                    }
                }
                Ok(RepoMount { files })
            }
            RepoMountRef::Snapshot(_) => unreachable!("handled before local repo access"),
        }
    }
}
