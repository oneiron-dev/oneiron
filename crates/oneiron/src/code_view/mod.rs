//! Per-agent file views over codebase blobs, with one owned shared service set.
use crate::build_cache::{ActionResult, BuildAction, BuildCache, BuildCacheResult, CachedBuildLeg};
use crate::checkout::CheckoutTaskClass;
use crate::codebase::CodebaseSnapshotMount;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod language_server;
pub use language_server::{LanguageServer, SharedLanguageServer, StdioLanguageServer};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisibleFilePolicy {
    pub version: u32,
    pub include_prefixes: Vec<String>,
    pub exclude_prefixes: Vec<String>,
}
impl VisibleFilePolicy {
    pub fn selects(&self, path: &str) -> Result<bool> {
        relative(path)?;
        if self.version != 1 {
            return Err(Error::InvalidClaimBody(
                "unknown visible-file policy version",
            ));
        }
        Ok(self.include_prefixes.iter().any(|p| path.starts_with(p))
            && !self.exclude_prefixes.iter().any(|p| path.starts_with(p)))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ViewReceipt {
    #[serde(with = "entity_serde")]
    pub view_id: EntityId,
    #[serde(with = "entity_serde")]
    pub actor: EntityId,
    pub fork_hash: [u8; 32],
    pub files: BTreeMap<String, [u8; 32]>,
}
/// Owns a private host directory. Views are immutable files, not writable links
/// to canonical blobs. Writers submit document operations through the code door.
pub struct CodeViewSet<'a> {
    vault: &'a Vault,
    root: PathBuf,
    materialization: std::sync::Mutex<()>,
}
impl<'a> CodeViewSet<'a> {
    pub fn create(vault: &'a Vault, root: &Path) -> Result<Self> {
        // create_dir, not create_dir_all: never adopt a caller-controlled tree.
        std::fs::create_dir(root)?;
        let root = root.canonicalize()?;
        std::fs::create_dir(root.join("blobs"))?;
        std::fs::create_dir(root.join("views"))?;
        Ok(Self {
            vault,
            root,
            materialization: std::sync::Mutex::new(()),
        })
    }
    pub fn materialize(
        &self,
        mount: &CodebaseSnapshotMount<'_>,
        actor: EntityId,
        policy: &VisibleFilePolicy,
    ) -> Result<ViewReceipt> {
        let _guard = self
            .materialization
            .lock()
            .map_err(|_| Error::InvariantViolation("view lock poisoned"))?;
        let view_id = EntityId::now();
        let destination = self.root.join("views").join(view_id.to_hex());
        std::fs::create_dir(&destination)?;
        let mut files = BTreeMap::new();
        for file in &mount.snapshot().files {
            if !policy.selects(&file.path)? {
                continue;
            }
            let bytes = mount
                .read_file(&file.path)?
                .ok_or(Error::CorruptedIndex("view blob absent"))?;
            if *blake3::hash(&bytes).as_bytes() != file.content_hash {
                return Err(Error::CorruptedIndex("view blob hash mismatch"));
            }
            let blob = self
                .root
                .join("blobs")
                .join(crate::entity_id::bytes_to_hex_lower(&file.content_hash));
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&blob)
            {
                Ok(mut output) => {
                    use std::io::Write;
                    output.write_all(&bytes)?;
                    output.sync_all()?;
                    let mut permissions = output.metadata()?.permissions();
                    permissions.set_readonly(true);
                    output.set_permissions(permissions)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if std::fs::symlink_metadata(&blob)?.file_type().is_symlink()
                        || std::fs::read(&blob)? != bytes
                    {
                        return Err(Error::CorruptedIndex("view blob was modified"));
                    }
                }
                Err(error) => return Err(error.into()),
            }
            let target = destination.join(&file.path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Same-user tools can chmod read-only files. Never share an inode
            // with the canonical blob or another view. fs::copy may use CoW.
            if target.try_exists()? {
                return Err(Error::InvalidClaimBody("duplicate view path"));
            }
            std::fs::copy(&blob, &target)?;
            files.insert(file.path.clone(), file.content_hash);
        }
        let receipt = ViewReceipt {
            view_id,
            actor,
            fork_hash: mount.snapshot().fork_hash,
            files,
        };
        let bytes = rmp_serde::to_vec_named(&receipt)
            .map_err(|_| Error::InvalidClaimBody("view receipt encode"))?;
        self.vault.with_write_txn(|txn| {
            self.vault
                .store
                .vault_meta
                .put(txn, &receipt_key(view_id), &bytes)?;
            Ok(())
        })?;
        Ok(receipt)
    }
    pub fn receipt(&self, id: EntityId) -> Result<Option<ViewReceipt>> {
        let txn = self.vault.store.env.read_txn()?;
        self.vault
            .store
            .vault_meta
            .get(&txn, &receipt_key(id))?
            .map(|bytes| {
                rmp_serde::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("view receipt decode"))
            })
            .transpose()
    }
    pub fn view_path(&self, id: EntityId) -> Result<PathBuf> {
        if self.receipt(id)?.is_none() {
            return Err(Error::InvalidClaimBody("unknown view"));
        }
        Ok(self.root.join("views").join(id.to_hex()))
    }
    pub fn build(
        &self,
        id: EntityId,
        cache: &BuildCache<'_>,
        class: CheckoutTaskClass,
        action: &BuildAction,
        execute: impl FnOnce(&Path, &Vault) -> BuildCacheResult<ActionResult>,
    ) -> BuildCacheResult<CachedBuildLeg> {
        let receipt = self
            .receipt(id)?
            .ok_or(Error::InvalidClaimBody("unknown view"))?;
        if receipt.fork_hash != action.input_root.fork_hash {
            return Err(crate::build_cache::BuildCacheError::InvalidAction(
                "view action root mismatch",
            ));
        }
        let path = self.view_path(id)?;
        // Tools are trusted host code, not sandboxed guests. Still reject
        // accidental input mutation BEFORE a miss can enter the shared cache.
        verify_view_inputs(&path, &receipt)?;
        let leg = cache.run_leg(class, action, |vault| {
            let result = execute(&path, vault)?;
            verify_view_inputs(&path, &receipt)?;
            Ok(result)
        })?;
        verify_view_inputs(&path, &receipt)?;
        // Materialize admitted account artifact versions for every view,
        // including a cache hit that never invoked the compiler.
        for (output, reference) in &leg.cached.result.outputs {
            relative(output.as_str())?;
            if receipt.files.contains_key(output.as_str()) {
                return Err(Error::InvalidClaimBody("build output overlaps an input").into());
            }
            let bytes = cache
                .artifact_vault()
                .read_blob_artifact_version(reference.artifact_id(), reference.version())?
                .ok_or(Error::CorruptedIndex("cached output unavailable"))?;
            let target = path.join(output.as_str());
            // Reject any output parent symlink rather than following it out of the view.
            let mut parent = path.clone();
            let parts: Vec<_> = output.as_str().split('/').collect();
            for part in &parts[..parts.len() - 1] {
                parent.push(part);
                if parent.try_exists()? {
                    if !std::fs::symlink_metadata(&parent)?.is_dir() {
                        return Err(Error::InvalidClaimBody("unsafe build output parent").into());
                    }
                } else {
                    std::fs::create_dir(&parent)?;
                }
            }
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !std::fs::symlink_metadata(&target)?.is_file()
                        || std::fs::read(&target)? != bytes
                    {
                        return Err(Error::InvalidClaimBody("build output collision").into());
                    }
                }
                Err(error) => return Err(Error::from(error).into()),
            }
        }
        let key = [
            b"code_view:build:v1:".as_slice(),
            id.as_bytes(),
            leg.cached.action_key.as_bytes(),
        ]
        .concat();
        let outcome = serde_json::to_vec(&serde_json::json!({"hit":leg.receipt.cache_hit,"producer":leg.receipt.producer_ref,"action":leg.cached.action_key.to_hex()})).map_err(|_| Error::InvalidClaimBody("view build receipt encode"))?;
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.put(txn, &key, &outcome)?;
            Ok(())
        })?;
        Ok(leg)
    }
}
fn verify_view_inputs(root: &Path, receipt: &ViewReceipt) -> Result<()> {
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(Error::CorruptedIndex("view root was replaced"));
    }
    for (path, expected) in &receipt.files {
        relative(path)?;
        let mut target = root.to_path_buf();
        let parts: Vec<_> = path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            target.push(part);
            if !std::fs::symlink_metadata(&target)?.is_dir() {
                return Err(Error::CorruptedIndex("view input parent was replaced"));
            }
        }
        target.push(parts[parts.len() - 1]);
        if !std::fs::symlink_metadata(&target)?.is_file()
            || blake3::hash(&std::fs::read(&target)?).as_bytes() != expected
        {
            return Err(Error::CorruptedIndex("view input was modified"));
        }
    }
    Ok(())
}

fn receipt_key(id: EntityId) -> Vec<u8> {
    [b"code_view:receipt:v1:".as_slice(), id.as_bytes()].concat()
}
fn relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.contains(['\\', '\0'])
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p == ".git" || p.contains(':'))
    {
        return Err(Error::InvalidClaimBody("unsafe view path"));
    }
    Ok(())
}
#[cfg(test)]
mod tests;

mod entity_serde {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<EntityId, D::Error> {
        let value = String::deserialize(deserializer)?;
        EntityId::from_hex(&value).map_err(serde::de::Error::custom)
    }
}
