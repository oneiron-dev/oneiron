//! Per-agent file views over codebase blobs, with one owned shared service set.
use crate::build_cache::{ActionResult, BuildAction, BuildCache, BuildCacheResult, CachedBuildLeg};
use crate::checkout::CheckoutTaskClass;
use crate::codebase::CodebaseSnapshotMount;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Named, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod erase;
mod language_server;
mod run;
pub use erase::{collect_after_delete, collect_after_sweep, collect_erased_views};
pub use language_server::{LanguageServer, SharedLanguageServer, StdioLanguageServer};
pub(crate) use run::{repo_view_receipts_in_txn, view_receipt_in_txn};

/// One materialized view's receipt, keyed by view id.
const VIEW_RECEIPTS: SideTable<EntityId, ViewReceipt, Named> =
    SideTable::new(&side_table::CODE_VIEW_RECEIPT);

/// One view build's cache outcome, keyed by (view id, action key). The
/// stored shape is an ad hoc JSON object with no matching Rust type, so the
/// table binds `serde_json::Value` directly rather than a struct that could
/// drift from the `json!` macro's field order.
const VIEW_BUILD_OUTCOMES: SideTable<(EntityId, [u8; 32]), serde_json::Value, LegacyJson> =
    SideTable::new(&side_table::CODE_VIEW_BUILD);

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
    pub base: Option<(EntityId, EntityId)>,
    pub files: BTreeMap<String, [u8; 32]>,
    /// The run this view is the work of (FIX 6867), bound in its first
    /// write; `None` for an owner's or trusted caller's view.
    pub run: Option<crate::memory::repo_doors::RepoRunStamp>,
    /// How each file a masked reader's copy holds differs from the stored
    /// blob it stands in for (FIX 8965): absent for the stored bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub projections: BTreeMap<String, crate::origin::secret_projection::RepoFileProjectionView>,
}
/// Owns a private host directory. Working files never share writable inodes
/// with canonical blobs or other views. Durable edits use the code document door.
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
        let mut files = BTreeMap::new();
        for file in &mount.snapshot().files {
            if policy.selects(&file.path)? {
                let bytes = mount
                    .read_file(&file.path)?
                    .ok_or(Error::CorruptedIndex("view blob absent"))?;
                if *blake3::hash(&bytes).as_bytes() != file.content_hash {
                    return Err(Error::CorruptedIndex("view blob hash mismatch"));
                }
                files.insert(file.path.clone(), bytes);
            }
        }
        self.materialize_tree(actor, mount.snapshot().fork_hash, None, &files, |_| Ok(()))
    }

    /// Reopens the vault-owned view set, never a caller-selected folder.
    pub(crate) fn open(vault: &'a Vault) -> Result<Self> {
        let root = vault.store.env.path().join("code-views");
        match Self::create(vault, &root) {
            Ok(set) => Ok(set),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                for path in [root.clone(), root.join("blobs"), root.join("views")] {
                    if !std::fs::symlink_metadata(path)?.is_dir() {
                        return Err(Error::CorruptedIndex("view set directory replaced"));
                    }
                }
                Ok(Self {
                    vault,
                    root,
                    materialization: std::sync::Mutex::new(()),
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn materialize_tree(
        &self,
        actor: EntityId,
        fork_hash: [u8; 32],
        base: Option<(EntityId, EntityId)>,
        contents: &BTreeMap<String, Vec<u8>>,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<ViewReceipt> {
        let materialized = self.materialize_checked(
            actor,
            fork_hash,
            base,
            contents,
            BTreeMap::new(),
            |txn, _| {
                admit(txn)?;
                Ok(Ok::<_, std::convert::Infallible>(None))
            },
        )?;
        match materialized {
            Ok(receipt) => Ok(receipt),
            Err(never) => match never {},
        }
    }
    pub fn receipt(&self, id: EntityId) -> Result<Option<ViewReceipt>> {
        let txn = self.vault.store.env.read_txn()?;
        VIEW_RECEIPTS.get(&self.vault.store, &txn, &id)
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
        self.build_inner(id, cache, class, action, None, execute)
    }

    pub(crate) fn build_pinned(
        &self,
        id: EntityId,
        cache: &BuildCache<'_>,
        class: CheckoutTaskClass,
        action: &BuildAction,
        expected: &crate::build_cache::ActionKey,
        execute: impl FnOnce(&Path, &Vault) -> BuildCacheResult<ActionResult>,
    ) -> BuildCacheResult<CachedBuildLeg> {
        self.build_inner(id, cache, class, action, Some(expected), execute)
    }

    pub(crate) fn build_action(
        &self,
        id: EntityId,
        action: &BuildAction,
    ) -> BuildCacheResult<BuildAction> {
        view_build_action(action, &self.freeze_inputs(id, action)?)
    }

    fn freeze_inputs(&self, id: EntityId, action: &BuildAction) -> Result<ViewReceipt> {
        let mut receipt = self
            .receipt(id)?
            .ok_or(Error::InvalidClaimBody("unknown view"))?;
        let root = self.view_path(id)?;
        if !std::fs::symlink_metadata(&root)?.is_dir() {
            return Err(Error::CorruptedIndex("view root was replaced"));
        }
        receipt.files.clear();
        let mut directories = vec![String::new()];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(root.join(&directory))? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Error::InvalidClaimBody("view path is not UTF-8"))?;
                let path = if directory.is_empty() {
                    name
                } else {
                    format!("{directory}/{name}")
                };
                relative(&path)?;
                if action
                    .declared_outputs()
                    .iter()
                    .any(|output| output.as_str() == path)
                {
                    continue;
                }
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    directories.push(path);
                } else if kind.is_file() {
                    let bytes = read_view_file(&root, &path)?;
                    receipt.files.insert(path, *blake3::hash(&bytes).as_bytes());
                } else {
                    return Err(Error::InvalidClaimBody("view input is not a regular file"));
                }
            }
        }
        Ok(receipt)
    }

    fn build_inner(
        &self,
        id: EntityId,
        cache: &BuildCache<'_>,
        class: CheckoutTaskClass,
        action: &BuildAction,
        expected: Option<&crate::build_cache::ActionKey>,
        execute: impl FnOnce(&Path, &Vault) -> BuildCacheResult<ActionResult>,
    ) -> BuildCacheResult<CachedBuildLeg> {
        let receipt = self.freeze_inputs(id, action)?;

        if receipt.fork_hash != action.input_root.fork_hash {
            return Err(crate::build_cache::BuildCacheError::InvalidAction(
                "view action root mismatch",
            ));
        }
        let action = view_build_action(action, &receipt)?;
        if expected.is_some_and(|expected| action.action_key().as_ref().ok() != Some(expected)) {
            return Err(crate::build_cache::BuildCacheError::InvalidAction(
                "view action digest changed",
            ));
        }
        let path = self.view_path(id)?;
        // Tools are trusted host code, not sandboxed guests. Still reject
        // accidental input mutation BEFORE a miss can enter the shared cache.
        verify_view_inputs(&path, &receipt)?;
        let leg = cache.run_leg(class, &action, |vault| {
            let result = execute(&path, vault)?;
            verify_view_inputs(&path, &receipt)?;
            if self.freeze_inputs(id, &action)?.files != receipt.files {
                return Err(Error::CorruptedIndex("view inputs changed during execution").into());
            }
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
            // A DOCX output shows its default author (FIX 4513).
            let bytes = cache.artifact_vault().resolve_docx_authors(bytes)?;
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
        let outcome = serde_json::json!({"hit":leg.receipt.cache_hit,"producer":leg.receipt.producer_ref,"action":leg.cached.action_key.to_hex(),"reusable":leg.reusable});
        self.vault.with_write_txn_grouped(|txn| {
            cache
                .admit_account_in_txn(txn)
                .map_err(|error| match error {
                    crate::build_cache::BuildCacheError::Store(error) => error,
                    _ => Error::InvalidClaimBody("build account no longer admitted"),
                })?;
            VIEW_BUILD_OUTCOMES.put(
                &self.vault.store,
                txn,
                &(id, *leg.cached.action_key.as_bytes()),
                &outcome,
            )?;
            Ok(())
        })?;
        Ok(leg)
    }
}
fn view_build_action(action: &BuildAction, receipt: &ViewReceipt) -> BuildCacheResult<BuildAction> {
    use crate::build_cache::ExtraInputDigest;
    let encoded = rmp_serde::to_vec(&receipt.files)
        .map_err(|_| Error::CorruptedIndex("view input identity encode"))?;
    let mut identity = blake3::Hasher::new_derive_key("oneiron.code_view.inputs.v1");
    identity.update(&encoded);
    let mut inputs = action.input_root.clone();
    // Keep custom REAPI roots and every original command/platform/input fact
    // bound, rather than letting a caller-supplied CAS root bypass selection.
    inputs
        .extra_inputs
        .push(ExtraInputDigest::new(*action.action_key()?.as_bytes()));
    inputs
        .extra_inputs
        .push(ExtraInputDigest::new(*identity.finalize().as_bytes()));
    BuildAction::new(
        action.command.clone(),
        inputs,
        action.platform.clone(),
        action.declared_outputs().to_vec(),
    )
}

fn verify_view_inputs(root: &Path, receipt: &ViewReceipt) -> Result<()> {
    for (path, expected) in &receipt.files {
        if blake3::hash(&read_view_file(root, path)?).as_bytes() != expected {
            return Err(Error::CorruptedIndex("view input was modified"));
        }
    }
    Ok(())
}

pub(crate) fn read_view_file(root: &Path, path: &str) -> Result<Vec<u8>> {
    relative(path)?;
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(Error::CorruptedIndex("view root was replaced"));
    }
    let parts: Vec<_> = path.split('/').collect();
    let mut target = root.to_path_buf();
    for part in &parts[..parts.len() - 1] {
        target.push(part);
        if !std::fs::symlink_metadata(&target)?.is_dir() {
            return Err(Error::CorruptedIndex("view parent was replaced"));
        }
    }
    target.push(parts[parts.len() - 1]);
    if !std::fs::symlink_metadata(&target)?.is_file() {
        return Err(Error::CorruptedIndex("view file was replaced"));
    }
    Ok(std::fs::read(target)?)
}

pub(crate) fn relative(path: &str) -> Result<()> {
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
