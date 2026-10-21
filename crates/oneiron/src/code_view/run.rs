//! The one view materializer (moved from `mod.rs`, FIX 6867 G1 PR2a): an
//! owner's or trusted caller's view, and a run's work, whose run stamp is
//! bound in the receipt's first write. Each open is a fresh view id, a
//! fresh private directory and private copied inodes; no permission is
//! cached and no view is shared between runs, the same agent's included.

use std::collections::BTreeMap;

use super::{CodeViewSet, VIEW_RECEIPTS, ViewReceipt, relative};
use crate::error::{Error, Result};
use crate::memory::repo_doors::RepoRunStamp;
use crate::{EntityId, Vault};

impl CodeViewSet<'_> {
    /// A run's work (FIX 6867): a fresh view of `contents` whose receipt
    /// binds the stamp `admit` builds from the admission it judges in the
    /// receipt's own writer, under the new view id. A refusal writes no
    /// receipt and removes the view's directory.
    pub(crate) fn materialize_tree_for_run<R>(
        &self,
        actor: EntityId,
        fork_hash: [u8; 32],
        contents: &BTreeMap<String, Vec<u8>>,
        admit: impl FnOnce(&heed::RoTxn<'_>, EntityId) -> Result<std::result::Result<RepoRunStamp, R>>,
    ) -> Result<std::result::Result<ViewReceipt, R>> {
        self.materialize_checked(actor, fork_hash, None, contents, |txn, view_id| {
            Ok(admit(txn, view_id)?.map(Some))
        })
    }

    /// The materializer both callers share: allocates the view, copies each
    /// file, then writes the receipt in one transaction whose first act is
    /// `admit`, which answers the run stamp the receipt binds, if any.
    pub(super) fn materialize_checked<R>(
        &self,
        actor: EntityId,
        fork_hash: [u8; 32],
        base: Option<(EntityId, EntityId)>,
        contents: &BTreeMap<String, Vec<u8>>,
        admit: impl FnOnce(
            &heed::RoTxn<'_>,
            EntityId,
        ) -> Result<std::result::Result<Option<RepoRunStamp>, R>>,
    ) -> Result<std::result::Result<ViewReceipt, R>> {
        let _guard = self
            .materialization
            .lock()
            .map_err(|_| Error::InvariantViolation("view lock poisoned"))?;
        let view_id = EntityId::now();
        let destination = self.root.join("views").join(view_id.to_hex());
        std::fs::create_dir(&destination)?;
        let mut files = BTreeMap::new();
        for (path, bytes) in contents {
            relative(path)?;
            let content_hash = *blake3::hash(bytes).as_bytes();
            let blob = self
                .root
                .join("blobs")
                .join(crate::entity_id::bytes_to_hex_lower(&content_hash));
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
                        || std::fs::read(&blob)?.as_slice() != bytes.as_slice()
                    {
                        return Err(Error::CorruptedIndex("view blob was modified"));
                    }
                }
                Err(error) => return Err(error.into()),
            }
            let target = destination.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Same-user tools can chmod read-only files. Never share an inode
            // with the canonical blob or another view. fs::copy may use CoW.
            if target.try_exists()? {
                return Err(Error::InvalidClaimBody("duplicate view path"));
            }
            std::fs::copy(&blob, &target)?;
            files.insert(path.clone(), content_hash);
        }
        let written = self.vault.with_write_txn_grouped(|txn| {
            let run = match admit(txn, view_id)? {
                Ok(run) => run,
                Err(refused) => return Ok(Err(refused)),
            };
            let receipt = ViewReceipt {
                view_id,
                actor,
                fork_hash,
                base,
                files,
                run,
            };
            VIEW_RECEIPTS.put(&self.vault.store, txn, &view_id, &receipt)?;
            Ok(Ok(receipt))
        })?;
        if written.is_err() {
            // A refused run leaves no work behind it.
            std::fs::remove_dir_all(&destination)?;
        }
        Ok(written)
    }
}

/// One view's receipt, read in the caller's snapshot `txn`.
pub(crate) fn view_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ViewReceipt>> {
    VIEW_RECEIPTS.get(&vault.store, txn, &id)
}

/// Every saved view receipt whose run stamp names the CODE anchor `repo`,
/// read in the caller's snapshot `txn` (G4 PR2): historical work evidence
/// for the owner's workbench, in view-id order. The caller admits the
/// owner first; no liveness, file bytes or run authority is inferred.
///
/// # Errors
/// A store failure.
pub(crate) fn repo_view_receipts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    repo: EntityId,
) -> Result<Vec<ViewReceipt>> {
    let mut receipts = Vec::new();
    for row in VIEW_RECEIPTS.iter_from(&vault.store, txn, &[])? {
        let (_, receipt) = row?;
        if receipt.run.as_ref().is_some_and(|stamp| stamp.repo == repo) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}
