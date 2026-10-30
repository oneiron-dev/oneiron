//! Which reviewed import a tested queue revision's untouched bytes descend
//! from (FIX 6869, G4 PR1), and the one complete-tree materializer.
//!
//! `resolve_code_revision_import_anchor` is the sole binding resolver. A
//! revision's own fold-bound `snapshot_anchor` names the manifest when its
//! seal knew it; otherwise the immutable parent links lead to the chain's
//! checked Baseline, whose typed import-approval receipt names it. Both, if
//! present, must agree. A chain with neither is unbound, an allowed state:
//! nothing is resealed or backfilled, and no live snapshot is looked up.
use std::collections::{BTreeMap, HashSet};

use heed::RoTxn;

use super::CodeRevision;
use super::import_types::{CodeImportApproval, CodeImportManifest, approval_id, manifest_id};
use super::promotion::promotion_receipt_in_txn;
use super::storage::read_code_revision_record_in_txn;
use super::tree_inventory::{CodeTreeInventory, MODE_GITLINK};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{ArtifactError, Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::merge_queue::QueueTestedTarget;
use crate::origin::tree::OriginTreeFile;
use crate::scan_check::{EngineScan, ScanCount};
use crate::{EntityId, Vault};

/// The import manifest `manifest_ref` names, read in `txn`; `None` when no
/// claim is there. A claim whose id is not its digest's is corruption.
///
/// # Errors
/// Corruption or a store failure.
pub(crate) fn import_manifest_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    manifest_ref: EntityId,
) -> Result<Option<CodeImportManifest>> {
    let Some(body) = vault.get_claim_in_txn(txn, &manifest_ref)? else {
        return Ok(None);
    };
    let manifest = CodeImportManifest::from_claim(&body)?;
    if manifest_id(&manifest.digest)? != manifest_ref {
        return Err(Error::CorruptedIndex(
            "an import manifest's id is not its digest's",
        ));
    }
    Ok(Some(manifest))
}

/// The import approval `baseline`'s stored promotion receipt names, read
/// in `txn`; `None` when the Baseline holds no receipt or its approval
/// claim is gone. A receipt that names anything else is corruption.
///
/// # Errors
/// Corruption or a store failure.
pub(crate) fn baseline_import_approval_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    baseline: EntityId,
) -> Result<Option<(EntityId, CodeImportApproval)>> {
    let Some(ids) = promotion_receipt_in_txn(&vault.store, txn, &baseline)? else {
        return Ok(None);
    };
    let [id] = ids.as_slice() else {
        return Err(Error::CorruptedIndex(
            "a checked baseline's promotion names one import approval",
        ));
    };
    let id = EntityId::from_hex(id)?;
    let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
        return Ok(None);
    };
    let approval = CodeImportApproval::from_claim(&body)?;
    if approval_id(&approval)? != id || approval.baseline_revision != baseline {
        return Err(Error::CorruptedIndex(
            "an import approval is not the one its receipt names",
        ));
    }
    Ok(Some((id, approval)))
}

/// The imported snapshot still holds the manifest's exact fork and custody
/// withholds none of it: `Ok(Err(_))` names what changed.
///
/// # Errors
/// A store failure.
pub(crate) fn import_snapshot_custody_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    manifest: &CodeImportManifest,
) -> Result<std::result::Result<(), String>> {
    let Some(snapshot) = vault.get_codebase_snapshot_in_txn(txn, &manifest.anchor.snapshot)? else {
        return Ok(Err("the imported snapshot is gone".to_owned()));
    };
    if bytes_to_hex_lower(&snapshot.fork_hash) != manifest.anchor.snapshot_fork_hash {
        return Ok(Err(
            "the imported snapshot no longer holds its manifest's fork".to_owned(),
        ));
    }
    if let Some(path) = vault
        .codebase_withheld_paths_in_txn(txn, &snapshot.fork_hash)?
        .into_iter()
        .next()
    {
        return Ok(Err(format!(
            "{path}: custody now withholds an imported file"
        )));
    }
    Ok(Ok(()))
}

impl Vault {
    /// The manifest of the reviewed import `revision_id`'s tested chain is
    /// bound to, or `None` for an ordinary or unbound revision.
    ///
    /// # Errors
    /// A missing record, a chain that does not end at its checked
    /// Baseline, bindings that disagree, or a store failure.
    pub(crate) fn resolve_code_revision_import_anchor(
        &self,
        revision_id: EntityId,
    ) -> Result<Option<CodeImportManifest>> {
        let txn = self.store.env.read_txn()?;
        resolve_import_anchor_in_txn(self, &txn, revision_id)
    }
}

/// [`Vault::resolve_code_revision_import_anchor`] in `txn`.
///
/// # Errors
/// As there.
pub(crate) fn resolve_import_anchor_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    revision_id: EntityId,
) -> Result<Option<CodeImportManifest>> {
    let revision = read_code_revision_record_in_txn(&vault.store, txn, &revision_id)?
        .ok_or(Error::EntityNotFound)?;
    let Some(tested) = revision.tested_queue.clone() else {
        return Ok(None);
    };
    let bound = revision.snapshot_anchor;
    let mut root = revision;
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::DagWalkRecords,
        revision_id.as_bytes(),
    )?;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(root.revision_id) {
            count.defer(&vault.store);
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision parent chain contains a cycle",
            )));
        }
        count.row();
        let Some(parent) = root.parent_revision_id else {
            break;
        };
        root = read_code_revision_record_in_txn(&vault.store, txn, &parent)?
            .ok_or(Error::EntityNotFound)?;
    }
    count.defer(&vault.store);
    let Some(root_tested) = root.tested_queue.as_ref().filter(|root_tested| {
        root.parent_revision_id.is_none()
            && root_tested.target == QueueTestedTarget::Baseline
            && root_tested.store == tested.store
            && root_tested.init_work == tested.init_work
    }) else {
        return Err(Error::CorruptedIndex(
            "a tested queue chain does not end at its checked baseline",
        ));
    };
    let approved = baseline_import_approval_in_txn(vault, txn, root.revision_id)?
        .map(|(_, approval)| approval.manifest);
    let manifest_ref = match (bound, approved) {
        (Some(bound), Some(approved)) if bound != approved => {
            return Err(Error::CorruptedIndex(
                "a revision's import binding and its baseline's approval disagree",
            ));
        }
        (Some(manifest_ref), _) | (None, Some(manifest_ref)) => manifest_ref,
        (None, None) => return Ok(None),
    };
    let manifest =
        import_manifest_in_txn(vault, txn, manifest_ref)?.ok_or(Error::EntityNotFound)?;
    if manifest.anchor.object_store != root_tested.store
        || manifest.anchor.source_commit != root_tested.commit
        || manifest.anchor.source_tree != root_tested.tree
    {
        return Err(Error::CorruptedIndex(
            "an import manifest is bound to another baseline",
        ));
    }
    Ok(Some(manifest))
}

/// The exact files a finalized tested revision's complete tree holds: the
/// persisted record authenticated, its object store and inventory digest
/// checked, and, for an import-bound chain, its imported snapshot's custody
/// checked again, then the one render body (G4 PR1). Untouched bytes are
/// never read past custody.
///
/// # Errors
/// An ordinary or changed revision, another object store or inventory, a
/// withheld import, or a render failure.
pub fn materialize_code_revision_tree(
    vault: &Vault,
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    revision: &CodeRevision,
) -> Result<BTreeMap<String, OriginTreeFile>> {
    verify_complete_tree(vault, repo, revision)?;
    CodeTreeInventory::render(vault, git, repo, revision)
}

/// The untouched blobs a finalized tested revision's complete tree holds,
/// by path, after the checks [`materialize_code_revision_tree`] makes: each
/// read at its recorded object and checked against its size and hash, for a
/// working view (FIX 9940). A submodule link holds no file bytes and is
/// left out.
///
/// # Errors
/// An ordinary or changed revision, another object store or inventory, a
/// withheld import, or a missing or changed object.
pub fn read_code_revision_blobs(
    vault: &Vault,
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    revision: &CodeRevision,
) -> Result<BTreeMap<String, Vec<u8>>> {
    verify_complete_tree(vault, repo, revision)?;
    let mut blobs = BTreeMap::new();
    for (path, blob) in &revision.blob_frontiers {
        if blob.mode == MODE_GITLINK {
            continue;
        }
        let content = git.read_object(repo, &GitOid::parse_hex(blob.git_oid.clone())?)?;
        if content.len() as u64 != blob.size_bytes
            || blake3::hash(&content).as_bytes() != &blob.content_hash
        {
            return Err(Error::InvariantViolation(
                "a tested tree blob differs from its recorded bytes",
            ));
        }
        blobs.insert(path.clone(), content);
    }
    Ok(blobs)
}

/// The persisted record authenticated, its object store and inventory
/// digest checked, and an import-bound chain's imported snapshot custody
/// checked again: untouched bytes are never read past custody.
fn verify_complete_tree(vault: &Vault, repo: &GitWireRepo, revision: &CodeRevision) -> Result<()> {
    let tested = revision
        .tested_queue
        .as_ref()
        .ok_or(Error::InvalidClaimBody(
            "only a tested queue revision holds a complete tree",
        ))?;
    let store = repo.identity().as_hex();
    if vault.get_code_revision(&revision.revision_id)?.as_ref() != Some(revision)
        || tested.store != store
        || CodeTreeInventory::digest(revision)? != tested.inventory_digest
    {
        return Err(Error::InvariantViolation(
            "engine commit belongs to another object store or inventory",
        ));
    }
    if let Some(manifest) = vault.resolve_code_revision_import_anchor(revision.revision_id)? {
        let txn = vault.store.env.read_txn()?;
        if manifest.anchor.object_store != store {
            return Err(Error::InvariantViolation(
                "the import manifest names another object store",
            ));
        }
        if let Err(detail) = import_snapshot_custody_in_txn(vault, &txn, &manifest)? {
            return Err(Error::Refused(detail));
        }
    }
    Ok(())
}
