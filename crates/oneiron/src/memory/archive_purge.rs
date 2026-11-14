//! Archive impact preview and confirmed ARCH-0038 delete: the owner's door,
//! and its checked siblings for every other caller's archive-delete
//! authority (OF-449 L4), each judged by check-in first (ROLES-CHECKIN 2k5c).
//! The ladder's erase, which also clears backups, is a different act.

use super::entity_delete::{RoleDeleteCheckIn, authority_changed};
use crate::EntityId;
use crate::check_in::{self, ActClass};
use crate::deletion::{AdmittedDeleteDoor, DeleteReason};
use crate::error::Error;
use crate::federation::{DeleteAuthority, DeleteCaller, DeleteRefusal, DeleteTarget};
use crate::memory::support::verify_deletion_authority_in_txn;
use crate::memory::{
    DeleteReceipt, MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, SafeDeleteReason,
};
use crate::ports::{DeletionMarker, TombstoneStoreRead};

/// The saved verb a checked archive delete is: the verb its check-in names
/// (2k5c).
const ARCHIVE_DELETE_VERB: &str = "vault.archive.delete.confirm";

/// One archived entity's retained record bytes. Secondary indexes and historical
/// carriers are handled by ARCH-0038; this is not a filesystem-space estimate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePurgeEntry {
    pub entity: EntityId,
    pub record_bytes: u64,
    fingerprint: [u8; 32],
    archive_marker: Vec<u8>,
}

impl ArchivePurgeEntry {
    /// The BLAKE3 hash of the record bytes this entry read.
    pub(crate) fn record_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// The exact archive marker bytes this entry read.
    pub(crate) fn marker(&self) -> &[u8] {
        &self.archive_marker
    }
}

/// What a confirm may bind one archived record to: the record hash and the
/// archive marker its preview read.
pub(crate) type ArchiveExpectation = ([u8; 32], Vec<u8>);

/// A batch's per-record answers, in canonical order.
pub(crate) type ArchiveDeleteResults<T> = Vec<(EntityId, MemoryResult<T>)>;

/// One archived record a checked confirm deletes: what its preview read,
/// when the item binds it, and the approved check-in its delete spends,
/// when the item names one (2k5c).
#[derive(Debug, Clone)]
pub(crate) struct ArchiveConfirmItem {
    /// The archived record.
    pub(crate) entity: EntityId,
    /// The record hash and archive marker a preview read.
    pub(crate) expected: Option<ArchiveExpectation>,
    /// The approved check-in this record's delete spends.
    pub(crate) check_in_ref: Option<EntityId>,
}

/// A snapshot-bound confirmation. Fields are read-only so callers cannot add a
/// target they did not preview. Restores and changed records invalidate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePurgePreview {
    entries: Vec<ArchivePurgeEntry>,
}

impl ArchivePurgePreview {
    pub fn entries(&self) -> &[ArchivePurgeEntry] {
        &self.entries
    }
    pub fn record_bytes(&self) -> u64 {
        self.entries.iter().map(|row| row.record_bytes).sum()
    }
}

impl Memory<'_> {
    /// Preview only explicit archive targets, under the same owner authority as
    /// the delete. No cron path holds a Memory owner capability.
    pub fn preview_archive_purge(&self, ids: &[EntityId]) -> MemoryResult<ArchivePurgePreview> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        let mut entries = Vec::new();
        // One preview/receipt per id, with stable order regardless of input.
        let mut targets = ids.to_vec();
        targets.sort_unstable();
        targets.dedup();
        for id in targets {
            let marker = archive_marker(self.vault, &txn, id)?;
            let raw = self
                .vault
                .get_raw_in(&txn, &id)?
                .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))?;
            entries.push(ArchivePurgeEntry {
                entity: id,
                record_bytes: raw.len() as u64,
                fingerprint: *blake3::hash(&raw).as_bytes(),
                archive_marker: marker,
            });
        }
        Ok(ArchivePurgePreview { entries })
    }

    /// Each result carries its own ARCH-0038 receipt or refusal. A later row's
    /// failure must not hide an earlier completed delete. The deletion rail
    /// rechecks both authority and the preview inside its linearizing
    /// transaction, the preview by its scrub-stable identity: the archive
    /// marker the previewed id holds (FIX 9062, `same_archive_in`). The
    /// owner's delete is never gated: each receipt records their own proof
    /// (ROLES-CHECKIN 2k5c).
    pub fn confirm_archive_purge(
        &self,
        preview: &ArchivePurgePreview,
    ) -> Vec<(EntityId, MemoryResult<DeleteReceipt>)> {
        preview
            .entries
            .iter()
            .map(|row| {
                let result = self
                    .safe_delete_checked(
                        &row.entity.to_hex(),
                        SafeDeleteReason::UserHardDelete,
                        |txn| same_archive_in(self.vault, txn, row.entity, &row.archive_marker),
                    )
                    .map(|mut receipt| {
                        receipt.check_in =
                            Some(check_in::owner_own_proof_decision(ActClass::Delete));
                        receipt
                    });
                (row.entity, result)
            })
            .collect()
    }
}

impl Memory<'_> {
    /// The checked sibling of [`Self::preview_archive_purge`] for a caller
    /// the owner door does not serve (OF-449 L4): each explicit target, in
    /// the same canonical order, under this caller's archive-delete
    /// authority in one snapshot. A target it may not delete, or that is no
    /// cleanup archive, answers its own error and the rest still preview.
    ///
    /// # Errors
    /// The snapshot could not be opened.
    pub(crate) fn preview_archive_delete(
        &self,
        ids: &[EntityId],
    ) -> MemoryResult<ArchiveDeleteResults<ArchivePurgeEntry>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let mut targets = ids.to_vec();
        targets.sort_unstable();
        targets.dedup();
        Ok(targets
            .into_iter()
            .map(|id| {
                let entry = self
                    .archive_delete_authority_in(&txn, &DeleteTarget::new(id))
                    .and_then(|_| archive_entry_in(self.vault, &txn, id));
                (id, entry)
            })
            .collect())
    }

    /// The checked sibling of [`Self::confirm_archive_purge`]: each explicit
    /// target, once, in canonical order (the first item named for an id is
    /// kept), is a user hard delete under this caller's archive-delete
    /// authority. The expected record hash and marker, when given, are
    /// compared once in a snapshot before the delete starts; each write
    /// before publication then rechecks that authority, the cleanup archive
    /// marker and, when given, the expected marker, the preview's
    /// scrub-stable identity (FIX 9062, `same_archive_in`). One target's
    /// refusal, failure or wait never hides another's receipt.
    ///
    /// Each target is judged by check-in first, in a writer of its own
    /// before its rail, as `vault.delete` judges a delete by role (2k5c;
    /// P25-SHAPE Q1 = A): the Owner on their own proof, an agent unjudged
    /// (PR 3's act gate), and a person under their membership role, a
    /// Steward's delete of another's record in scope waiting on its own
    /// pending check-in, which that target's item names as `check_in_ref`
    /// once approved (Engine ruling STEWARD-DELETE-WAIT = B).
    pub(crate) fn confirm_archive_delete(
        &self,
        items: &[ArchiveConfirmItem],
    ) -> ArchiveDeleteResults<(DeleteReceipt, DeleteAuthority)> {
        let mut targets = items.to_vec();
        targets.sort_by_key(|item| item.entity);
        targets.dedup_by_key(|item| item.entity);
        targets
            .iter()
            .map(|item| (item.entity, self.confirm_archive_item(item)))
            .collect()
    }

    /// One target of [`Self::confirm_archive_delete`]: its expectation, its
    /// check-in judged, then its rail, each write of which must find the
    /// authority the judge read. A target that waits answers
    /// `CHECK_IN_PENDING` naming its check-in and deletes nothing.
    fn confirm_archive_item(
        &self,
        item: &ArchiveConfirmItem,
    ) -> MemoryResult<(DeleteReceipt, DeleteAuthority)> {
        let id = item.entity;
        self.expected_archive_holds(id, item.expected.as_ref())?;
        let target = DeleteTarget::new(id);
        let authority = |txn: &heed::RoTxn<'_>| -> MemoryResult<DeleteAuthority> {
            self.archive_delete_authority_in(txn, &target)
        };
        let (judged, decision) = match self.role_delete_check_in(
            &target,
            DeleteReason::UserHardDelete,
            ARCHIVE_DELETE_VERB,
            &authority,
            item.check_in_ref.as_ref(),
        )? {
            RoleDeleteCheckIn::Go {
                authority: judged,
                decision,
            } => (judged, decision),
            RoleDeleteCheckIn::Waits(check_in) => {
                return Err(Error::CheckInPending(check_in.to_hex()).into());
            }
        };
        let (mut receipt, admitted) = self.safe_delete_admitted(
            id,
            DeleteReason::UserHardDelete,
            AdmittedDeleteDoor::Archive,
            &authority,
            |txn| {
                match &item.expected {
                    Some((_, marker)) => same_archive_in(self.vault, txn, id, marker)?,
                    None => archive_marker(self.vault, txn, id).map(drop)?,
                }
                if authority(txn)? == judged {
                    Ok(())
                } else {
                    Err(authority_changed(AdmittedDeleteDoor::Archive))
                }
            },
        )?;
        receipt.check_in = decision;
        Ok((receipt, admitted))
    }

    /// Whether archived `id` is still what `expected` names, read in one
    /// snapshot before its delete starts: the record hash and archive
    /// marker its preview read. Nothing expected passes.
    fn expected_archive_holds(
        &self,
        id: EntityId,
        expected: Option<&ArchiveExpectation>,
    ) -> MemoryResult<()> {
        let Some((hash, marker)) = expected else {
            return Ok(());
        };
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        same_archive_in(self.vault, &txn, id, marker)?;
        let raw = self
            .vault
            .get_raw_in(&txn, &id)?
            .ok_or_else(stale_preview)?;
        if blake3::hash(&raw).as_bytes() != hash {
            return Err(stale_preview());
        }
        Ok(())
    }

    /// This caller's authority to delete the archived `target` in `txn`
    /// (`federation::require_delete_authority_in_txn`), its refusal FORBIDDEN.
    fn archive_delete_authority_in(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &DeleteTarget,
    ) -> MemoryResult<DeleteAuthority> {
        let caller = DeleteCaller {
            actor: self.actor,
            class: self.actor_class,
            credential: self.presented_credential(),
        };
        crate::federation::require_delete_authority_in_txn(self.vault, txn, caller, target)?
            .map_err(|refusal: DeleteRefusal| {
                MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    refusal.message(),
                    &[
                        "An archived record is deleted by the vault's Owner, an Admin whose scope \
                         holds it, the Member who owns it, or an agent under one Grant that names \
                         delete.",
                    ],
                )
            })
    }
}

/// One archived record's preview entry as `txn` holds it.
fn archive_entry_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> MemoryResult<ArchivePurgeEntry> {
    let marker = archive_marker(vault, txn, id)?;
    let raw = vault
        .get_raw_in(txn, &id)?
        .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))?;
    Ok(ArchivePurgeEntry {
        entity: id,
        record_bytes: raw.len() as u64,
        fingerprint: *blake3::hash(&raw).as_bytes(),
        archive_marker: marker,
    })
}

/// Whether `id` in `txn` is still the cleanup archive a preview read, by its
/// scrub-stable identity (FIX 9062): the archive marker `id` holds is
/// `marker`. That marker carries the archiving request's own id, so a
/// restore, which clears it, or a change and a new archive, which writes
/// another, fails the check; a scrub before publication changes the record
/// bytes but never the marker, so the record bytes are not compared here.
fn same_archive_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    marker: &[u8],
) -> MemoryResult<()> {
    if archive_marker(vault, txn, id)? != marker {
        return Err(stale_preview());
    }
    Ok(())
}

fn stale_preview() -> MemoryError {
    MemoryError::bad_request("archive preview no longer matches; preview again")
}

fn archive_marker(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> MemoryResult<Vec<u8>> {
    if vault
        .archive_tombstone_in_txn(txn, &id)?
        .is_none_or(|marker| {
            marker.reason != Some(crate::deletion::TombstoneReason::ArchivedByCleanup)
        })
    {
        return Err(stale_preview());
    }
    vault
        .port_deletion_marker(txn, DeletionMarker::Archive, &id)?
        .ok_or_else(stale_preview)
}
