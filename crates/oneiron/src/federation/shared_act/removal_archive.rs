//! An export-first removal's archive as it is kept (FIX-LIST 8224): the
//! delivered copy, and beside it the position each archived record stood at
//! when the removal froze it. The positions never leave the vault; they let
//! a holder the removed Owner transferred the archive slip to take only what
//! that holder's own bounds admit, projected from the frozen archive itself
//! (`REMOVAL_ARCHIVE_TRANSFER_MODE`). The removed Owner proving the mint's
//! own key keeps the copy exactly as stored: the positions are kept as their
//! own encoded bytes, so that read never decodes them. A projection whose own
//! input does not read (the positions, the archive's manifest, members or
//! rows) answers the stored copy as it did before projection existed
//! (`ISOLATION_NEW_CHECK_ERROR_MODE`); bounds that were judged still bound.
//! A one-shot transfer is served once (FIX-LIST 10773): the row keeps each
//! slip an archive door spent so, on every archive of its removed Owner, and
//! the door signs the spend into the authority log, so a replica that does
//! not share these rows refuses the slip once it folds that entry (FIX
//! 11862). A pact-bound transfer is served only while its pact holds, and
//! the row logs each serve under that pact (FIX 11860).
//! The archive's bytes are a file the row names, held under the row's own
//! owner, its removed member and its receipt (FIX 3679,
//! [`super::removal_file`]); the row is metadata. An
//! erase reaches these copies in its own commit (FIX-LIST 2241): from it on,
//! no read answers an erased record an archive froze, and the erase owes
//! the file's instance its retirement. The rewrite without those records,
//! a new file, lands on the shared-act sweep the erase wakes, outside every
//! writer, and its release of the old file stages that retirement. An
//! archive the erase leaves no record in, or whose positions do not read,
//! goes in the erase's commit. A person's erase drops the archives kept for
//! them, their files' instances retired with it (FIX 11723).

use std::collections::BTreeSet;

use super::removal_file::ArchiveFile;
use super::{
    ArchiveRow, REMOVAL_EXPORT, RemovalExportCopy, RemovalExportDelivery, removal_export_key,
};
use crate::authority::{ISOLATION_NEW_CHECK_ERROR_MODE, NewCheckErrorMode};
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::{EntityId, Vault};

/// Key-only views of the delivery ledger and of the record ids a removal's
/// export counted; their own modules keep the values. A person's erase
/// deletes their rows by key and reads no value (FIX 11723).
const REMOVAL_DELIVERY_KEYS: SideTable<String, (), Named> =
    SideTable::new(&side_table::SHARED_ACT_REMOVAL_DELIVERY);
const EXPORT_RECORD_KEYS: SideTable<HexId, (), Named> =
    SideTable::new(&side_table::SHARED_ACT_REMOVAL_EXPORT_RECORDS);

/// How a transferred holder takes a removal archive (CALLS
/// "REMOVAL_ARCHIVE_TRANSFER_MODE", accepted by the Engine 10-22 05:3x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferMode {
    /// The stored archive, cut down to the records its bounds admit.
    ProjectStoredSnapshot,
}

const REMOVAL_ARCHIVE_TRANSFER_MODE: TransferMode = TransferMode::ProjectStoredSnapshot;

/// What a projected archive's `digest` names (CALLS
/// "REMOVAL_ARCHIVE_PROJECTED_DIGEST", open): the bytes the holder receives.
/// The removal receipt keeps the stored archive's own digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectedDigest {
    ProjectedBytes,
}

const REMOVAL_ARCHIVE_PROJECTED_DIGEST: ProjectedDigest = ProjectedDigest::ProjectedBytes;

/// One archived record and the position it stood at when the removal froze
/// the archive; `None` where it carried none.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenPosition {
    id: EntityId,
    scope: Option<Scope>,
}

/// A kept removal archive's delivered copy without its bytes (FIX 3679):
/// what its delivery names and what its holder receives beside the archive.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeptRemovalCopy {
    pub(crate) receipt_id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub(crate) vault_id: u64,
    /// The removed Owner, PERSON hex: the archive's one recipient.
    pub(crate) member: String,
    /// When it was last delivered: the removal, or a remaining Owner's re-run.
    pub(crate) delivered_at: u64,
    pub(crate) expires_at: u64,
    /// The archive manifest's `format`.
    pub(crate) format: String,
    /// As [`crate::memory::MemoryExport::holder_requests`].
    pub(crate) holder_requests: Vec<crate::authority::HolderExportRequest>,
}

impl KeptRemovalCopy {
    /// The archive row this copy is kept under: its removed member and its
    /// receipt.
    fn row(&self) -> Result<ArchiveRow> {
        Ok(ArchiveRow {
            member: EntityId::from_hex(&self.member)?,
            receipt: EntityId::from_hex(&self.receipt_id)?,
        })
    }

    /// The copy its holder receives: `archive`, the bytes it is answered,
    /// and their `digest`.
    fn with_archive(self, archive: Vec<u8>, digest: String) -> RemovalExportCopy {
        RemovalExportCopy {
            receipt_id: self.receipt_id,
            vault_id: self.vault_id,
            member: self.member,
            delivered_at: self.delivered_at,
            expires_at: self.expires_at,
            export: crate::memory::MemoryExport {
                format: self.format,
                archive,
                digest,
                holder_requests: self.holder_requests,
                // A removal's records archive follows the world settings, so
                // it names no world it carried past them.
                notices: Vec::new(),
                // Nor is it an Owner's copy: no member's mailbox to name.
                mailbox_notices: Vec::new(),
            },
        }
    }
}

/// A removal archive's row: the delivered copy's metadata, the file its
/// bytes are (FIX 3679), and its frozen positions as their own encoded
/// bytes ([`freeze_positions_in_txn`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRemovalExport {
    pub(crate) copy: KeptRemovalCopy,
    file: ArchiveFile,
    positions: Vec<u8>,
    /// The records erases took that `file` still holds, until the rewrite
    /// without them lands (FIX 3679): no read answers them meanwhile.
    erased: BTreeSet<EntityId>,
    /// The one-shot transferred slips an archive door already served, by
    /// slip id (FIX-LIST 10773): each is kept on every archive of the
    /// removed Owner, so it takes none of them again.
    spent_slips: BTreeSet<[u8; 32]>,
    /// Each serve of this archive to a pact-bound transferred slip, oldest
    /// first (FIX 11860).
    pact_serves: Vec<PactServe>,
}

/// One serve of an archive to a pact-bound transferred slip (FIX 11860): the
/// grant whose pact held at the serve, the slip, and when it was served.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PactServe {
    grant: EntityId,
    slip_id: [u8; 32],
    served_at: u64,
}

impl StoredRemovalExport {
    pub(super) fn new(copy: KeptRemovalCopy, file: ArchiveFile, positions: Vec<u8>) -> Self {
        Self {
            copy,
            file,
            positions,
            erased: BTreeSet::new(),
            spent_slips: BTreeSet::new(),
            pact_serves: Vec::new(),
        }
    }

    /// The file the archive's bytes are.
    pub(super) const fn file(&self) -> &ArchiveFile {
        &self.file
    }

    /// BLAKE3 of the archive as kept, lowercase hex.
    pub(super) fn digest(&self) -> String {
        self.file.digest()
    }

    /// What the delivery tells an Owner: never the archive.
    pub(super) fn delivery(&self) -> RemovalExportDelivery {
        RemovalExportDelivery {
            receipt_id: self.copy.receipt_id.clone(),
            recipient: self.copy.member.clone(),
            digest: self.digest(),
            delivered_at: self.copy.delivered_at,
            expires_at: self.copy.expires_at,
        }
    }

    /// What the erase of `erased` leaves of this row (FIX-LIST 2241), its
    /// newly erased records noted on it. An input that does not read cannot
    /// prove the erased bytes absent, so the row goes
    /// ([`ERASE_UNREADABLE_ARCHIVE_MODE`]).
    fn after_erase(&mut self, erased: &BTreeSet<EntityId>) -> ErasedFromArchive {
        let receipt = self.copy.receipt_id.as_str();
        let Ok(positions) = rmp_serde::from_slice::<Vec<FrozenPosition>>(&self.positions) else {
            return unreadable_on_erase(receipt, "frozen positions", erased);
        };
        let hit: Vec<EntityId> = positions
            .iter()
            .map(|record| record.id)
            .filter(|id| erased.contains(id) && !self.erased.contains(id))
            .collect();
        let Some(&cause) = hit.first() else {
            return ErasedFromArchive::Untouched;
        };
        self.erased.extend(hit);
        if positions
            .iter()
            .all(|record| self.erased.contains(&record.id))
        {
            return ErasedFromArchive::Dropped { cause };
        }
        ErasedFromArchive::Rewrite { cause }
    }
}

/// What an erase leaves of one stored removal archive (FIX-LIST 2241), and
/// the erased record whose erase answers for its file (`cause`).
enum ErasedFromArchive {
    /// It froze none of the erased records.
    Untouched,
    /// Records are left: the file is rewritten without the erased ones.
    Rewrite { cause: EntityId },
    /// Nothing is left, or the row did not read: it goes.
    Dropped { cause: EntityId },
}

/// How an erase treats a removal archive whose own input does not read
/// (CALLS "FIX 2241 unreadable archive on erase"): the copy is a courtesy
/// copy until `expires_at`, and the erase is the user's own act, so the copy
/// goes rather than keep bytes the erase may have named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EraseUnreadableArchiveMode {
    DropCopy,
}

const ERASE_UNREADABLE_ARCHIVE_MODE: EraseUnreadableArchiveMode =
    EraseUnreadableArchiveMode::DropCopy;

fn unreadable_on_erase(
    receipt: &str,
    input: &'static str,
    erased: &BTreeSet<EntityId>,
) -> ErasedFromArchive {
    let EraseUnreadableArchiveMode::DropCopy = ERASE_UNREADABLE_ARCHIVE_MODE;
    tracing::warn!(
        receipt = %receipt,
        input,
        "an erase met a removal archive that did not read; the archive copy goes (FIX-LIST 2241)"
    );
    match erased.first() {
        Some(&cause) => ErasedFromArchive::Dropped { cause },
        None => ErasedFromArchive::Untouched,
    }
}

/// [`ISOLATION_NEW_CHECK_ERROR_MODE`] for a projection whose `input` did not
/// read: the stored copy, as every holder took it before projection
/// existed. The warning names the removal receipt and the input only.
fn keep_stored_copy(copy: RemovalExportCopy, input: &'static str) -> RemovalExportCopy {
    match ISOLATION_NEW_CHECK_ERROR_MODE {
        NewCheckErrorMode::KeepExistingPath => {
            tracing::warn!(
                receipt = %copy.receipt_id,
                input,
                policy = ?ISOLATION_NEW_CHECK_ERROR_MODE,
                "a transferred removal archive did not project; its holder takes the stored copy \
                 (FIX-LIST 8224)"
            );
            copy
        }
    }
}

/// Each of `ids`'s position as `txn`, the archive's own snapshot, holds it
/// ([`Vault::export_positions_in_txn`]), encoded on their own.
pub(super) fn freeze_positions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<Vec<u8>> {
    let positions: Vec<FrozenPosition> = vault
        .export_positions_in_txn(txn, ids)?
        .into_iter()
        .map(|(id, scope)| FrozenPosition { id, scope })
        .collect();
    rmp_serde::to_vec_named(&positions)
        .map_err(|_| Error::InvariantViolation("removal archive positions do not encode"))
}

impl Vault {
    /// [`Self::removal_exports_in_txn`] for a holder the removed Owner
    /// transferred the slip to: each archive cut down to the records
    /// `admits` takes, and one it takes none of left out.
    pub(crate) fn projected_removal_exports_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        now: u64,
        admits: &dyn Fn(EntityId, Option<&Scope>) -> bool,
    ) -> Result<Vec<RemovalExportCopy>> {
        let prefix = removal_export_key(&member.to_hex(), "");
        let mut copies = Vec::new();
        for (_, stored) in REMOVAL_EXPORT.scan_from(&self.store, txn, prefix.as_bytes())? {
            if now < stored.copy.expires_at
                && let Some(copy) = self.removal_export_copy_in_txn(txn, stored, Some(admits))?
            {
                copies.push(copy);
            }
        }
        Ok(copies)
    }

    /// The copy of `stored` its reader takes, its bytes read from the
    /// archive's file in `txn` (FIX 3679): judged record by record on the
    /// frozen positions, the stored archive when the reader takes every
    /// record, none when it takes none, else the stored archive projected
    /// onto those it takes. `admits` judges a holder the removed Owner
    /// transferred the slip to; `None`, the removed Owner proving the mint's
    /// own key, takes every record. No reader takes a record an erase took
    /// that the file still holds. Positions or an archive that do not read
    /// leave the stored copy ([`keep_stored_copy`]) while no erase is owed
    /// on it, and none once one is.
    ///
    /// # Errors
    ///
    /// A file that does not open or match its descriptor; storage errors.
    pub(crate) fn removal_export_copy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stored: StoredRemovalExport,
        admits: Option<&dyn Fn(EntityId, Option<&Scope>) -> bool>,
    ) -> Result<Option<RemovalExportCopy>> {
        let row = stored.copy.row()?;
        let whole = |vault: &Self, stored: StoredRemovalExport| -> Result<RemovalExportCopy> {
            let archive = vault.read_removal_archive_in_txn(txn, row, &stored.file)?;
            let digest = stored.digest();
            Ok(stored.copy.with_archive(archive, digest))
        };
        // The removed Owner's own read never decodes the positions.
        if admits.is_none() && stored.erased.is_empty() {
            return whole(self, stored).map(Some);
        }
        let positions: Vec<FrozenPosition> = match rmp_serde::from_slice(&stored.positions) {
            Ok(positions) => positions,
            Err(_) if stored.erased.is_empty() => {
                return Ok(Some(keep_stored_copy(
                    whole(self, stored)?,
                    "frozen positions",
                )));
            }
            Err(_) => return Ok(None),
        };
        let archived: BTreeSet<EntityId> = positions.iter().map(|record| record.id).collect();
        let kept: BTreeSet<EntityId> = positions
            .iter()
            .filter(|record| {
                !stored.erased.contains(&record.id)
                    && admits.is_none_or(|admits| admits(record.id, record.scope.as_ref()))
            })
            .map(|record| record.id)
            .collect();
        if kept.is_empty() {
            return Ok(None);
        }
        if kept.len() == archived.len() {
            return whole(self, stored).map(Some);
        }
        let TransferMode::ProjectStoredSnapshot = REMOVAL_ARCHIVE_TRANSFER_MODE;
        let archive = self.read_removal_archive_in_txn(txn, row, &stored.file)?;
        match crate::batch::export::project_stored_archive(&archive, &archived, &kept) {
            Ok(bytes) => {
                let ProjectedDigest::ProjectedBytes = REMOVAL_ARCHIVE_PROJECTED_DIGEST;
                let digest = blake3::hash(&bytes).to_hex().to_string();
                Ok(Some(stored.copy.with_archive(bytes, digest)))
            }
            Err(_) if stored.erased.is_empty() => {
                let digest = stored.digest();
                Ok(Some(keep_stored_copy(
                    stored.copy.with_archive(archive, digest),
                    "stored archive",
                )))
            }
            Err(_) => {
                tracing::warn!(
                    receipt = %stored.copy.receipt_id,
                    "a removal archive an erase is owed on did not project; it answers none until \
                     its rewrite (FIX 3679)"
                );
                Ok(None)
            }
        }
    }

    /// Whether an archive door of this store already served the one-shot
    /// transferred slip `slip_id`: any of `member`'s archives keeps its spend
    /// (FIX-LIST 10773). The authority fold's consumed set carries a signed
    /// spend to the replicas that do not share these rows (FIX 11862); the
    /// door reads both.
    pub(crate) fn removal_archive_slip_spent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        slip_id: &[u8; 32],
    ) -> Result<bool> {
        let prefix = removal_export_key(&member.to_hex(), "");
        Ok(REMOVAL_EXPORT
            .scan_from(&self.store, txn, prefix.as_bytes())?
            .iter()
            .any(|(_, stored)| stored.spent_slips.contains(slip_id)))
    }

    /// Spends the one-shot transferred slip `slip_id` on every archive of
    /// `member`, in the writer whose answer served it (FIX-LIST 10773). The
    /// door signs the same spend into the authority log in that writer when
    /// it holds a signer (FIX 11862).
    pub(crate) fn spend_removal_archive_slip_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        member: EntityId,
        slip_id: [u8; 32],
    ) -> Result<()> {
        let prefix = removal_export_key(&member.to_hex(), "");
        for (row_key, mut stored) in
            REMOVAL_EXPORT.scan_from(&self.store, txn, prefix.as_bytes())?
        {
            if stored.spent_slips.insert(slip_id) {
                REMOVAL_EXPORT.put(&self.store, txn, &row_key, &stored)?;
            }
        }
        Ok(())
    }

    /// An erase's reach into the archives kept for removed Owners
    /// (FIX-LIST 2241), in the erase's own commit: each archive that froze
    /// an erased record notes it, so no read answers it from this commit
    /// on, and the erase owes its file's instance a retirement; the rewrite
    /// without it lands on the shared-act sweep this wakes now
    /// ([`Self::finish_removal_archive_rewrites`]), and its release of the
    /// old file stages that retirement. One left with no record, or whose
    /// positions do not read, goes now, its file released and its instance
    /// retired by this erase. No file is written in this writer: a new
    /// file's instance is minted before any writer opens.
    pub(crate) fn scrub_removal_exports_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        erased: &[EntityId],
    ) -> Result<()> {
        if erased.is_empty() {
            return Ok(());
        }
        let erased: BTreeSet<EntityId> = erased.iter().copied().collect();
        let mut owed = false;
        for (row_key, mut stored) in REMOVAL_EXPORT.scan(&self.store, txn)? {
            let row = ArchiveRow::from_key(&row_key);
            match stored.after_erase(&erased) {
                ErasedFromArchive::Untouched => {}
                ErasedFromArchive::Rewrite { cause } => {
                    if let Some(row) = row {
                        self.owe_removal_archive_erase_in_txn(txn, row, &stored.file, cause)?;
                    }
                    REMOVAL_EXPORT.put(&self.store, txn, &row_key, &stored)?;
                    owed = true;
                }
                ErasedFromArchive::Dropped { cause } => {
                    REMOVAL_EXPORT.delete(&self.store, txn, &row_key)?;
                    if let Some(row) = row {
                        self.release_removal_archives_in_txn(txn, row, Some(cause))?;
                    }
                }
            }
        }
        if owed {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            crate::housekeeping::note_wake_in_txn(
                &self.store,
                txn,
                crate::housekeeping::HousekeepingSweep::SharedActMaturity,
                now,
            )?;
        }
        Ok(())
    }

    /// Lands the rewrite each erase left owed on a kept archive (FIX 3679):
    /// the archive projected from its file onto the records left, written
    /// as a new file outside every writer, then swapped in for the old one
    /// in a writer that finds the row as it was read; the old file's release
    /// there stages the retirement the erase owes its instance. An archive
    /// whose file, positions or projection do not read goes instead
    /// ([`ERASE_UNREADABLE_ARCHIVE_MODE`]). A row that changed meanwhile
    /// waits for the next pass. Warning-only: each owed rewrite stays on
    /// its row until it lands. Answers how many rows it rewrote or dropped.
    pub(crate) fn finish_removal_archive_rewrites(&self) -> usize {
        let owed: Vec<(String, StoredRemovalExport)> = match self.store.env.read_txn() {
            Ok(txn) => match REMOVAL_EXPORT.scan(&self.store, &txn) {
                Ok(rows) => rows
                    .into_iter()
                    .filter(|(_, stored)| !stored.erased.is_empty())
                    .collect(),
                Err(error) => {
                    tracing::warn!(error = %error, "removal archive rewrites wait (FIX 3679)");
                    return 0;
                }
            },
            Err(error) => {
                tracing::warn!(error = %error, "removal archive rewrites wait (FIX 3679)");
                return 0;
            }
        };
        let mut landed = 0;
        for (row_key, stored) in owed {
            match self.rewrite_removal_archive(&row_key, &stored) {
                Ok(true) => landed += 1,
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    receipt = %stored.copy.receipt_id,
                    error = %error,
                    "a removal archive's erase rewrite waits for the next pass (FIX 3679)"
                ),
            }
        }
        #[cfg(unix)]
        if landed > 0 {
            self.finish_body_custody_retirements_after_commit();
        }
        landed
    }

    /// [`Self::finish_removal_archive_rewrites`] for the row `row_key`, as
    /// `stored` read it. `false` when the row changed or went meanwhile.
    fn rewrite_removal_archive(&self, row_key: &str, stored: &StoredRemovalExport) -> Result<bool> {
        let row = ArchiveRow::from_key(row_key)
            .ok_or(Error::InvariantViolation("removal archive row key"))?;
        let row_key = &row_key.to_owned();
        let rewritten = self.rewritten_removal_archive(row, stored)?;
        let mut txn = self.store.env.write_txn()?;
        let Some(mut current) = REMOVAL_EXPORT.get(&self.store, &txn, row_key)? else {
            return Ok(false);
        };
        if current.file != stored.file || current.erased != stored.erased {
            return Ok(false);
        }
        let old = current.file.clone();
        match rewritten {
            Some((staged, positions)) => {
                current.file = self.bind_removal_archive_in_txn(&mut txn, row, &staged)?;
                current.positions = positions;
                current.erased.clear();
                REMOVAL_EXPORT.put(&self.store, &mut txn, row_key, &current)?;
            }
            None => {
                REMOVAL_EXPORT.delete(&self.store, &mut txn, row_key)?;
            }
        }
        self.release_removal_archive_in_txn(&mut txn, row, &old)?;
        txn.commit()?;
        Ok(true)
    }

    /// The file `stored`'s archive becomes without the records erases took,
    /// written before the writer that names it, with the positions left;
    /// `None` when its file, positions or projection do not read, or no
    /// record is left: the archive goes.
    fn rewritten_removal_archive(
        &self,
        row: ArchiveRow,
        stored: &StoredRemovalExport,
    ) -> Result<Option<(super::removal_file::StagedArchive, Vec<u8>)>> {
        let receipt_hex = stored.copy.receipt_id.as_str();
        let unreadable = |input: &'static str| {
            let _ = unreadable_on_erase(receipt_hex, input, &stored.erased);
            Ok(None)
        };
        let Ok(positions) = rmp_serde::from_slice::<Vec<FrozenPosition>>(&stored.positions) else {
            return unreadable("frozen positions");
        };
        let archived: BTreeSet<EntityId> = positions.iter().map(|record| record.id).collect();
        let left: Vec<FrozenPosition> = positions
            .into_iter()
            .filter(|record| !stored.erased.contains(&record.id))
            .collect();
        if left.is_empty() {
            return Ok(None);
        }
        let kept: BTreeSet<EntityId> = left.iter().map(|record| record.id).collect();
        let archive = {
            let _pin = self.pin_all_result_bodies();
            let _custody = self.store.gate_custody_read_guard()?;
            let txn = self.store.env.read_txn()?;
            self.read_removal_archive_in_txn(&txn, row, &stored.file)
        };
        let Ok(archive) = archive else {
            return unreadable("stored archive");
        };
        let Ok(bytes) = crate::batch::export::project_stored_archive(&archive, &archived, &kept)
        else {
            return unreadable("stored archive");
        };
        drop(archive);
        let Ok(positions) = rmp_serde::to_vec_named(&left) else {
            return unreadable("frozen positions");
        };
        let staged = self.stage_removal_archive(&mut std::io::Cursor::new(bytes))?;
        Ok(Some((staged, positions)))
    }

    /// A person's erase, in its own writer (FIX 11723): the removal archives
    /// kept for them go, each with its file, whose instances this erase
    /// retires (FIX 3679), and the record ids its export counted, and
    /// every holder's delivery of an archive of theirs goes too, one whose
    /// archive is already gone included. Only rows keyed by the erased
    /// person go. It is the declared actor scrub of the archive table and of
    /// the delivery ledger both; whichever runs second finds nothing left.
    pub(crate) fn erase_removal_archive_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let prefix = removal_export_key(&actor.to_hex(), "");
        let archives = REMOVAL_EXPORT.scan_keys(&self.store, wtxn, prefix.as_bytes())?;
        let mut records = 0_usize;
        for row_key in &archives {
            if let Some(row) = ArchiveRow::from_key(row_key) {
                if EXPORT_RECORD_KEYS.delete(&self.store, wtxn, &HexId(row.receipt))? {
                    records += 1;
                }
                // Read from the row's archive descriptors, so a row that
                // does not decode strands no file; this erase retires each.
                self.release_removal_archives_in_txn(wtxn, row, Some(*actor))?;
            }
            REMOVAL_EXPORT.delete(&self.store, wtxn, row_key)?;
        }
        let deliveries = REMOVAL_DELIVERY_KEYS.delete_from(&self.store, wtxn, prefix.as_bytes())?;
        if !archives.is_empty() || deliveries > 0 {
            tracing::info!(
                archives = archives.len(),
                records,
                deliveries,
                "a person's erase dropped the removal archives kept for them (FIX 11723)"
            );
        }
        Ok(())
    }

    /// Logs on each archive in `served` that the pact-bound transferred slip
    /// `slip_id` took it at `now` while `grant`'s pact held (FIX 11860).
    pub(crate) fn log_removal_archive_pact_serve_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        served: &[RemovalExportCopy],
        grant: EntityId,
        slip_id: [u8; 32],
        now: u64,
    ) -> Result<()> {
        for copy in served {
            let row_key = removal_export_key(&copy.member, &copy.receipt_id);
            if let Some(mut stored) = REMOVAL_EXPORT.get(&self.store, txn, &row_key)? {
                stored.pact_serves.push(PactServe {
                    grant,
                    slip_id,
                    served_at: now,
                });
                REMOVAL_EXPORT.put(&self.store, txn, &row_key, &stored)?;
            }
        }
        Ok(())
    }

    /// [`Self::removal_export_in_txn`] for a transferred holder, as
    /// [`Self::projected_removal_exports_in_txn`] cuts it.
    pub(crate) fn projected_removal_export_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        receipt_id: EntityId,
        now: u64,
        admits: &dyn Fn(EntityId, Option<&Scope>) -> bool,
    ) -> Result<Option<RemovalExportCopy>> {
        let row_key = removal_export_key(&member.to_hex(), &receipt_id.to_hex());
        match REMOVAL_EXPORT.get(&self.store, txn, &row_key)? {
            Some(stored) if now < stored.copy.expires_at => {
                self.removal_export_copy_in_txn(txn, stored, Some(admits))
            }
            _ => Ok(None),
        }
    }
}
