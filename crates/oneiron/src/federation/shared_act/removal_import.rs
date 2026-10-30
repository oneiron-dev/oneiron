//! A removed person's device takes in the archive an export-first removal
//! delivered to it (FIX 11197). The device's receiver writes each archive it
//! is sent beside its paired credential (FIX 3215, 3396); here the archive is
//! checked against what this vault knows and kept in it as the removal keeps
//! it at the home, so the same readers answer it here
//! ([`Vault::removed_owner_exports`], [`Vault::removed_owner_archive`]), and
//! its person is told in their inbox.
//!
//! An archive goes in only once it checks: it is the person's, its bytes are
//! the ones its digest names, its term is the one its delivery opened and has
//! not run out on this vault's clock, the whole-vault archive reader takes
//! every member and row of it, and its manifest names this vault's own
//! authority as its source. Where this vault holds the removal's receipt, or
//! its own creation, the archive must agree with them too. One that does not
//! check is refused, and its file stays where the receiver wrote it.
//!
//! Nothing in the archive is applied: no record, grant, membership or key
//! leaves it. It lands whole as received evidence its person reads, and
//! imports into a vault of their own when they choose
//! ([`Vault::import_whole_vault_archive`]). Each delivery taken in is
//! recorded, so none is taken in twice; the person hears of each archive
//! once.

use super::removal_archive::{FrozenPosition, StoredRemovalExport};
use super::{REMOVAL_EXPORT, REMOVAL_EXPORT_RETAIN_SECS, RemovalExportCopy, removal_export_key};
use crate::batch::export::{
    ArchiveRecordKind, ExportAuthorityManifest, VAULT_ARCHIVE_FORMAT, read_vault_archive_indexed,
};
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each delivery of a removal archive this vault took in. Key: hex32
/// (person) ":" hex32 (receipt id) ":" decimal (the delivery's version).
const REMOVAL_IMPORT: SideTable<String, ImportedRemovalArchive, Named> =
    SideTable::new(&side_table::SHARED_ACT_REMOVAL_IMPORT);

/// The inbox producer of an arrived removal archive; its event is
/// `<person>:<receipt id>`, so each archive is told once.
const NOTIFICATION_PRODUCER_REMOVAL_ARCHIVE: &str = "shared_vault.removal_archive";

/// One delivery of a removal archive as this vault took it in.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedRemovalArchive {
    /// BLAKE3 of the archive, lowercase hex.
    digest: String,
    /// The records it holds, as its manifest counts them.
    records: u64,
    /// The files attached to them.
    files: u64,
    /// When this vault took it in, on its store clock.
    imported_at: u64,
}

/// What an archive holds, as its manifest lists it.
#[derive(Debug, Clone, Copy)]
struct Held {
    records: u64,
    files: u64,
}

/// The row key of `person`'s delivery `version` of the archive the removal
/// receipt `receipt` names.
fn import_key(person: EntityId, receipt: EntityId, version: u64) -> String {
    format!("{}:{}:{version}", person.to_hex(), receipt.to_hex())
}

/// The refusal of an archive that does not check: `why` names the check.
fn refused(why: &str) -> Error {
    Error::InvalidConfig(format!("a removal archive that {why} is not imported"))
}

/// `seconds` as its UTC date, `2026-10-30`.
fn utc_date(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || seconds.to_string(),
            |stamp| stamp.date_naive().to_string(),
        )
}

impl Vault {
    /// Takes into this vault the archive `copy` its home delivered to
    /// `person`, the holder of this device's own paired credential, once it
    /// checks (as this module says), and tells `person` in their inbox that
    /// it arrived. The archive is kept as the removal keeps it at the home,
    /// for the readers there to answer here; a later delivery of the same
    /// archive moves its term on. `Some` with the records it holds when this
    /// call took it in; `None` when this delivery was taken in before.
    ///
    /// # Errors
    ///
    /// An archive that does not check, which stays out of the vault; storage
    /// errors.
    pub fn import_removal_archive(
        &self,
        person: EntityId,
        copy: &RemovalExportCopy,
    ) -> Result<Option<u64>> {
        let receipt = EntityId::from_hex(&copy.receipt_id)?;
        let version = copy.delivered_at;
        if self.removal_archive_imported(person, receipt, version)? {
            return Ok(None);
        }
        if EntityId::from_hex(&copy.member).ok() != Some(person) {
            return Err(refused("is another person's"));
        }
        if copy.export.format != VAULT_ARCHIVE_FORMAT
            || blake3::hash(&copy.export.archive).to_hex().as_str() != copy.export.digest
        {
            return Err(refused("is not the bytes its digest names"));
        }
        if version.checked_add(REMOVAL_EXPORT_RETAIN_SECS) != Some(copy.expires_at) {
            return Err(refused("names a term no removal grants"));
        }
        let held = self.removal_archive_holds(&copy.export.archive)?;
        let row = import_key(person, receipt, version);
        self.with_write_txn_grouped(|txn| {
            if REMOVAL_IMPORT.contains(&self.store, txn, &row)? {
                return Ok(None);
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if now >= copy.expires_at {
                return Err(refused("is past its term"));
            }
            self.check_known_removal_in_txn(txn, person, receipt, copy)?;
            self.keep_received_removal_export_in_txn(txn, person, receipt, copy)?;
            let imported = ImportedRemovalArchive {
                digest: copy.export.digest.clone(),
                records: held.records,
                files: held.files,
                imported_at: now,
            };
            REMOVAL_IMPORT.put(&self.store, txn, &row, &imported)?;
            self.notify_removal_archive_in_txn(txn, person, receipt, copy, held, now)?;
            Ok(Some(held.records))
        })
    }

    /// Whether this vault took in `person`'s delivery `version` (the
    /// archive's `delivered_at` as delivered) of the archive the removal
    /// receipt `receipt_id` names ([`Self::import_removal_archive`]).
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn removal_archive_imported(
        &self,
        person: EntityId,
        receipt_id: EntityId,
        version: u64,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        REMOVAL_IMPORT.contains(&self.store, &txn, &import_key(person, receipt_id, version))
    }

    /// What `archive` holds, read through the whole-vault archive's own
    /// reader (FIX 2766, 3678): every member checked against its manifest
    /// and every row as it is read, into a scratch index that goes with the
    /// call. Refused unless its manifest names this vault's authority as its
    /// source. Nothing of it is written.
    fn removal_archive_holds(&self, archive: &[u8]) -> Result<Held> {
        let ours = self
            .authority_vault_id()?
            .map(|id| crate::entity_id::bytes_to_hex_lower(&id));
        let scratch = self
            .store
            .archive_scratch_env(self.config.page_seal.as_ref())?;
        let read = read_vault_archive_indexed(self, &scratch, std::io::Cursor::new(archive))?;
        let manifest = &read.manifest;
        let source = manifest
            .storage
            .authority()
            .map(ExportAuthorityManifest::vault_id);
        if ours.is_none() || ours.as_deref() != source {
            return Err(refused("names another vault as its source"));
        }
        let records = manifest
            .records
            .iter()
            .filter(|file| {
                matches!(
                    file.kind,
                    ArchiveRecordKind::Entity | ArchiveRecordKind::Claim | ArchiveRecordKind::Skill
                )
            })
            .map(|file| file.rows)
            .sum();
        Ok(Held {
            records,
            files: u64::try_from(manifest.files.len()).unwrap_or(u64::MAX),
        })
    }

    /// Refuses `copy` where it disagrees with what this vault holds of its
    /// removal: the receipt `receipt` names, when this vault holds it, must
    /// be an export of the same archive to `person` from the same vault; and
    /// this vault's own creation, when it holds one, must name the vault the
    /// archive names.
    fn check_known_removal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        receipt: EntityId,
        copy: &RemovalExportCopy,
    ) -> Result<()> {
        if let Some(known) = self.shared_act_receipt_in_txn(txn, &receipt.to_hex())? {
            let agrees = known.vault_id == copy.vault_id
                && known.export.as_ref().is_some_and(|export| {
                    export.member == person.to_hex() && export.digest == copy.export.digest
                });
            if !agrees {
                return Err(refused("disagrees with this vault's removal receipt"));
            }
        }
        if let Some(creation) = self.shared_vault_creation_in_txn(txn)?
            && creation.vault_id != copy.vault_id
        {
            return Err(refused("names another shared vault"));
        }
        Ok(())
    }

    /// Keeps `copy` as the removal keeps it at the home, under its member
    /// and receipt, so the removal-export readers answer it here. One
    /// already kept must be the same archive: a later delivery of it moves
    /// its term on, and an earlier one leaves it. A copy kept here carries
    /// no frozen positions, so a holder the slip was transferred to takes
    /// none of it here (FIX-LIST 8224).
    fn keep_received_removal_export_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        person: EntityId,
        receipt: EntityId,
        copy: &RemovalExportCopy,
    ) -> Result<()> {
        let row_key = removal_export_key(&person.to_hex(), &receipt.to_hex());
        if let Some(mut stored) = REMOVAL_EXPORT.get(&self.store, txn, &row_key)? {
            if stored.copy.export.digest != copy.export.digest {
                return Err(refused("differs from the archive kept under its receipt"));
            }
            if copy.delivered_at > stored.copy.delivered_at {
                stored.copy.delivered_at = copy.delivered_at;
                stored.copy.expires_at = copy.expires_at;
                REMOVAL_EXPORT.put(&self.store, txn, &row_key, &stored)?;
            }
            return Ok(());
        }
        let mut kept = copy.clone();
        kept.receipt_id = receipt.to_hex();
        kept.member = person.to_hex();
        let positions = rmp_serde::to_vec_named(&Vec::<FrozenPosition>::new())
            .map_err(|_| Error::InvariantViolation("removal archive positions do not encode"))?;
        REMOVAL_EXPORT.put(
            &self.store,
            txn,
            &row_key,
            &StoredRemovalExport::new(kept, positions),
        )
    }

    /// Tells `person` in their inbox that the archive `copy` arrived: whose
    /// it is, when it came, what it holds and until when it stays readable
    /// here, in plain words. One notice per archive: a later delivery of it
    /// finds the notice there and leaves it as it stands.
    fn notify_removal_archive_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        person: EntityId,
        receipt: EntityId,
        copy: &RemovalExportCopy,
        held: Held,
        now: u64,
    ) -> Result<EntityId> {
        let detail = format!(
            "Your export from shared vault {vault} arrived on {arrived}. It holds {records} \
             records and {files} attached files: what you could read there before your \
             removal. You can read it on this device until {until}, and import it into a \
             vault of your own.",
            vault = copy.vault_id,
            arrived = utc_date(now),
            records = held.records,
            files = held.files,
            until = utc_date(copy.expires_at),
        );
        self.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::ImportFinished,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_REMOVAL_ARCHIVE.to_owned(),
                    event: format!("{}:{}", person.to_hex(), receipt.to_hex()),
                    result: Some(receipt.to_hex()),
                    detail: Some(detail),
                    ..NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(person),
                created_at: now,
                origin_conversation: None,
            },
        )
    }
}
