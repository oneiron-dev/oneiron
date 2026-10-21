//! The vault's export audit (FIX 6427, owner ruling RT-EXPORT 2026-10-20).
//! Each Owner copy that leaves the vault, the whole vault or an off-record
//! room's talk, is one row every live co-Owner reads: the copy's id, what
//! left, whose copy it is, when and in what shape. Never a byte of the copy,
//! and never a thread, a member or a word of it. The copy itself is never
//! narrowed: the Owner's export carries every private thread, plaintext.
//! Each private thread it carries whose audience does not hold the Owner now
//! tells its members, once per copy, as the thread's own notices do; one
//! gone since the copy read it tells the members its binding then and the
//! vault's edits now name (FIX 6681).
//!
//! Export is never gated: the row and the notices are written after the
//! copy is made, in a write of their own, and whatever they meet is logged
//! and never withholds the copy.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::OwnerAct;
use crate::batch::export::{ExportDiaryRead, WholeVaultExportReceipt};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};
use crate::workspace_roster::ExportThreadRoots;

/// The `format` of an off-record room's talk, which its door answers as
/// JSON.
const EXPORT_FORMAT_OFF_RECORD_TALK: &str = "off_record_talk";
/// The `format` of the whole-vault JSON bundle a raw `Vault` door writes.
const EXPORT_FORMAT_JSON: &str = "json";

/// What an export copied (FIX 6427).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportAuditScope {
    /// The whole vault: the archive, the OKF bundle or the JSON bundle.
    WholeVault,
    /// An off-record room's talk, as its Owner's membership shows it.
    OffRecordRoom,
}

/// One copy that left the vault, written by the call that made it, so every
/// owner can see that the vault left, whose copy it was and in what shape.
/// Never the bytes. A row that cannot be written is logged and does not
/// withhold the copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReceipt {
    /// The copy's id, minted from the vault's clock as it was made: a new
    /// one for every copy, however alike two copies are, and the one each
    /// private thread's notice of it names.
    pub export: EntityId,
    /// What the copy holds: the whole vault, or an off-record room's talk.
    pub scope: ExportAuditScope,
    /// The Owner whose copy it is, whichever door it came through.
    pub exporter: EntityId,
    /// Vault clock seconds.
    pub at: u64,
    pub format: String,
    /// The copy's length, where its door read the copy back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// BLAKE3 of the copy, lowercase hex, where its door read it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The exporting actor as hex, or `host` for a host-root export.
    pub by: String,
    /// OF-490: each agent whose diaries this export read, with the reason.
    pub diary_reads: Vec<ExportDiaryRead>,
    /// The owner's act this export carried out, on a door that records one
    /// (Engine 10-19 02:4x): kind [`crate::authority::OwnerActKind::Export`],
    /// on the whole vault's reserved target, by the owner the export's
    /// snapshot revalidated, with where he said so (audit only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<OwnerAct>,
}

const EXPORT_RECEIPTS: SideTable<u64, ExportReceipt, Named> =
    SideTable::new(&side_table::EXPORT_RECEIPT);

/// One copy a door made, for [`record_export`]: its audit row but the id
/// and time, beside the root of each thread a TURN the copy carries is of,
/// with its binding, read in the copy's own snapshot (FIX 6681).
pub(crate) struct ExportCopy {
    pub(crate) scope: ExportAuditScope,
    pub(crate) exporter: EntityId,
    pub(crate) format: String,
    pub(crate) bytes: Option<u64>,
    pub(crate) digest: Option<String>,
    pub(crate) by: String,
    pub(crate) diary_reads: Vec<ExportDiaryRead>,
    pub(crate) act: Option<OwnerAct>,
    pub(crate) thread_roots: ExportThreadRoots,
}

impl ExportCopy {
    /// A whole-vault copy a raw `Vault` door made as `format` for the
    /// embedded owner `exporter`, whose diaries it read: no act, and no
    /// length or digest, its sink not being read back.
    fn raw(
        exporter: EntityId,
        format: &str,
        diary_reads: Vec<ExportDiaryRead>,
        thread_roots: ExportThreadRoots,
    ) -> Self {
        Self {
            scope: ExportAuditScope::WholeVault,
            exporter,
            format: format.to_owned(),
            bytes: None,
            digest: None,
            by: exporter.to_hex(),
            diary_reads,
            act: None,
            thread_roots,
        }
    }

    /// The Owner `exporter`'s copy of an off-record room's talk, carrying a
    /// turn of each thread in `thread_roots`. Its door has not encoded the
    /// talk yet, so it has no length or digest.
    pub(crate) fn off_record_room(exporter: EntityId, thread_roots: ExportThreadRoots) -> Self {
        Self {
            scope: ExportAuditScope::OffRecordRoom,
            exporter,
            format: EXPORT_FORMAT_OFF_RECORD_TALK.to_owned(),
            bytes: None,
            digest: None,
            by: exporter.to_hex(),
            diary_reads: Vec::new(),
            act: None,
            thread_roots,
        }
    }
}

impl Vault {
    /// Every export audit row, oldest first: each whole-vault copy and each
    /// Owner's copy of an off-record room's talk. A trusted host read; a
    /// co-Owner reads them through [`Self::owner_export_audit`].
    pub fn export_receipts(&self) -> crate::Result<Vec<ExportReceipt>> {
        let txn = self.store.env.read_txn()?;
        export_receipts_in(self, &txn)
    }

    /// The export audit as a co-Owner reads it (FIX 6427): every row, oldest
    /// first, whoever exported, read in the snapshot that revalidates
    /// `owner`. No row names a thread, a member or a word of what left.
    pub fn owner_export_audit(
        &self,
        owner: &AuthenticatedOwner,
    ) -> crate::Result<Vec<ExportReceipt>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        export_receipts_in(self, &txn)
    }
}

/// Every export audit row in `txn`, oldest first.
fn export_receipts_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> crate::Result<Vec<ExportReceipt>> {
    Ok(EXPORT_RECEIPTS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, receipt)| receipt)
        .collect())
}

/// Records `copy`, once it has left (FIX 6427): its audit row under a fresh
/// id from the vault's clock, and, for each private thread it carries whose
/// audience does not hold its exporter now, that thread's members' notice
/// of it, in one write of its own. A root base does not hold is read in the
/// published overlay of the live off-record stretch that holds it; one gone
/// since the copy read it, from the binding that read resolved and the
/// edits base holds now (FIX 6681). Best effort: whatever this meets is
/// logged and never reaches the copy's door, and a row not written still
/// lets the notices go.
pub(crate) fn record_export(vault: &Vault, copy: ExportCopy) {
    let export = match vault.new_entity_id() {
        Ok(export) => export,
        Err(error) => {
            tracing::warn!(%error, "export served without its audit: no export id");
            return;
        }
    };
    let ExportCopy {
        scope,
        exporter,
        format,
        bytes,
        digest,
        by,
        diary_reads,
        act,
        thread_roots,
    } = copy;
    let written = vault.with_write_txn(|txn| {
        // The id's allocation floor is kept with the row that names it.
        let at = match crate::ports::recorded_at_in_txn(&vault.store, txn) {
            Ok(at) => at,
            Err(error) => {
                tracing::warn!(%error, "export audit: clock floor not recorded");
                vault.store.clock.now_recorded_at()
            }
        };
        let receipt = ExportReceipt {
            export,
            scope,
            exporter,
            at,
            format,
            bytes,
            digest,
            by,
            diary_reads,
            act,
        };
        if let Err(error) = append_in_txn(vault, txn, &receipt) {
            tracing::warn!(
                export = %export.to_hex(),
                %error,
                "export served without its audit row"
            );
        }
        crate::workspace_roster::notify_exported_threads_in_txn(
            vault,
            txn,
            &thread_roots,
            exporter,
            export,
        );
        Ok(())
    });
    if let Err(error) = written {
        tracing::warn!(export = %export.to_hex(), %error, "export served without its audit");
    }
}

/// Appends `receipt` after the last row, in `txn`.
fn append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &ExportReceipt,
) -> crate::Result<()> {
    let sequence = match EXPORT_RECEIPTS
        .iter_rev_from(&vault.store, txn, &[])?
        .next()
    {
        None => 0,
        Some(row) => row?
            .0
            .checked_add(1)
            .ok_or(crate::Error::IndexOverflow("export receipt sequence"))?,
    };
    EXPORT_RECEIPTS.put(&vault.store, txn, &sequence, receipt)
}

/// Records the whole-vault copy a raw `Vault` door wrote to its sink as
/// `format` for the embedded owner `exporter` ([`record_export`]): no act,
/// and no length or digest, its sink not being read back.
pub(crate) fn record_raw_export(
    vault: &Vault,
    exporter: EntityId,
    format: &str,
    receipt: &mut WholeVaultExportReceipt,
) {
    let roots = std::mem::take(&mut receipt.thread_roots);
    let copy = ExportCopy::raw(exporter, format, receipt.diary_reads.clone(), roots);
    record_export(vault, copy);
}

/// Records the whole-vault JSON bundle `json` a raw `Vault` door encoded
/// for the embedded owner ([`record_export`]), with its length and digest,
/// `roots` being the root of each thread a TURN it carries is of.
pub(crate) fn record_raw_json_export(vault: &Vault, json: &[u8], roots: ExportThreadRoots) {
    let exporter = match crate::vault::embedded_owner_actor_id() {
        Ok(exporter) => exporter,
        Err(error) => {
            tracing::warn!(%error, "JSON export served without its audit: no owner");
            return;
        }
    };
    let copy = ExportCopy {
        bytes: u64::try_from(json.len()).ok(),
        digest: Some(blake3::hash(json).to_hex().to_string()),
        ..ExportCopy::raw(exporter, EXPORT_FORMAT_JSON, Vec::new(), roots)
    };
    record_export(vault, copy);
}

/// Whether `person`, who takes a copy of an off-record room's talk, owns
/// this vault in `txn`, so that the copy is in its export audit. A role
/// that does not read is logged and taken as none: it never fails the copy.
pub(crate) fn owner_copy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, person: EntityId) -> bool {
    match crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &person) {
        Ok(owner) => owner,
        Err(error) => {
            tracing::warn!(%error, "off-record export: the owner role not read");
            false
        }
    }
}

/// The root of the thread a carried row is of, read from its stored `body`
/// when it is a TURN; `None` for any other row, a trunk TURN, or a binding
/// that does not decode, which the copy carries as it is.
pub(crate) fn turn_thread_root(entity_type: u8, body: &[u8]) -> Option<EntityId> {
    if entity_type != crate::registry::ENTITY_TYPE_TURN {
        return None;
    }
    crate::workspace_roster::thread_binding(body)
        .ok()
        .flatten()
        .map(|binding| binding.root)
}
