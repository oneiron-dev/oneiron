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
//! and never withholds the copy. An owner's export that carries his act is
//! also signed in that write as an `ExportAct` every machine he admits
//! folds and checks (FIX 4624), on the same terms: a record that cannot be
//! signed is logged, and the copy and its row stand. Each custody value the
//! copy carried as its handle because it did not open here is recorded in
//! that write too, for its holder to seal to the owner (FIX 4624(b)), and
//! the row lists them, each recorded or why not; on the same terms again.
//!
//! The one exception is a copy that carries another member's personal
//! mailbox, or uses an approval of its Owner's request for one (fix list row
//! 15416, [`crate::mail_pack`]): whatever its shape, its row, which counts
//! those mailboxes, each mailbox's person's notice and each approval's use
//! are written in one write before the copy leaves
//! ([`record_member_mail_export`]), and a write that does not commit leaves
//! those mailboxes out of the copy, made again: its row, counting none, is
//! written the same way before that copy leaves, and it never leaves
//! unaudited.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{HolderExportBasis, HolderExportRequest, OwnerAct};
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
/// The `format` of the Owner's own copy of every record, which a raw `Vault`
/// door answers as a vector of records (fix list row 15416).
const EXPORT_FORMAT_RECORDS: &str = "records";

/// What an export copied (FIX 6427).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportAuditScope {
    /// The whole vault: the archive, the OKF bundle, the JSON bundle or the
    /// Owner's copy of every record.
    WholeVault,
    /// An off-record room's talk, as its Owner's membership shows it.
    OffRecordRoom,
}

/// One copy that left the vault, written by the call that made it, so every
/// owner can see that the vault left, whose copy it was and in what shape.
/// Never the bytes. A row that cannot be written is logged and does not
/// withhold the copy, but for a copy that carries another member's personal
/// mailbox: that row is written before the copy leaves (fix list row 15416).
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
    /// FIX 4624(b): each custody value the copy carried as its handle
    /// because it did not open here, and where its holder's sealed copy
    /// stands, read again from the fold whenever the row is read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holder_requests: Vec<HolderExportRequest>,
    /// How many other members' personal mailboxes the copy carried, each
    /// mailbox's person told in this row's own write (fix list row 15416).
    /// Never which mailboxes, whose, or a word of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_mailboxes: Option<u64>,
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
    /// The custody values the copy's snapshot could not open, not recorded
    /// yet (FIX 4624(b)).
    pub(crate) holder_requests: Vec<HolderExportRequest>,
    /// The machine the owner named to receive their sealed copies.
    pub(crate) recipient: Option<EntityId>,
}

impl ExportCopy {
    /// A whole-vault copy a raw `Vault` door made as `format` for the
    /// embedded owner `exporter`, whose diaries it read: no act; its door
    /// adds the length and digest it read the copy back with.
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
            holder_requests: Vec::new(),
            recipient: None,
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
            holder_requests: Vec::new(),
            recipient: None,
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

/// Every export audit row in `txn`, oldest first, each holder request's
/// status read again from the fold in `txn` (FIX 4624(b)); a fold that does
/// not read leaves each as its row recorded it.
fn export_receipts_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> crate::Result<Vec<ExportReceipt>> {
    let mut receipts: Vec<ExportReceipt> = EXPORT_RECEIPTS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, receipt)| receipt)
        .collect();
    if receipts
        .iter()
        .any(|receipt| !receipt.holder_requests.is_empty())
        && let Ok(fold) = vault.authority_view_readonly_in_txn(txn)
    {
        for receipt in &mut receipts {
            receipt.holder_requests = std::mem::take(&mut receipt.holder_requests)
                .into_iter()
                .map(|request| request.refreshed(&fold))
                .collect();
        }
    }
    Ok(receipts)
}

/// Records `copy`, once it has left (FIX 6427): its audit row under a fresh
/// id from the vault's clock, and, for each private thread it carries whose
/// audience does not hold its exporter now, that thread's members' notice
/// of it, in one write of its own. A root base does not hold is read in the
/// published overlay of the live off-record stretch that holds it; one gone
/// since the copy read it, from the binding that read resolved and the
/// edits base holds now (FIX 6681). Best effort: whatever this meets is
/// logged and never reaches the copy's door, and a row not written still
/// lets the notices go. Returns where each custody value the copy carried as
/// its handle stands for its holder (FIX 4624(b)): recorded, or why not.
pub(crate) fn record_export(vault: &Vault, copy: ExportCopy) -> Vec<HolderExportRequest> {
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
        holder_requests,
        recipient,
    } = copy;
    let export = match vault.new_entity_id() {
        Ok(export) => export,
        Err(error) => {
            tracing::warn!(%error, "export served without its audit: no export id");
            return holder_requests;
        }
    };
    let needs: Vec<_> = holder_requests
        .iter()
        .map(HolderExportRequest::need)
        .collect();
    let written = vault.with_write_txn(|txn| {
        // The id's allocation floor is kept with the row that names it.
        let at = match crate::ports::recorded_at_in_txn(&vault.store, txn) {
            Ok(at) => at,
            Err(error) => {
                tracing::warn!(%error, "export audit: clock floor not recorded");
                vault.store.clock.now_recorded_at()
            }
        };
        // The signed record goes before the holder requests, which link it,
        // and both before the row, which lists them: each in a savepoint of
        // its own, so a fault leaves the write as it was.
        let export_act = act.and_then(|act| {
            vault.record_export_act_op_in_txn(txn, act, export, &format, bytes, digest.as_deref())
        });
        let holder_requests = vault.record_holder_export_requests_in_txn(
            txn,
            HolderExportBasis {
                act,
                export,
                digest: digest
                    .as_deref()
                    .and_then(|hex| blake3::Hash::from_hex(hex).ok())
                    .map(|hash| *hash.as_bytes()),
                export_act,
                recipient,
                needs: &needs,
            },
        );
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
            holder_requests,
            member_mailboxes: None,
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
        Ok(receipt.holder_requests)
    });
    match written {
        Ok(holder_requests) => holder_requests,
        Err(error) => {
            tracing::warn!(export = %export.to_hex(), %error, "export served without its audit");
            // Nothing the write did stands: no request waits for a holder.
            needs
                .into_iter()
                .map(HolderExportRequest::unrecorded)
                .collect()
        }
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

/// The audit of the whole-vault copy a raw `Vault` door made as `format`
/// for the embedded owner `exporter`, before it releases it: no act, its
/// length `bytes` and BLAKE3 `digest` as the door read its copy back, and
/// the thread roots and holder requests its `receipt` carried, taken from
/// it for the audit.
pub(crate) fn raw_export_copy(
    exporter: EntityId,
    format: &str,
    receipt: &mut WholeVaultExportReceipt,
    bytes: u64,
    digest: &str,
) -> ExportCopy {
    let roots = std::mem::take(&mut receipt.thread_roots);
    ExportCopy {
        bytes: Some(bytes),
        digest: Some(digest.to_owned()),
        holder_requests: std::mem::take(&mut receipt.holder_requests),
        ..ExportCopy::raw(exporter, format, receipt.diary_reads.clone(), roots)
    }
}

/// The audit of the Owner `exporter`'s own copy of every record, which a raw
/// `Vault` door made for the embedded owner, before it answers it (fix list
/// row 15416): no act and no diary read, the length `bytes` and BLAKE3
/// `digest` of its records as their one encoding reads, and the root of each
/// thread a TURN it carries is of, `thread_roots`.
pub(crate) fn raw_records_copy(
    exporter: EntityId,
    bytes: u64,
    digest: String,
    thread_roots: ExportThreadRoots,
) -> ExportCopy {
    ExportCopy {
        bytes: Some(bytes),
        digest: Some(digest),
        ..ExportCopy::raw(exporter, EXPORT_FORMAT_RECORDS, Vec::new(), thread_roots)
    }
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

/// Records the whole-vault JSON bundle `json` a raw `Vault` door encoded,
/// which carries other members' personal mailboxes (fix list row 15416),
/// before a byte of it leaves ([`record_member_mail_export`]): its length
/// and digest, no act, and each private thread it carries, `roots`. With no
/// `mailboxes`, `json` is the bundle made again without them after such a
/// write did not commit, recorded the same strict way, counting no mailbox.
///
/// # Errors
///
/// As [`record_member_mail_export`], or no embedded owner to record.
pub(crate) fn record_member_mail_json_export(
    vault: &Vault,
    json: &[u8],
    roots: ExportThreadRoots,
    mailboxes: Option<&crate::mail_pack::CarriedMemberMailboxes>,
) -> crate::Result<()> {
    let exporter = match mailboxes {
        Some(mailboxes) => mailboxes.exporter(),
        None => crate::vault::embedded_owner_actor_id()?,
    };
    let copy = ExportCopy {
        bytes: u64::try_from(json.len()).ok(),
        digest: Some(blake3::hash(json).to_hex().to_string()),
        ..ExportCopy::raw(exporter, EXPORT_FORMAT_JSON, Vec::new(), roots)
    };
    record_member_mail_export(vault, copy, mailboxes).map(drop)
}

/// Records `copy`, an Owner's copy of whatever shape that carries other
/// members' personal mailboxes, or uses an approval of its Owner's request
/// for one (fix list row 15416), before a byte of it leaves: under one export
/// id, in one write, each mailbox's person's notice and each approval's use
/// ([`crate::mail_pack::tell_member_mailboxes_in_txn`]), the owner's act and
/// the custody values the copy carried as their handles as [`record_export`]
/// records them, its audit row with how many such mailboxes it carries, and
/// each private thread it carries told as [`record_export`] tells it. Such a
/// copy is never also recorded through [`record_export`]. Nothing here but
/// the act and the holder requests, which [`record_export`] records best
/// effort too, is best effort: whatever this meets before the commit fails
/// the write and nothing of it stands, and the copy's door then leaves
/// those mailboxes out of the copy. Once the write commits, its row and
/// notices stand and this answers where each custody value stands for its
/// holder (FIX 4624(b)): a step the write door runs after the commit that
/// fails is logged, never read as a rollback, so the copy keeps its one
/// export id.
///
/// With no `mailboxes`, `copy` is the one made again without them after
/// such a write did not commit: its row, counting no mailbox, is written
/// the same way before a byte of it leaves, with no notice and no approval
/// used, and a write that does not commit releases nothing.
///
/// # Errors
///
/// The write did not commit: a mailbox or an approval no longer goes with
/// the copy, or a storage failure.
pub(crate) fn record_member_mail_export(
    vault: &Vault,
    copy: ExportCopy,
    mailboxes: Option<&crate::mail_pack::CarriedMemberMailboxes>,
) -> crate::Result<Vec<HolderExportRequest>> {
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
        holder_requests,
        recipient,
    } = copy;
    let export = vault.new_entity_id()?;
    let needs: Vec<_> = holder_requests
        .iter()
        .map(HolderExportRequest::need)
        .collect();
    // Set once the write is durable, to what it recorded, before the steps
    // the door runs after it.
    let mut committed = None;
    let written = vault.write_txn_door_after_commit(
        crate::store::Callback::Opaque,
        |txn| -> crate::Result<Vec<HolderExportRequest>> {
            // The id's allocation floor is kept with the row that names it.
            let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let told = match mailboxes {
                Some(mailboxes) => crate::mail_pack::tell_member_mailboxes_in_txn(
                    vault, txn, mailboxes, export, at,
                )?,
                // The copy made again carries no mailbox and uses no
                // approval: no one is told.
                None => 0,
            };
            // The signed record goes before the holder requests, which link
            // it, and both before the row, which lists them, as
            // [`record_export`] writes them.
            let export_act = act.and_then(|act| {
                vault.record_export_act_op_in_txn(
                    txn,
                    act,
                    export,
                    &format,
                    bytes,
                    digest.as_deref(),
                )
            });
            let holder_requests = vault.record_holder_export_requests_in_txn(
                txn,
                HolderExportBasis {
                    act,
                    export,
                    digest: digest
                        .as_deref()
                        .and_then(|hex| blake3::Hash::from_hex(hex).ok())
                        .map(|hash| *hash.as_bytes()),
                    export_act,
                    recipient,
                    needs: &needs,
                },
            );
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
                holder_requests,
                member_mailboxes: Some(told),
            };
            append_in_txn(vault, txn, &receipt)?;
            crate::workspace_roster::notify_exported_threads_in_txn(
                vault,
                txn,
                &thread_roots,
                exporter,
                export,
            );
            Ok(receipt.holder_requests)
        },
        |holder_requests| {
            committed = Some(holder_requests.clone());
            Ok(holder_requests)
        },
    );
    match (written, committed) {
        (Err(error), Some(holder_requests)) => {
            tracing::warn!(
                export = %export.to_hex(),
                %error,
                "export: its audit row and the members' notices are written; a step after the write failed"
            );
            Ok(holder_requests)
        }
        (written, _) => written,
    }
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
