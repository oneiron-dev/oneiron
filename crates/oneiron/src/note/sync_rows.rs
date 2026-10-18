//! The NOTE-adjacent per-entity `sync_state` workflow rows swept alongside
//! the canonical entity-document family. These sit beside, but are distinct
//! from, the ARCH-0023b document families (`d:e:`, `u:e:`, `sv:e:`, `ssv:e:`,
//! `m:u_seq:e:`), which go through the document-row port
//! (`crate::ports::DocumentRowStore`).
//!
//! Every one of these prefixes is also written from `crate::sync`, outside
//! this module's assigned slice; the bindings here are local to the NOTE
//! module's own call sites (get/contains/delete/delete_from), never the full
//! read/write surface of the family.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, LegacyJson, Raw, SideTable};

use super::operations::NoteOperationReceipt;
use super::proposals::{NoteActor, names_no_actor};
use super::side_keys::HexPair;

/// Per-entity text-document subscription marker (`ds:e:`); this module only
/// checks for its presence and, on erasure, deletes it.
pub(super) const SYNC_DS_E: SideTable<side_table::HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_DS_E);

/// Durable unacknowledged local text-document edit frame (`qd:e:`); swept
/// wholesale on erasure/recovery, never decoded here.
pub(super) const SYNC_QD_E: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QD_E);

/// Durable pending semantic NOTE-operation request (`qn:e:`), keyed by entity
/// then request id.
pub(super) const SYNC_QN_E: SideTable<HexPair, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QN_E);

/// Per-admission disclosure floor (`ad:e:`); swept wholesale here, never
/// decoded (its key carries an optional middle segment this module never
/// parses).
pub(super) const SYNC_AD_E: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_AD_E);

/// Durable applied/rejected NOTE-operation receipt (`nc:e:`); swept wholesale
/// here, never decoded.
pub(super) const SYNC_NC_E: SideTable<Vec<u8>, serde_json::Value, LegacyJson> =
    SideTable::new(&side_table::SYNC_NC_E);

/// Idempotent operation receipt for one authenticated NOTE command (`nr:e:`),
/// keyed by entity then request id, beside the actor that gave the command:
/// its hex id, or no one once that actor was erased (FIX 3879).
pub(super) const NOTE_RECEIPT_BY_REQUEST: SideTable<
    HexPair,
    (NoteActor, NoteOperationReceipt),
    LegacyJson,
> = SideTable::new(&side_table::NOTE_RECEIPT_BY_REQUEST);

/// What an actor's erase does with the receipts of the NOTE commands it gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteRequestReceiptErase {
    /// The receipt stays, with its request, command hash and outcome, and
    /// names no one.
    KeepReceiptEraseActor,
    /// The receipt goes.
    DeleteReceipt,
}

/// A receipt records a command that already ran, so it stays and a replay
/// of its request is still refused; it names no one once its actor is
/// erased, and no one matches a replay (FIX 3879; a call).
pub const ACTOR_ERASE_NOTE_REQUEST_RECEIPT: NoteRequestReceiptErase =
    NoteRequestReceiptErase::KeepReceiptEraseActor;

impl Vault {
    /// Erasing `actor` from the NOTE command receipts (FIX 3879): each
    /// receipt of a command it gave keeps its key, its command hash and its
    /// outcome, and names no one, when [`ACTOR_ERASE_NOTE_REQUEST_RECEIPT`]
    /// says so. One-way, in the erase's own transaction. An id whose entity
    /// is no actor scans nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, or a receipt row that cannot be read.
    #[expect(
        dead_code,
        reason = "the nr:e: declaration names this scrub with the scrub registrations (FIX 3879)"
    )]
    pub(crate) fn erase_note_request_receipt_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let mut erased = Vec::new();
        for (key, (by, receipt)) in NOTE_RECEIPT_BY_REQUEST.scan(&self.store, wtxn)? {
            if by.is(*actor) {
                erased.push((key, receipt));
            }
        }
        for (key, receipt) in erased {
            match ACTOR_ERASE_NOTE_REQUEST_RECEIPT {
                NoteRequestReceiptErase::KeepReceiptEraseActor => {
                    NOTE_RECEIPT_BY_REQUEST.put(
                        &self.store,
                        wtxn,
                        &key,
                        &(NoteActor::Erased, receipt),
                    )?;
                }
                NoteRequestReceiptErase::DeleteReceipt => {
                    NOTE_RECEIPT_BY_REQUEST.delete(&self.store, wtxn, &key)?;
                }
            }
        }
        Ok(())
    }
}
