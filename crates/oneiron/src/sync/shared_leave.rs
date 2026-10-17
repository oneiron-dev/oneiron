//! Leaving a shared vault, the device side (OF-158). A member device keeps a
//! shared vault in an env of its own. Once a notice confirms that this member
//! left or was removed, the device drops what it queued to send there and
//! records how much unsynced work that discarded. Only a notice confirms it:
//! a removed member's slips are revoked, so a refused reconnect (a 401) is
//! never read as a leave.
//!
//! What goes is only what is provably that vault's: the queued window
//! updates (`q:`, with their `d:` sidecars), the unacknowledged text frames
//! (`qd:e:`) and the pending NOTE commands (`qn:e:`) of the env that holds
//! it. The env's replica rows are dropped by the host with the env.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::federation::{SharedActOutcome, SharedVaultChange};
use crate::side_table::{self, Named, Raw, SideTable};

/// This device's leave records, keyed by the notice's receipt id.
const LEAVE_RECEIPTS: SideTable<String, SharedLeaveReceipt, Named> =
    SideTable::new(&side_table::SYNC_SHARED_LEAVE_RECEIPT);

/// Unacknowledged local text-document frames.
const QUEUED_TEXT_FRAMES: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_QD_E);

/// Pending semantic NOTE commands.
const QUEUED_NOTE_COMMANDS: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QN_E);

/// Rows one purge pass of the left env deletes, a transaction each
/// ([`crate::store::local_replica::purge_left_shared_env_in_txn`]).
const LEAVE_PURGE_ROWS_PER_PASS: usize = 4096;

/// How this member's membership ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedLeaveKind {
    /// The member left.
    Left,
    /// A holder removed the member.
    Removed,
}

/// The local record that this device left a shared vault: the notice it
/// confirmed and the unsynced edits the leave discarded. Local only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedLeaveReceipt {
    /// The shared-act receipt the notice names.
    pub notice_receipt: String,
    pub vault_id: u64,
    /// The member (person id, hex) who left.
    pub member: String,
    pub kind: SharedLeaveKind,
    /// When the shared vault recorded the change.
    pub changed_at: u64,
    /// When this device discarded its queued edits.
    pub completed_at: u64,
    /// Queued window updates discarded (`q:` rows).
    pub discarded_window_updates: u64,
    /// Unacknowledged text frames discarded (`qd:e:` rows).
    pub discarded_text_frames: u64,
    /// Pending NOTE commands discarded (`qn:e:` rows).
    pub discarded_note_commands: u64,
    /// Every unsynced edit the leave discarded: the three counts together.
    pub discarded_unsynced_edits: u64,
    /// The env's replica rows the leave purged: entity, edge, index, side and
    /// sync rows.
    pub purged_rows: u64,
    /// The entities the purge kept: authority log and machine rows, rows a
    /// legal hold names, and the pinned pack map.
    pub kept_entities: u64,
}

/// How `notice` ends `member`'s membership in shared vault `vault_id`, when
/// it is that member's own MemberLeft or MemberRemoved notice for it.
#[must_use]
pub fn left_change(
    notice: &SharedActOutcome,
    vault_id: u64,
    member: &str,
) -> Option<SharedLeaveKind> {
    if notice.vault_id != vault_id || notice.recipient != member {
        return None;
    }
    match &notice.change {
        SharedVaultChange::MemberLeft { member: who } if who == member => {
            Some(SharedLeaveKind::Left)
        }
        SharedVaultChange::MemberRemoved { member: who } if who == member => {
            Some(SharedLeaveKind::Removed)
        }
        _ => None,
    }
}

/// Whether this env's device has left the shared vault it holds.
///
/// # Errors
///
/// Storage errors.
pub fn has_left(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(LEAVE_RECEIPTS
        .iter_from(&vault.store, &txn, &[])?
        .next()
        .is_some())
}

/// Confirms, in `vault` (the env that holds shared vault `vault_id`), that
/// `member` left it: discards every queued window update, text frame and NOTE
/// command, records the counts and runs the first purge pass of the env's
/// replica rows in one transaction, then purges the rest a pass at a time
/// and records what went and what stayed. Idempotent: a notice already
/// confirmed finishes any purge an interrupted call left and answers its
/// receipt. Stop the env's sync lane first
/// (`SyncConnection::confirm_shared_leave` does), so no buffered update lands
/// after the discard and nothing refills the env.
///
/// # Errors
///
/// A notice that is not `member`'s own leave of `vault_id`; storage errors.
pub fn confirm_shared_leave(
    vault: &Vault,
    vault_id: u64,
    member: &str,
    notice: &SharedActOutcome,
) -> Result<SharedLeaveReceipt> {
    let Some(kind) = left_change(notice, vault_id, member) else {
        return Err(Error::InvalidConfig(
            "the notice is not this member's leave of this shared vault".into(),
        ));
    };
    let purge = |wtxn: &mut heed::RwTxn<'_>, receipt: &mut SharedLeaveReceipt| -> Result<bool> {
        let pass = crate::store::local_replica::purge_left_shared_env_in_txn(
            &vault.store,
            wtxn,
            LEAVE_PURGE_ROWS_PER_PASS,
        )?;
        let rows = [
            pass.entities,
            pass.edges,
            pass.index_rows,
            pass.side_rows,
            pass.sync_rows,
        ]
        .into_iter()
        .fold(0_u64, |total, rows| total.saturating_add(count(rows)));
        receipt.purged_rows = receipt.purged_rows.saturating_add(rows);
        receipt.kept_entities = count(pass.kept_total);
        LEAVE_RECEIPTS.put(&vault.store, wtxn, &notice.receipt_id, receipt)?;
        Ok(pass.complete)
    };
    let (mut receipt, mut complete) = vault.with_write_txn_grouped(|wtxn| {
        if let Some(mut receipt) = LEAVE_RECEIPTS.get(&vault.store, wtxn, &notice.receipt_id)? {
            // Confirmed before: finish the purge an interrupted call left.
            let complete = purge(wtxn, &mut receipt)?;
            return Ok((receipt, complete));
        }
        let discarded_window_updates =
            crate::sync::queue::discard_updates_for_leave_in_txn(vault, wtxn)?;
        let discarded_text_frames =
            count(QUEUED_TEXT_FRAMES.delete_from(&vault.store, wtxn, &[])?);
        let discarded_note_commands =
            count(QUEUED_NOTE_COMMANDS.delete_from(&vault.store, wtxn, &[])?);
        let mut receipt = SharedLeaveReceipt {
            notice_receipt: notice.receipt_id.clone(),
            vault_id,
            member: member.to_owned(),
            kind,
            changed_at: notice.completed_at,
            completed_at: crate::unix_seconds_now(),
            discarded_window_updates,
            discarded_text_frames,
            discarded_note_commands,
            discarded_unsynced_edits: discarded_window_updates
                .saturating_add(discarded_text_frames)
                .saturating_add(discarded_note_commands),
            purged_rows: 0,
            kept_entities: 0,
        };
        let complete = purge(wtxn, &mut receipt)?;
        Ok((receipt, complete))
    })?;
    while !complete {
        complete = vault.with_write_txn_grouped(|wtxn| purge(wtxn, &mut receipt))?;
    }
    Ok(receipt)
}

fn count(rows: usize) -> u64 {
    u64::try_from(rows).unwrap_or(u64::MAX)
}
