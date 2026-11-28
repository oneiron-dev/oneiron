//! Which records a customer hold's sealed captures hold: one empty row per (hold, record,
//! capture), for the erase answer's legal copy count. A hold's own row names its explicit
//! targets but no prospective member and no inquiry's kept copy CLAIM, and a flushed capture
//! names only its id; these rows name the members each seal wrote. Rows are evidence of the
//! copy, so they outlive the record's erase and go with the hold's copy when it is dropped.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::deletion::LegalHold;
use crate::deletion::legal_hold::holds_capture;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable, SideTableDbs};

/// Which records a hold's sealed captures hold. Key: id16 (hold) + id16 (record) + id16
/// (capture); the value is empty.
pub(super) const SEALED_RECORDS: SideTable<([u8; 16], [u8; 16], [u8; 16]), Vec<u8>, Raw> =
    SideTable::new(&side_table::LEGAL_HOLD_SEALED_RECORD);

/// Records that `capture` of `hold` holds each of `records`: one empty row per record, in the
/// writer that sealed them.
pub(crate) fn put_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hold: &[u8; 16],
    capture: &[u8; 16],
    records: &[[u8; 16]],
) -> Result<()> {
    for record in records {
        SEALED_RECORDS.put(dbs, txn, &(*hold, *record, *capture), &Vec::new())?;
    }
    Ok(())
}

/// Drops every sealed-record row of `hold`, with its copy; returns how many went.
pub(crate) fn drop_hold_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hold: &[u8; 16],
) -> Result<usize> {
    SEALED_RECORDS.delete_from(dbs, txn, hold)
}

/// Whether `hold`'s sealed copy holds `record`, by its rows: `None` when no row (hold, record, C)
/// exists; otherwise whether some row's capture landed (named in `clone_captures`, with its file
/// and the hold's key in this install's hold store) or, for a hold that names future messages,
/// waits sealed in the outbox for its flush.
pub(crate) fn kept_copy_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    hold: &LegalHold,
    record: &EntityId,
) -> Result<Option<bool>> {
    let store = &vault.store;
    let mut start = Vec::with_capacity(32);
    start.extend_from_slice(hold.hold_id.as_bytes());
    start.extend_from_slice(record.as_bytes());
    let pending = if hold.future_messages.is_some() {
        crate::deletion::legal_hold::prospective::owner_pending_capture_in_txn(
            store,
            txn,
            hold.hold_id.as_bytes(),
        )?
    } else {
        None
    };
    let mut rows = false;
    for row in SEALED_RECORDS.iter_from(store, txn, &start)? {
        let ((holder, held, capture), _) = row?;
        if holder != *hold.hold_id.as_bytes() || held != *record.as_bytes() {
            break;
        }
        rows = true;
        if pending == Some(capture) {
            return Ok(Some(true));
        }
        if let Some(named) = hold
            .clone_captures
            .iter()
            .find(|named| *named.capture.as_bytes() == capture)
            && holds_capture(vault, &hold.hold_id, &named.capture)?
        {
            return Ok(Some(true));
        }
    }
    Ok(rows.then_some(false))
}

/// Whether this install's hold store holds any capture `hold` names: the rule for a Record
/// target sealed before sealed-record rows, which no row names. A hold row restored from an
/// archive names its source's captures, whose files stayed with the source.
pub(crate) fn holds_any_capture(vault: &Vault, hold: &LegalHold) -> Result<bool> {
    for named in &hold.clone_captures {
        if holds_capture(vault, &hold.hold_id, &named.capture)? {
            return Ok(true);
        }
    }
    Ok(false)
}
