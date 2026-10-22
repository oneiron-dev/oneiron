//! A wait's delivered and settled replies, read before they decode (FIX
//! 9390): a row whose reply never decoded is carried whole by a checkpoint,
//! and its retired form is the explicit erased marker. Each canonical reader
//! takes its row through here, so the marker answers the typed unavailable
//! `ResponseErased`, as an erased reply does, and never a missing reply that
//! is waited on, delivered or asked again.

use super::{DELIVERIES, SETTLED, SETTLED_TAG, WaitDelivery};
use crate::side_table::SideTableDbs;
use crate::store::{ResponseFamily, ResponseRead};
use crate::{EntityId, Result};

/// The delivery row `row` (run, wait, generation), as `txn` holds it.
///
/// # Errors
///
/// Storage errors, a row that does not decode, and `ResponseErased` for the
/// erased marker.
pub(super) fn delivery_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    row: &(EntityId, EntityId, u64),
) -> Result<Option<WaitDelivery>> {
    let Some(raw) = DELIVERIES.get_bytes(dbs, txn, row)? else {
        return Ok(None);
    };
    let key = DELIVERIES.key_bytes(row);
    let raw = ResponseRead::of(ResponseFamily::WaitDelivery, &key, &raw).present()?;
    DELIVERIES.decode_value(raw).map(Some)
}

/// The settled row of `wait_id`, as `txn` holds it.
///
/// # Errors
///
/// Storage errors, a row that does not decode, and `ResponseErased` for the
/// erased marker.
pub(super) fn settled_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    wait_id: EntityId,
) -> Result<Option<WaitDelivery>> {
    let row = (SETTLED_TAG, wait_id);
    let Some(raw) = SETTLED.get_bytes(dbs, txn, &row)? else {
        return Ok(None);
    };
    let key = SETTLED.key_bytes(&row);
    let raw = ResponseRead::of(ResponseFamily::WaitSettled, &key, &raw).present()?;
    SETTLED.decode_value(raw).map(Some)
}
