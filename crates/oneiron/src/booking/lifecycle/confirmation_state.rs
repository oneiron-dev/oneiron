//! The confirmation receipt's session and invite-identity bindings, read and
//! bound inside the caller's transaction.
use super::LifecycleReceiptRow;
use super::storage::{RECEIPT, engine_failure, read_txn, refused};
use crate::booking::BookingError;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The confirmation receipt of a live booking EVENT. An erased or absent
/// EVENT has none to read (FIX 9636): what its receipt kept about its
/// parties is never returned for it.
pub(super) fn confirmation_receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Option<([u8; 32], LifecycleReceiptRow)>, BookingError> {
    if !live_entity_row_in_txn(&vault.store, txn, event)
        .map_err(|error| engine_failure("booking EVENT liveness", error))?
        .is_live()
    {
        return Ok(None);
    }
    let mut found = None;
    for row in RECEIPT
        .iter_from(&vault.store, txn, &[])
        .map_err(|error| engine_failure("confirmation receipt scan", error))?
    {
        // An unreadable receipt cannot bind any event. Its booking will get a
        // missing-context refusal; it must not hide unrelated valid receipts.
        let Ok((key, receipt)) = row else {
            continue;
        };
        if receipt.event_ref == *event && receipt.session_hash.is_some() {
            if found.is_some() {
                return Err(refused("booking has competing confirmation receipts"));
            }
            found = Some((key, receipt));
        }
    }
    Ok(found)
}

pub(crate) fn booking_invite_identity(
    vault: &Vault,
    event: &EntityId,
) -> Result<Option<(String, String)>, BookingError> {
    let txn = read_txn(vault)?;
    booking_invite_identity_in_txn(vault, &txn, event)
}

pub(crate) fn booking_invite_identity_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Option<(String, String)>, BookingError> {
    Ok(
        confirmation_receipt_in(vault, txn, event)?
            .and_then(|(_, receipt)| receipt.invite_identity),
    )
}

/// Set once by CAL's real invite admission, in the passport write transaction.
/// Provider EVENT rewrites and later owners cannot change this identity.
pub(crate) fn bind_booking_invite_identity_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event: &EntityId,
    organizer: &str,
    recipient: &str,
) -> Result<(), BookingError> {
    let Some((key, mut receipt)) = confirmation_receipt_in(vault, txn, event)? else {
        return Ok(());
    };
    if let Some(prior) = &receipt.invite_identity {
        if prior != &(organizer.to_owned(), recipient.to_owned()) {
            return Err(refused(
                "calendar revision changes the original booking organizer",
            ));
        }
    } else {
        receipt.invite_identity = Some((organizer.to_owned(), recipient.to_owned()));
        RECEIPT
            .put(&vault.store, txn, &key, &receipt)
            .map_err(|error| engine_failure("meta write", error))?;
    }
    Ok(())
}

/// Scrubs what an erased booking EVENT's lifecycle receipts keep about its
/// parties (FIX 9636): the confirmation's intake, booker and zones, and the
/// invite's organizer and recipient addresses. The revision identity a
/// receipt replays (EVENT, UID, SEQUENCE, session) stays. A per-entity
/// eraser (`deletion::derived_rows`): it runs in the erase transaction at
/// both delete doors, and an entity that is not a booking EVENT is a no-op.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_booking_receipt_carriers_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> crate::Result<()> {
    if let LiveEntityRow::Live { entity_type, .. } = live_entity_row_in_txn(store, txn, entity)?
        && entity_type != ENTITY_TYPE_EVENT
    {
        return Ok(());
    }
    let mut scrubbed = Vec::new();
    for row in RECEIPT.iter_from(store, txn, &[])? {
        let Ok((key, mut receipt)) = row else {
            continue;
        };
        if receipt.event_ref == *entity
            && (receipt.confirmation.is_some() || receipt.invite_identity.is_some())
        {
            receipt.confirmation = None;
            receipt.invite_identity = None;
            scrubbed.push((key, receipt));
        }
    }
    for (key, receipt) in scrubbed {
        RECEIPT.put(store, txn, &key, &receipt)?;
    }
    Ok(())
}
