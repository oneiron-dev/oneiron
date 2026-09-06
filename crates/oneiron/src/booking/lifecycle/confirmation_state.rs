use super::*;

pub(super) fn confirmation_receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Option<(Vec<u8>, LifecycleReceiptRow)>, BookingError> {
    let mut found = None;
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, BOOKING_RECEIPT_META_PREFIX)
        .map_err(|error| engine_failure("confirmation receipt scan", error))?
    {
        let (key, raw) = row.map_err(|error| engine_failure("confirmation receipt read", error))?;
        // An unreadable receipt cannot bind any event. Its booking will get a
        // missing-context refusal; it must not hide unrelated valid receipts.
        let Ok(receipt) = decode_row::<LifecycleReceiptRow>(&raw) else {
            continue;
        };
        if receipt.event_ref == *event && receipt.session_hash.is_some() {
            if found.is_some() {
                return Err(refused("booking has competing confirmation receipts"));
            }
            found = Some((key.to_vec(), receipt));
        }
    }
    Ok(found)
}

pub(crate) fn booking_invite_identity(
    vault: &Vault,
    event: &EntityId,
) -> Result<Option<(String, String)>, BookingError> {
    let txn = read_txn(vault)?;
    Ok(confirmation_receipt_in(vault, &txn, event)?
        .and_then(|(_, receipt)| receipt.invite_identity))
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
        put_meta(vault, txn, &key, &encode_row(&receipt)?)?;
    }
    Ok(())
}
