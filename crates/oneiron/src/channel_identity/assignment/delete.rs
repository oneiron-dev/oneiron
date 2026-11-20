//! Assignment cleanup for a deleted ChannelIdentity: its references in the
//! slot index and its own `channel_identity.*` claim heads, staged in the
//! SAME write transaction as the deletion.
//! Entry: `clear_assignment_for_delete`. Defines its own items; the slot index stays in `assignment`.

use super::*;

/// Clears every reference to a deleted ChannelIdentity before its body is
/// removed or soft-erased. The caller supplies the stored type while the row
/// is still readable, and stages this in the SAME write transaction as deletion.
///
/// Scan the small assignment projection rather than deriving just one key
/// from the body: a damaged body or stray second slot must not leave a dangling
/// occupant or predecessor behind. A successor in the other slot is preserved.
///
/// A self-held row holds its address forever (never-recycle), so its delete
/// keeps it as the key's occupant: the record goes, the address stays bound to
/// the deleted id, and a fresh id is refused (H102). The deletion marker below
/// is what tells readers that occupant routes nothing. A delegated row frees
/// its key, as its retirement does.
pub(crate) fn clear_assignment_for_delete(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(());
    }
    // FIX 6424 part 3: the erased identity's kept lifecycle receipts go.
    crate::channel_identity_lifecycle::drop_lifecycle_requests_of_identity_in_txn(store, txn, id)?;
    crate::phone_line::drop_identity_in_txn(store, txn, id)?;
    // Its mailbox progress and the messages a run set aside from its mailbox
    // go with it, on the tear and the soft erase alike.
    crate::channel_identity_provider::mailbox_cursor::drop_mailbox_cursor_in_txn(store, txn, id)?;
    crate::channel_identity_provider::mailbox_skipped::drop_skipped_messages_in_txn(
        store, txn, id,
    )?;
    crate::channel_identity_provider::native_mail::drop_native_mail_skipped_messages_in_txn(
        store, txn, id,
    )?;
    let holds_address = match store.port_entity_record(txn, id)? {
        Some(row) => match decode_channel_identity_body(&row.body) {
            Ok(row) => !row.is_delegated(),
            // A soft erase's shell kept the hold it took then.
            Err(_) => ERASED.get(store, txn, id)?.is_some(),
        },
        None => false,
    };
    let mut changed = Vec::new();
    for item in SLOTS.iter_from(store, &*txn, &[])? {
        let (key, mut slot) = item?;
        let mut touched = false;
        let (occupant, predecessor) = slot.split_at_mut(16);
        if occupant == id.as_bytes() && !holds_address {
            occupant.fill(0);
            touched = true;
        }
        if predecessor == id.as_bytes() {
            predecessor.fill(0);
            touched = true;
        }
        if touched {
            changed.push((key, slot));
        }
    }
    for (key, slot) in changed {
        if slot == [0; 32] {
            SLOTS.delete(store, txn, &key)?;
        } else {
            SLOTS.put(store, txn, &key, &slot)?;
        }
    }
    // Soft erase retains the type-index row and a metadata-only shell. This
    // marker proves that empty body was deleted rather than live corruption,
    // and on either tier marks a kept occupant as a hold. It is retired on put.
    ERASED.put(store, txn, id, &[1])?;
    Ok(())
}

/// Closes a deleted ChannelIdentity's own `channel_identity.*` heads, the
/// claim half of [`clear_assignment_for_delete`] (OF-272). The caller stages
/// it in the SAME write transaction as the deletion, with the type it read
/// while the row was still readable, and BEFORE the deletion tears the
/// `claim_of` edges the heads are found by: each live head is closed
/// `retracted` at `now` on the family's engine-owned setting, so a deleted
/// identity has no live facts and its heads leave the live postings. Other
/// kinds are left alone.
pub(crate) fn close_claim_heads_for_delete_in_txn(
    writer: &crate::counterparty_contact::ClaimHeadWriter<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    now: u64,
) -> Result<()> {
    if entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(());
    }
    writer.retract_subject_heads_in_txn(txn, id, is_channel_identity_claim_predicate, now)?;
    Ok(())
}
