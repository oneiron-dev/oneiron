//! An asked reveal's inbox Ask (FIX 2355): one notice per live owner, so an
//! open ask waits in the inbox, not only at the reveal door.

use super::RevealRow;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, Vault, live_entity_row_in_txn};

/// Producer name of an asked reveal's inbox Ask.
pub(crate) const NOTIFICATION_PRODUCER_SECRET_REVEAL: &str = "secret.reveal";

/// What an asked reveal's notice says. The handle and the ids ride in the
/// notice's result and subjects; no value is anywhere in it.
const SECRET_REVEAL_NOTICE_DETAIL: &str =
    "an agent asks to read a secret; answer it at the secret reveal door";

/// Raises the inbox Ask of the reveal `file_ask_in_txn` just asked (FIX
/// 2355): one [`NotificationKind::Ask`] notice per live owner, keyed by the
/// reveal, its once digest and the owner, whose result names the reveal and
/// whose subjects name the secret. The ids it returns land on the row,
/// replacing the re-ask's settled ones.
///
/// # Errors
/// Storage errors.
pub(super) fn notify_reveal_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reveal: &EntityId,
    row: &mut RevealRow,
) -> Result<()> {
    let once = row.stored_once_digest()?.to_hex();
    let reveal_hex = reveal.to_hex();
    let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut notices = Vec::new();
    for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
        notices.push(vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_SECRET_REVEAL.to_owned(),
                    event: format!("{reveal_hex}:{once}:{}", owner.to_hex()),
                    result: Some(reveal_hex.clone()),
                    detail: Some(SECRET_REVEAL_NOTICE_DETAIL.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: vec![row.secret],
                recipient: Some(owner),
                created_at,
                origin_conversation: None,
            },
        )?);
    }
    row.notices = notices;
    Ok(())
}

/// Settles the inbox Asks `row` raised (FIX 2355): each id still a live
/// NOTIFICATION is marked seen and acked for the owner it was raised for,
/// as a cleared takeover ask is, then the row holds none. A notice already
/// acked, or gone, stays as it is.
///
/// # Errors
/// Storage errors.
pub(super) fn settle_reveal_notices_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &mut RevealRow,
) -> Result<()> {
    for notice in &row.notices {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*txn, notice)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        let Some(owner) = body.recipient.clone() else {
            continue;
        };
        if body.acked_by.get(&owner) == Some(&true) {
            continue;
        }
        body.seen_by.insert(owner.clone(), true);
        body.acked_by.insert(owner, true);
        vault.put_notification_in_txn(txn, notice, &body)?;
    }
    row.notices.clear();
    Ok(())
}
