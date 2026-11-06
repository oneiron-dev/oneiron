//! Owner inbox notices for stock switches that actually applied.

use super::{OfferSwitchReceipt, STOCK_SWITCH_NOTIFICATION_PRODUCER, SwitchApplication};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::{Result, Vault};

/// Shares the binding's write, including a staged embedder move's later swap.
/// Replays preserve the inbox row's seen, acknowledged and deleted state.
pub(super) fn record_applied_switch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &OfferSwitchReceipt,
) -> Result<()> {
    let at = match &receipt.application {
        SwitchApplication::Bound => receipt.at,
        SwitchApplication::Applied { at } => *at,
        _ => return Ok(()),
    };
    let offer = receipt.offer.to_hex();
    for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Finding,
                source: NotificationSource {
                    producer: STOCK_SWITCH_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{offer}:{}", owner.to_hex()),
                    result: Some(offer.clone()),
                    ..NotificationSource::default()
                },
                subject_refs: vec![receipt.offer],
                recipient: Some(owner),
                created_at: at,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}
