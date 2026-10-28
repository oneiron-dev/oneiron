//! The outbound path's answer for a handed-off signature (FIX 7690, 9811).
//!
//! The send door confirms nothing. The ordinary delivery path
//! (`feedback/report/delivery.rs`) dispatches each signature under one logical
//! send and writes that send's outcome back here, keyed by its send ref. Only
//! a delivery to the channel makes a signature [`SignatureSendState::Sent`]
//! and records its comm send receipt, once: "delivered" means the channel
//! took it, never that anyone read it (ARCH-0046).

use super::transport::{PUBLISHER_CHANNEL_CLASS, PUBLISHER_PARTY_KEY, SEND_STATE, SendStateRow};
use super::{PublisherResult, SignatureSendState};
use crate::Vault;
use crate::comm::record_comm_send_receipt_in_txn;
use crate::entity_id::EntityId;
use crate::error::Error;

/// What the ordinary outbound path answered for one signature's send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureDeliveryOutcome {
    /// The channel acknowledged it: `delivered_to_channel`, never "seen".
    Delivered,
    /// It may have landed; the outbound ledger reconciles it.
    Uncertain,
    /// It did not leave on this send.
    NotDelivered,
}

impl SignatureDeliveryOutcome {
    const fn state(self) -> SignatureSendState {
        match self {
            Self::Delivered => SignatureSendState::Sent,
            Self::Uncertain => SignatureSendState::Uncertain,
            Self::NotDelivered => SignatureSendState::NotDelivered,
        }
    }
}

/// The row `outcome` of send `send_ref` leaves, or `None` when it changes
/// nothing: a confirmed signature stays confirmed, and a replay of the
/// outcome already written is a no-op.
fn settled(
    current: &SendStateRow,
    send_ref: &str,
    outcome: SignatureDeliveryOutcome,
) -> Option<SendStateRow> {
    let next = SendStateRow {
        state: outcome.state(),
        send_ref: Some(send_ref.to_owned()),
    };
    (current.state != SignatureSendState::Sent && *current != next).then_some(next)
}

/// Writes one send's outcome back onto its signature, in the caller's write.
/// A delivery confirms the signature and records its comm send receipt in
/// that same write, exactly once.
fn record_signature_delivery_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    signature: EntityId,
    send_ref: &str,
    outcome: SignatureDeliveryOutcome,
) -> PublisherResult<()> {
    let current = SEND_STATE
        .get(&vault.store, &*wtxn, &signature)?
        .unwrap_or_default();
    let Some(next) = settled(&current, send_ref, outcome) else {
        return Ok(());
    };
    if next.state == SignatureSendState::Sent {
        record_comm_send_receipt_in_txn(
            vault,
            wtxn,
            PUBLISHER_PARTY_KEY,
            PUBLISHER_CHANNEL_CLASS,
            vault.store.clock.now_recorded_at(),
        )?;
    }
    Ok(SEND_STATE.put(&vault.store, wtxn, &signature, &next)?)
}

/// Writes one send's outcome back onto its signature, in a write taken only
/// when the outcome changes the signature's state: the replay of a settled
/// send writes nothing. A crash before it runs leaves the lane's own record,
/// whose next run replays the outcome here.
///
/// # Errors
///
/// Storage errors, and whatever `comm.rs`'s send-receipt door raises.
pub(crate) fn record_signature_delivery(
    vault: &Vault,
    signature: EntityId,
    send_ref: &str,
    outcome: SignatureDeliveryOutcome,
) -> PublisherResult<()> {
    let current = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        SEND_STATE
            .get(&vault.store, &rtxn, &signature)?
            .unwrap_or_default()
    };
    if settled(&current, send_ref, outcome).is_none() {
        return Ok(());
    }
    vault.try_with_write_txn_grouped(|wtxn| {
        record_signature_delivery_in_txn(vault, wtxn, signature, send_ref, outcome)
    })
}
