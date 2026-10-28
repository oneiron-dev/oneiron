//! The outbound path's answer for a handed-off signature (FIX 7690, 9811).
//!
//! The send door confirms nothing. The ordinary delivery path
//! (`feedback/report/delivery.rs`) dispatches each signature under one logical
//! send and writes that send's outcome back here, keyed by its send ref. Only
//! a delivery to the channel makes a signature [`SignatureSendState::Sent`]
//! and records its comm send receipt, once: "delivered" means the channel
//! took it, never that anyone read it (ARCH-0046). The receipt's counterparty
//! is the signature artifact's publisher ACTOR (FIX 7829), which the delivery
//! path resolves from the artifact's publisher metadata.

use super::signature_store::SIGNATURE;
use super::transport::{PUBLISHER_CHANNEL_CLASS, SEND_STATE, SendStateRow};
use super::{PublisherResult, SignatureSendState};
use crate::Vault;
use crate::comm::record_comm_actor_send_receipt_in_txn;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The publisher ACTOR an issue signature's channel runs to: "publisher ↔
/// user is a normal comm channel with that actor as counterparty"
/// (ARCH-0056).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublisherActor {
    /// The actor's vault-resident entity.
    pub(crate) actor: EntityId,
    /// The publisher identity it acts for.
    pub(crate) identity: String,
}

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

/// Writes one send's outcome back onto its signature, in the caller's write:
/// the lane records its outcome and the signature's state together. A
/// delivery confirms the signature and records its comm send receipt to
/// `publisher` in that same write, exactly once; a replay of the outcome
/// already written changes nothing. A delivery with no publisher actor to
/// name is still `Sent`, and records no comm receipt: no placeholder party is
/// minted for it. `publisher` is read before the write takes its writer.
///
/// # Errors
///
/// Storage errors, and whatever `comm.rs`'s send-receipt door raises.
pub(crate) fn record_signature_delivery_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    signature: EntityId,
    send_ref: &str,
    outcome: SignatureDeliveryOutcome,
    publisher: Option<&PublisherActor>,
) -> PublisherResult<()> {
    let current = SEND_STATE
        .get(&vault.store, &*wtxn, &signature)?
        .unwrap_or_default();
    let Some(next) = settled(&current, send_ref, outcome) else {
        return Ok(());
    };
    if next.state == SignatureSendState::Sent
        && let Some(publisher) = publisher
    {
        record_comm_actor_send_receipt_in_txn(
            vault,
            wtxn,
            publisher.actor,
            &publisher.identity,
            PUBLISHER_CHANNEL_CLASS,
            vault.store.clock.now_recorded_at(),
        )?;
    }
    Ok(SEND_STATE.put(&vault.store, wtxn, &signature, &next)?)
}

/// [`record_signature_delivery_in_txn`] for a finished lane's replay, read
/// first: the write is taken only when the outcome changes the signature's
/// state, so the replay of a settled send writes nothing. `publisher`
/// answers the ACTOR the stored signature's artifact was published by; it is
/// asked only when a delivery is about to be confirmed.
///
/// # Errors
///
/// Storage errors, whatever `publisher` raises, and whatever `comm.rs`'s
/// send-receipt door raises.
pub(crate) fn record_signature_delivery<F>(
    vault: &Vault,
    signature: EntityId,
    send_ref: &str,
    outcome: SignatureDeliveryOutcome,
    publisher: F,
) -> PublisherResult<()>
where
    F: FnOnce(EntityId) -> Result<Option<PublisherActor>>,
{
    let (current, artifact) = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        (
            SEND_STATE
                .get(&vault.store, &rtxn, &signature)?
                .unwrap_or_default(),
            SIGNATURE
                .get(&vault.store, &rtxn, &signature)?
                .map(|stored| stored.artifact()),
        )
    };
    let Some(next) = settled(&current, send_ref, outcome) else {
        return Ok(());
    };
    let publisher = match artifact {
        Some(artifact) if next.state == SignatureSendState::Sent => publisher(artifact)?,
        _ => None,
    };
    vault.try_with_write_txn_grouped(|wtxn| {
        record_signature_delivery_in_txn(
            vault,
            wtxn,
            signature,
            send_ref,
            outcome,
            publisher.as_ref(),
        )
    })
}
