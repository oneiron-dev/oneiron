//! A courtesy try across this vault's own host re-root (FIX 5088; Engine
//! 10-19 15:0x). An ask or answer the owner queued keeps the bytes the root
//! of that day signed, for audit. Once a re-root hands that root on, each
//! try is signed again from that durable body by the live root, the same
//! ask or answer with the same clock and nonce, so a peer that kept the
//! successor's ReRoot row (FIX 3014) files it. Only a still-pending leg is
//! signed again, inside the writer that starts its try and while the claim
//! still holds the try's lease. A signature no root of this vault handed on
//! from (an ask the owner brought signed by another key) goes as queued, and
//! the owner's resend stays.
//!
//! The peer files a same-nonce ask once: the same body under the walked tip's
//! signature is the ask it already holds ([`same_ask`]).

use rmpv::Value;

use super::super::coop_request::{
    decode, decode_self_signed_cooperative_deletion_request, envelope_signature, fields,
};
use super::*;
use crate::authority::{AuthorityFold, AuthorityKey, HostSlipIssuer};

/// What starting one claimed try found, in its writer.
pub(super) enum TryStart {
    /// The leg is `sent`, and these bytes go.
    Send(Vec<u8>),
    /// The ledger row is gone or past sending: the try fails here.
    Settled,
    /// The claim no longer holds the try's lease: nothing moved.
    NotHeld,
}

/// Starts one claimed try in `txn`: the claim's lease first, then the leg
/// `sent`, then the bytes it sends, signed again by `issuer` where a root
/// it succeeded signed them ([`resigned`]).
pub(super) fn start_try_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptRecord,
    lease_owner: &str,
    payload: &DeliveryPayload,
    issuer: Option<&HostSlipIssuer>,
    now: u64,
) -> Result<TryStart> {
    if !AttemptQueue::new(vault).holds_lease_in_txn(
        txn,
        attempt.id,
        lease_owner,
        attempt.attempt_count,
    )? {
        return Ok(TryStart::NotHeld);
    }
    if !move_leg(
        vault,
        txn,
        payload,
        CooperativeDeletionDeliveryStatus::Sent,
        now,
    )? {
        return Ok(TryStart::Settled);
    }
    let resigned = match issuer {
        Some(issuer) => resigned(vault, txn, issuer, payload)?,
        None => None,
    };
    Ok(TryStart::Send(
        resigned.unwrap_or_else(|| payload.bytes.clone()),
    ))
}

/// A queued envelope, verified against the key it carries.
enum Queued {
    Request(SignedCooperativeDeletionRequest),
    Reply(SignedCooperativeDeletionReply),
}

impl Queued {
    /// The leg's queued envelope, or `None` when its bytes are not one.
    fn of(payload: &DeliveryPayload) -> Option<Self> {
        let bytes = &payload.bytes;
        match payload.leg {
            Leg::Request => decode_self_signed_cooperative_deletion_request(bytes)
                .ok()
                .map(Self::Request),
            Leg::Reply => {
                let envelope = decode(bytes).ok()?;
                let signature =
                    envelope_signature(fields(&envelope, &["body", "signature"]).ok()?[1]).ok()?;
                let body =
                    decode_and_verify_cooperative_deletion_reply(bytes, &signature.public_key)
                        .ok()?;
                Some(Self::Reply(SignedCooperativeDeletionReply {
                    body,
                    signature,
                }))
            }
        }
    }

    /// Its pact and nonce, the vault that signs it (the asker, or the one
    /// that answers), and its signer.
    fn binding(&self) -> ([u8; 32], [u8; 16], [u8; 32], &AuthorityKey) {
        match self {
            Self::Request(ask) => (
                ask.body.pact_id,
                ask.body.nonce,
                ask.body.requester_vault_id,
                &ask.signature.public_key,
            ),
            Self::Reply(reply) => (
                reply.body.pact_id,
                reply.body.nonce,
                reply.body.responder_vault_id,
                &reply.signature.public_key,
            ),
        }
    }

    /// The same body under `issuer`'s signature, encoded.
    fn signed_by(&self, issuer: &HostSlipIssuer, fold: &AuthorityFold) -> Result<Vec<u8>> {
        match self {
            Self::Request(ask) => encode_signed_cooperative_deletion_request(
                &issuer.resign_cooperative_deletion_request(fold, &ask.body)?,
            ),
            Self::Reply(reply) => encode_signed_cooperative_deletion_reply(
                &issuer.resign_cooperative_deletion_reply(fold, &reply.body)?,
            ),
        }
    }
}

/// The try's queued envelope signed again by `issuer`, or `None` to send it
/// as queued. It is signed again only when it verifies against its own
/// signer, names this leg's pact and nonce and this vault, its signer is not
/// `issuer`'s key but one this vault's settled ReRoot rows hand on to it,
/// and `issuer` is the vault's live root in `txn`'s snapshot. A fold this
/// snapshot cannot answer signs nothing again.
fn resigned(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issuer: &HostSlipIssuer,
    payload: &DeliveryPayload,
) -> Result<Option<Vec<u8>>> {
    let Some(queued) = Queued::of(payload) else {
        return Ok(None);
    };
    let (pact, nonce, signed_for, signer) = queued.binding();
    let successor = issuer.public_key();
    if (pact, nonce) != payload.ids()? || *signer == successor {
        return Ok(None);
    }
    let Ok(fold) = vault.authority_view_readonly_in_txn(txn) else {
        return Ok(None);
    };
    if fold.vault_id != Some(signed_for)
        || !vault.root_handed_on_in_txn(txn, &fold, signer, &successor)?
    {
        return Ok(None);
    }
    Ok(queued.signed_by(issuer, &fold).ok())
}

/// Whether `bytes`, an ask already verified under its pact's walked tip, is
/// the ask `filed` holds signed again (FIX 5088): the same canonical body,
/// so the same pact, clock, worlds, cutoff and nonce. The filed bytes are
/// never verified again under the new tip: they were authenticated when
/// filed, and stay as filed.
pub(super) fn same_ask(filed: &[u8], bytes: &[u8]) -> bool {
    envelope_body(filed).is_some_and(|filed| envelope_body(bytes) == Some(filed))
}

/// The canonical body bytes an envelope carries, read without verifying it.
fn envelope_body(bytes: &[u8]) -> Option<Value> {
    let envelope = decode(bytes).ok()?;
    Some(fields(&envelope, &["body", "signature"]).ok()?[0].clone())
}
