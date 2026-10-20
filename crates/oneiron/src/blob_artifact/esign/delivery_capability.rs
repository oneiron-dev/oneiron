//! Fresh signing links at delivery export (FIX 5238 option 3, the owner's KEY
//! STORE = A ruling: no recoverable secret at rest).
//!
//! Every invitation and reminder delivery carries a link minted for its
//! recipient when the delivery exports: the invitation, each reminder, each
//! resend. The vault keeps only the link's digest and non-secret export
//! metadata; the raw link reaches the delivery envelope and nothing else.
//! Each link works until the document's deadline, its own revocation or the
//! document's end, and a later delivery never revokes an earlier one.
//!
//! A mint runs under the send's authority as it stands under the mint
//! writer, never under the queued row alone: the vault owner's own recorded
//! act, or a Grant still live that covers the send, with the principal dial
//! still permitting an automated sender. Anything short of that holds the
//! delivery unexported with its reason; it is never dropped.

use super::capability::{EsignCapability, delivered_digest_in, mint_delivery_capability_in_txn};
use super::ledger::state_in;
use super::model::*;
use super::notice_dispatch::EsignNotice;
use super::outbound::{EsignOutboundVerb, dispatch_marker_in};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::{EntityId, Result, Vault};

/// The queue kind the vault keeps authorized e-sign mail under.
const DELIVERY_KIND: &str = "esign.delivery";

/// A fresh signing link for one delivery lease.
pub struct EsignDeliveryLink {
    /// The bearer capability: the recipient opens the signing page with it
    /// as the fragment (`/sign#<capability>`).
    pub capability: EsignCapability,
    /// When the link stops working: the document's deadline.
    pub hard_expires_at: u64,
}

/// What one delivery mint came to.
pub enum EsignDeliveryMint {
    Minted(EsignDeliveryLink),
    /// Nothing was minted, for this reason; the delivery stays queued.
    Held(&'static str),
}

impl EsignNotice {
    /// Whether this notice's delivery carries a signing link: an invitation
    /// or a reminder. Every other notice goes out without one.
    #[must_use]
    pub fn carries_signing_link(&self) -> bool {
        matches!(self.transition.as_str(), "invite" | "reminder")
    }
}

impl Vault {
    /// Mints the signing link of the invitation or reminder that `attempt`
    /// delivers under its current lease (`lease_owner`, `attempt_count`),
    /// re-read under this writer. `deliver` is the exporter's digest of the
    /// content it delivers with the link and its hard expiry; the vault keeps
    /// it beside the lease, so an ack, a completion receipt and a restart all
    /// bind that exact content. The raw link is returned to the exporter
    /// alone.
    /// # Errors
    /// A row whose notice is unreadable or carries no link, or a storage
    /// failure. A delivery the mint may not serve is [`EsignDeliveryMint::Held`].
    pub fn mint_esign_delivery_link(
        &self,
        attempt: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        deliver: &dyn Fn(&EsignCapability, u64) -> [u8; 32],
    ) -> Result<EsignDeliveryMint> {
        self.with_write_txn_grouped(|txn| {
            let Some(raw) = self.store.attempt_records.get(txn, attempt.as_bytes())? else {
                return Ok(EsignDeliveryMint::Held("the delivery is no longer queued"));
            };
            let row = crate::attempt_queue::decode_record(&raw, attempt)?;
            if row.kind != DELIVERY_KIND
                || row.state != AttemptState::Leased
                || row.lease_owner.as_deref() != Some(lease_owner)
                || row.attempt_count != attempt_count
            {
                return Ok(EsignDeliveryMint::Held("the delivery's lease ended"));
            }
            let notice = notice_of(&row)?;
            if !notice.carries_signing_link() {
                return Err(invalid("this delivery carries no signing link"));
            }
            let Some(dispatch_ref) = notice.dispatch_ref.as_deref() else {
                return Ok(EsignDeliveryMint::Held(
                    "the delivery names no admitted send",
                ));
            };
            let document = EntityId::from_hex(&notice.document)?;
            let key = match notice.transition.as_str() {
                "reminder" => format!(
                    "{}:reminder:{}:{dispatch_ref}",
                    notice.document, notice.recipient
                ),
                _ => format!("{}:invite:{}", notice.document, notice.recipient),
            };
            if row.dedupe_key.as_deref() != Some(key.as_str()) {
                return Ok(EsignDeliveryMint::Held(
                    "the delivery's key does not bind its notice",
                ));
            }
            let state = state_in(self, txn, document)?;
            if let Some(reason) = unsignable(&state, &notice, self.now_recorded_at()) {
                return Ok(EsignDeliveryMint::Held(reason));
            }
            if let Some(reason) = self.delivery_unauthorized_in(txn, &notice, dispatch_ref)? {
                return Ok(EsignDeliveryMint::Held(reason));
            }
            let lease = crate::entity_id::bytes_to_hex_lower(attempt.as_bytes());
            let capability = mint_delivery_capability_in_txn(
                self,
                txn,
                document,
                &notice.recipient,
                state.document.expires_at,
                (&lease, attempt_count),
                deliver,
            )?;
            Ok(EsignDeliveryMint::Minted(EsignDeliveryLink {
                capability,
                hard_expires_at: state.document.expires_at,
            }))
        })
    }

    /// The delivered-content digest the exporter recorded with the link
    /// minted for `row`'s current lease; `None` when no link names it.
    /// # Errors
    /// A row whose notice is unreadable, or a storage failure.
    pub fn esign_delivery_digest(&self, row: &AttemptRecord) -> Result<Option<String>> {
        let notice = notice_of(row)?;
        let document = EntityId::from_hex(&notice.document)?;
        let txn = self.store.env.read_txn()?;
        let lease = crate::entity_id::bytes_to_hex_lower(row.id.as_bytes());
        delivered_digest_in(
            self,
            &txn,
            document,
            &notice.recipient,
            (&lease, row.attempt_count),
        )
    }

    /// Why the send's authority no longer covers minting this delivery's
    /// link, or `None` when it does: the vault owner's own recorded act, or
    /// a Grant live under this writer that covers the admitted call, with an
    /// automated sender's principal dial still at autonomous-in-envelope.
    fn delivery_unauthorized_in(
        &self,
        txn: &heed::RwTxn<'_>,
        notice: &EsignNotice,
        dispatch_ref: &str,
    ) -> Result<Option<&'static str>> {
        let Some(marker) = dispatch_marker_in(self, txn, dispatch_ref)? else {
            return Ok(Some("no admitted send act covers the delivery"));
        };
        let Some(call) = crate::outbound::esign_delivery_call_in_txn(self, txn, dispatch_ref)?
        else {
            return Ok(Some("the send's admitted call is not on the ledger"));
        };
        let verb = if notice.transition == "invite" {
            EsignOutboundVerb::SendForSignature
        } else {
            EsignOutboundVerb::Remind
        };
        if call.target != notice.document
            || call.verb != verb.as_str()
            || call.content_ref.as_deref() != Some(marker.binding.as_str())
        {
            return Ok(Some("the send's admitted call does not cover the delivery"));
        }
        // The owner's own act, recorded with his revalidated proof, covers
        // every delivery it queued.
        let owner_act = marker.owner_act.as_ref().is_some_and(|act| {
            call.actor_entity_ref
                .is_some_and(|actor| actor.to_hex() == act.actor)
        });
        if owner_act {
            return Ok(None);
        }
        if crate::outbound::esign_delivery_grant_in_txn(self, txn, &call)?.is_none() {
            return Ok(Some("no live Grant covers the delivery"));
        }
        if call.actor_class != "human"
            && !super::principals::automated_outbound_allowed(
                self,
                txn,
                call.on_behalf_of.as_deref(),
            )?
        {
            return Ok(Some("the principal's autonomy no longer permits the send"));
        }
        Ok(None)
    }
}

fn notice_of(row: &AttemptRecord) -> Result<EsignNotice> {
    serde_json::from_slice(&row.payload).map_err(|_| invalid("notice schema"))
}

/// Why the document no longer takes `notice`'s recipient's signature, or
/// `None` while it does.
fn unsignable(state: &EsignState, notice: &EsignNotice, now: u64) -> Option<&'static str> {
    if state.status != DocumentStatus::Pending || state.rejection.is_some() {
        return Some("the document no longer takes signatures");
    }
    if now >= state.document.expires_at {
        return Some("the document's deadline passed");
    }
    if !state
        .document
        .recipients
        .iter()
        .any(|recipient| recipient.id == notice.recipient && recipient.email == notice.email)
    {
        return Some("the recipient changed since the send");
    }
    let Some(progress) = state.recipients.get(&notice.recipient) else {
        return Some("the recipient changed since the send");
    };
    if matches!(
        progress.signing,
        SigningStatus::Completed | SigningStatus::Rejected
    ) {
        return Some("the recipient already answered");
    }
    (now >= progress.expires_at).then_some("the recipient's signing window closed")
}
