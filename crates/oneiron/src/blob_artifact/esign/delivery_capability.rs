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
//! act or his recorded one-time press on the send (FIX 6362), or a Grant
//! still live that covers the send, with the principal dial
//! still permitting an automated sender. Anything short of that holds the
//! delivery unexported with its reason; it is never dropped. A delivery whose
//! document or recipient ended settles instead, unsent, with its typed reason
//! (FIX 6363, [`super::delivery_settlement`]). One whose document has an
//! event awaiting its owner's answer, or whose trail no longer reads, waits
//! on its own with its typed reason (FIX 6423), and so does one whose own
//! queued notice, or whose send's admitted call on the outbound ledger, does
//! not read (FIX 6455), or whose send's dispatch marker or recipient's
//! signing links do not read (FIX 6482). No other delivery waits on it. A
//! storage failure is the only error: nothing in one delivery's own data is.
//!
//! [`delivery_read_in`] is the one classifier: the mint acts on what it
//! reads, and the owner's document view lists the waits it reads now beside
//! the ended receipts (`delivery_receipts`).

use super::capability::{
    EsignCapability, delivered_digest_in, mint_delivery_capability_in_txn,
    recipient_bindings_read_in,
};
use super::delivery_settlement::{EsignDeliveryEndReason, ended_reason, fail_ended_in_txn};
use super::ledger::delivery_chain_in;
use super::model::*;
use super::notice_dispatch::EsignNotice;
use super::outbound::{EsignOutboundVerb, OwnerSendAct, dispatch_marker_in};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::outbound::EsignDeliveryCall;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// The queue kind the vault keeps authorized e-sign mail under.
pub(super) const DELIVERY_KIND: &str = "esign.delivery";

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
    /// Nothing was minted: the delivery's document or recipient ended, so
    /// it settled unsent with this reason (FIX 6363).
    Settled(EsignDeliveryEndReason),
    /// Nothing was minted: this one delivery waits, its lease kept, for its
    /// document or its own data (FIX 6423, 6455, 6482).
    Waits(EsignDeliveryWait),
}

/// Why one delivery stays unexported for now (FIX 6423, 6455, 6482). It
/// waits on its own; no other delivery waits on it. The exporter logs its
/// code, and the owner reads it on `vault.esign.get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EsignDeliveryWait {
    /// An event of the document awaits its owner's answer.
    DocumentAwaitsOwner,
    /// The document's trail no longer reads.
    DocumentUnreadable,
    /// The delivery's own queued notice does not read as an invitation or a
    /// reminder of one document: its schema, the document it names, or a
    /// notice that carries no signing link.
    NoticeUnreadable,
    /// The send's admitted call does not read: its dispatch marker, or off
    /// the outbound ledger its dispatch ref, its ledger row or its frozen
    /// payload.
    SendUnreadable,
    /// The recipient's signing links on the document do not read: their
    /// index or a link's binding does not decode, an indexed link has no
    /// binding, or a binding names another document or recipient (FIX 6482).
    LinksUnreadable,
}

impl EsignDeliveryWait {
    /// The reason's code, as the exporter logs it and the owner reads it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DocumentAwaitsOwner => "document_awaits_owner",
            Self::DocumentUnreadable => "document_unreadable",
            Self::NoticeUnreadable => "notice_unreadable",
            Self::SendUnreadable => "send_unreadable",
            Self::LinksUnreadable => "links_unreadable",
        }
    }
}

/// What one queued invitation or reminder reads to, in the mint's order
/// ([`delivery_read_in`]).
pub(super) enum DeliveryRead {
    /// Its document or recipient ended: it settles unsent, for this reason.
    Ended(EsignDeliveryEndReason),
    /// It stays queued and unexported, for this reason.
    Held(&'static str),
    /// It waits on its own, for this typed reason.
    Waits(EsignDeliveryWait),
    /// Every read passes; the mint goes on under its writer.
    Mintable(Box<Mintable>),
}

/// What the mint goes on with once every read passes.
pub(super) struct Mintable {
    document: EntityId,
    notice: EsignNotice,
    state: EsignState,
    /// The admitted call a Grant live under the mint's writer must still
    /// cover, or `None` when the vault owner's own act covers the send.
    grant: Option<Box<EsignDeliveryCall>>,
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
    /// A storage failure, the queue row's own decode included. A delivery the
    /// mint may not serve is [`EsignDeliveryMint::Held`]; one whose document
    /// or recipient ended settles, under this same writer, as
    /// [`EsignDeliveryMint::Settled`]; one whose document's chain holds an
    /// event for its owner's answer or does not read, or whose own notice or
    /// send's admitted call does not read, is [`EsignDeliveryMint::Waits`].
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
            let now = self.now_recorded_at();
            let mintable = match delivery_read_in(self, txn, &row, now)? {
                DeliveryRead::Mintable(mintable) => mintable,
                DeliveryRead::Held(reason) => return Ok(EsignDeliveryMint::Held(reason)),
                DeliveryRead::Waits(wait) => return Ok(EsignDeliveryMint::Waits(wait)),
                // An end that landed after the exporter's own check settles
                // here, under the mint's writer, so no link is minted for it.
                DeliveryRead::Ended(reason) => {
                    fail_ended_in_txn(self, txn, &row, reason, now)?;
                    return Ok(EsignDeliveryMint::Settled(reason));
                }
            };
            if let Some(call) = &mintable.grant
                && let Some(reason) = self.grant_unauthorized_in(txn, call)?
            {
                return Ok(EsignDeliveryMint::Held(reason));
            }
            let Mintable {
                document,
                notice,
                state,
                ..
            } = *mintable;
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
    /// minted for `row`'s current lease; `None` when no link names it, as for
    /// a row whose notice does not read as one (its mint waits it, FIX 6455).
    /// The inner error: the recipient's signing links do not read, so no
    /// link is known to name the lease (its mint waits it, FIX 6482).
    /// # Errors
    /// A storage failure.
    pub fn esign_delivery_digest(&self, row: &AttemptRecord) -> Result<Result<Option<String>>> {
        let txn = self.store.env.read_txn()?;
        lease_digest_in(self, &txn, row)
    }

    /// Why no Grant live under this writer covers `call` any more, or `None`
    /// when one does, with an automated sender's principal dial still at
    /// autonomous-in-envelope.
    fn grant_unauthorized_in(
        &self,
        txn: &heed::RwTxn<'_>,
        call: &EsignDeliveryCall,
    ) -> Result<Option<&'static str>> {
        if crate::outbound::esign_delivery_grant_in_txn(self, txn, call)?.is_none() {
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

/// Reads `row`, a queued invitation or reminder, as its mint does at `now`,
/// short of what only the mint's writer may decide (the send's live Grant
/// and its principal's dial): the end it settles on, why it holds or waits,
/// or what the mint goes on with. The mint acts on it and the owner's
/// document view lists its waits, so the two never part (FIX 6455).
/// # Errors
/// A storage failure only. A notice, a document trail, a send's dispatch
/// marker or admitted call, or a recipient's signing links that do not read
/// wait this one delivery.
pub(super) fn delivery_read_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
    now: u64,
) -> Result<DeliveryRead> {
    let Ok(notice) = notice_of(row) else {
        return Ok(DeliveryRead::Waits(EsignDeliveryWait::NoticeUnreadable));
    };
    if !notice.carries_signing_link() {
        return Ok(DeliveryRead::Waits(EsignDeliveryWait::NoticeUnreadable));
    }
    let Some(dispatch_ref) = notice.dispatch_ref.as_deref() else {
        return Ok(DeliveryRead::Held("the delivery names no admitted send"));
    };
    let Ok(document) = EntityId::from_hex(&notice.document) else {
        return Ok(DeliveryRead::Waits(EsignDeliveryWait::NoticeUnreadable));
    };
    if row.dedupe_key.as_deref() != Some(delivery_key(&notice, dispatch_ref).as_str()) {
        return Ok(DeliveryRead::Held(
            "the delivery's key does not bind its notice",
        ));
    }
    let Some((state, held)) = delivery_chain_in(vault, txn, document)? else {
        return Ok(DeliveryRead::Waits(EsignDeliveryWait::DocumentUnreadable));
    };
    if let Some(reason) = ended_reason(&state, held, &notice, now) {
        return Ok(DeliveryRead::Ended(reason));
    }
    if held {
        return Ok(DeliveryRead::Waits(EsignDeliveryWait::DocumentAwaitsOwner));
    }
    if let Some(reason) = unsignable(&state, &notice, now) {
        return Ok(DeliveryRead::Held(reason));
    }
    let marker = match dispatch_marker_in(vault, txn, dispatch_ref)? {
        Ok(Some(marker)) => marker,
        Ok(None) => {
            return Ok(DeliveryRead::Held(
                "no admitted send act covers the delivery",
            ));
        }
        Err(_) => return Ok(DeliveryRead::Waits(EsignDeliveryWait::SendUnreadable)),
    };
    let ledger_identity = marker.ledger_identity_ref.as_deref();
    let call = match crate::outbound::esign_delivery_call_in_txn(
        vault,
        txn,
        dispatch_ref,
        ledger_identity,
    )? {
        Ok(Some(call)) => call,
        Ok(None) => {
            return Ok(DeliveryRead::Held(
                "the send's admitted call is not on the ledger",
            ));
        }
        Err(_) => return Ok(DeliveryRead::Waits(EsignDeliveryWait::SendUnreadable)),
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
        return Ok(DeliveryRead::Held(
            "the send's admitted call does not cover the delivery",
        ));
    }
    // The owner's own act, recorded with his revalidated proof, covers every
    // delivery it queued; so does his one-time press on an agent's send, when
    // it is the proof this same admitted call carries (FIX 6362). An agent
    // sender is not the owner, so the press is matched by its proof, never by
    // actor. Anything else needs a Grant live under the mint's writer.
    let owner_act = match &marker.owner_act {
        Some(OwnerSendAct::Direct { actor, .. }) => call
            .actor_entity_ref
            .is_some_and(|entity| entity.to_hex() == *actor),
        Some(OwnerSendAct::Approved {
            intent_ref,
            effect_digest,
        }) => call.admitted_approval.is_some_and(|proof| {
            crate::entity_id::bytes_to_hex_lower(&proof.intent_id()) == *intent_ref
                && proof.effect_digest().to_hex() == *effect_digest
        }),
        None => false,
    };
    // The mint reads the recipient's links again under its writer: links
    // that do not read wait this one delivery here (FIX 6482).
    if recipient_bindings_read_in(vault, txn, document, &notice.recipient)?.is_err() {
        return Ok(DeliveryRead::Waits(EsignDeliveryWait::LinksUnreadable));
    }
    Ok(DeliveryRead::Mintable(Box::new(Mintable {
        document,
        notice,
        state,
        grant: (!owner_act).then(|| Box::new(call)),
    })))
}

/// The digest recorded with the link minted for `row`'s current lease, or
/// `None` when no link names it, as for a row whose notice does not read as
/// one: the store's own failure (the outer error) apart from the recipient's
/// signing links that do not read (the inner one).
pub(super) fn lease_digest_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<Result<Option<String>>> {
    let Ok(notice) = notice_of(row) else {
        return Ok(Ok(None));
    };
    let Ok(document) = EntityId::from_hex(&notice.document) else {
        return Ok(Ok(None));
    };
    let lease = crate::entity_id::bytes_to_hex_lower(row.id.as_bytes());
    delivered_digest_in(
        vault,
        txn,
        document,
        &notice.recipient,
        (&lease, row.attempt_count),
    )
}

pub(super) fn notice_of(row: &AttemptRecord) -> Result<EsignNotice> {
    serde_json::from_slice(&row.payload).map_err(|_| invalid("notice schema"))
}

/// The dedupe key the vault queues `notice`'s invitation or reminder under,
/// for the send `dispatch_ref` admitted.
pub(super) fn delivery_key(notice: &EsignNotice, dispatch_ref: &str) -> String {
    match notice.transition.as_str() {
        "reminder" => format!(
            "{}:reminder:{}:{dispatch_ref}",
            notice.document, notice.recipient
        ),
        _ => format!("{}:invite:{}", notice.document, notice.recipient),
    }
}

/// Why the document no longer takes `notice`'s recipient's signature, or
/// `None` while it does. An ended document or recipient has settled before
/// this is read; what is left here holds the delivery.
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
