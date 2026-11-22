//! One press for a reviewed batch (ARCH-0046 #send-grant: "A send needs a
//! press per send, one press for a reviewed batch, or no press"; ARCH-0082
//! #modes; PLAN L3-35 D5; Engine ruling L3-35-BATCH = A).
//!
//! The holder reviews several held sends and approves them with one press:
//! one approve-once proof per send, each the digest that send's own per-send
//! press names, all minted in one write or none. The proofs are the batch's
//! accounting: each releases its one send once and a spent proof releases
//! nothing, so no counter is kept. A batch press releases exactly what the
//! same per-send presses would; a family whose single press releases nothing
//! today gains nothing from a batch.
//!
//! The vault's send grant decides whether one press may cover more than one
//! send: only when its `mode` rows naming `outbound_send` compose `manual`
//! with `ask_per: batch` ([`crate::check_in::send_grant_presses_batch_in_txn`]).
//! The grant is read in the write that mints, so the row standing at the
//! press decides. It sets the shape of the holder's press, so it reaches
//! every send a press releases, a member mailbox's and a native-mail cold
//! send's among them; each such send still takes its own exact approval, and
//! the row never releases one with no press (ruling L3-35-PRINCIPAL = A).

use crate::Vault;
use crate::consent::{AuthenticatedOwner, ConsentReceipt, EffectDigest};
use crate::error::{Error, Result};
use crate::outbound::dispatch_types::{OutboundDispatchError, OutboundDispatchRequest};

impl Vault {
    /// One owner press for a reviewed batch of outbound sends: an exact
    /// approval for each of `requests`, all minted in one transaction
    /// (module doc).
    ///
    /// `reviewed_send_refs` is what the holder saw: the card's
    /// `BundleExactSends` refs. The requests must be exactly those sends, one
    /// each, by intent ref. Each send's approval is the digest its own
    /// per-send press mints: [`super::outbound_approve_once_digest`] for a
    /// family that pins its target, else a native or member mailbox send's
    /// canonical mail operation. It mints no standing authority; dispatch
    /// still rechecks recipient, sender and the Gate. Either every approval
    /// lands or none does; an already-pressed send refuses the batch.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the requests are not exactly the
    /// reviewed refs, when a request has no press that releases it, or when
    /// the vault's send grant asks a press per send and the batch holds more
    /// than one send; a request's own refusal at preparation; and the
    /// approve-once door's owner and replay checks.
    pub fn approve_outbound_batch(
        &self,
        owner: &AuthenticatedOwner,
        reviewed_send_refs: &[String],
        requests: &[OutboundDispatchRequest],
    ) -> std::result::Result<Vec<ConsentReceipt>, OutboundDispatchError> {
        require_reviewed_sends(reviewed_send_refs, requests)?;
        let digests = requests
            .iter()
            .map(|request| send_press_digest(self, request))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(self.approve_reviewed_batch(owner, digests)?)
    }

    /// The batch press's one write: each of `digests`, one per reviewed send,
    /// approved once, under the vault's send grant as this same write reads
    /// it (module doc). A door that composes its sends' digests itself (the
    /// Gmail member door) checks the reviewed refs and its envelopes first.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the grant asks a press per send and
    /// `digests` holds more than one; the approve-once door's owner and
    /// replay checks, so a digest named twice refuses the batch.
    pub(crate) fn approve_reviewed_batch(
        &self,
        owner: &AuthenticatedOwner,
        digests: Vec<EffectDigest>,
    ) -> Result<Vec<ConsentReceipt>> {
        self.with_write_txn_grouped(|wtxn| {
            if digests.len() > 1
                && !crate::check_in::send_grant_presses_batch_in_txn(&self.store, wtxn)?
            {
                return Err(Error::InvalidConfig(
                    "the vault's send grant asks a press per send: one press covers one send"
                        .to_owned(),
                ));
            }
            digests
                .into_iter()
                .map(|digest| self.approve_once_in_txn(wtxn, owner, digest))
                .collect()
        })
    }
}

/// Refuses a batch whose requests are not exactly the reviewed sends, once
/// each, by intent ref, and an empty one.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for such a batch.
pub(crate) fn require_reviewed_sends(
    reviewed_send_refs: &[String],
    requests: &[OutboundDispatchRequest],
) -> Result<()> {
    let mut reviewed = reviewed_send_refs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut requested = requests
        .iter()
        .map(|request| request.intent_ref.as_str())
        .collect::<Vec<_>>();
    reviewed.sort_unstable();
    requested.sort_unstable();
    if requests.is_empty()
        || reviewed != requested
        || requested.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(Error::InvalidConfig(
            "a batch approval must cover exactly the reviewed sends, once each".to_owned(),
        ));
    }
    Ok(())
}

/// The approve-once digest `request`'s own per-send press mints: the Gate's
/// pinned-target digest ([`super::outbound_approve_once_digest`]), else, for
/// a native or member mailbox send, which pins none, its canonical mail
/// operation's, as the native-mail and Gmail member doors mint it.
fn send_press_digest(
    vault: &Vault,
    request: &OutboundDispatchRequest,
) -> std::result::Result<EffectDigest, OutboundDispatchError> {
    if let Some(digest) = super::outbound_approve_once_digest(vault, request)? {
        return Ok(digest);
    }
    let (Some(identity_ref), Some(actor)) =
        (request.channel_identity_ref, request.actor.actor_entity_ref)
    else {
        return Err(Error::InvalidConfig(
            "a batch approval names a send that no press releases".to_owned(),
        )
        .into());
    };
    Ok(
        crate::channel_identity_provider::native_mail::canonical_mail_send_digest(
            request,
            identity_ref,
            actor,
        )?,
    )
}
