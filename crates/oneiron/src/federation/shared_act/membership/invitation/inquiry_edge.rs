//! An acceptance that carries the member's inquiry edge (federation.md
//! #inquiry-first-build: "the edge is created at joining"), and its exact
//! retry.

use super::super::super::{
    OUTCOME_PREFIX, SharedActExecutionReceipt, SharedActOutcome, SharedVaultChange, check_vault,
    decode, invalid, key,
};
use super::SharedInvitationState;
use crate::authority::{ConnectOffer, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::inquiry::InquiryJoinOffer;
use crate::{EntityId, Vault};

impl Vault {
    /// [`Self::accept_shared_invitation`] with the member's inquiry edge, in
    /// the same writer (federation.md #inquiry-first-build: "the edge is
    /// created at joining"; Engine ruling L7-04-COMPANY-HALF = A): after the
    /// seat, the company's half of the edge that `edge` offers, approved by
    /// the seat the invitation gives and signed by this vault's host
    /// `issuer` ([`Self::prepare_inquiry_edge_for_join`] on the member's
    /// vault makes the offer). One refusal rolls back all of it: no seat
    /// without the company's half, and no company half without the seat.
    /// Answers the receipt and the company host's counter, which the member's
    /// vault applies on its edge; the counter carries the pact's scope
    /// opening key and is never written to the receipt or a log. A seat
    /// accepted without an offer takes its edge later through
    /// [`Self::attach_inquiry_edge_to_seat`] (L7-04-NO-PERSONAL-VAULT = A).
    ///
    /// An exact retry answers again and applies nothing: the member's pact
    /// waits on the counter, so a lost answer must not strand it. The proof
    /// therefore carries no invitation slip, only the invitee's own
    /// independent credential (or none, when the host vouches for it): an
    /// invitation slip stops standing once the acceptance spends its
    /// invitation (FIX 8745), so it could not retry, and an invitee who holds
    /// only that slip accepts with a credential, then attaches the edge.
    pub fn accept_shared_invitation_with_inquiry_edge(
        &self,
        invitee: &AuthenticatedOwner,
        vault_id: u64,
        invitation_id: &str,
        issuer: &HostSlipIssuer,
        edge: &InquiryJoinOffer,
    ) -> Result<(SharedActExecutionReceipt, ConnectOffer)> {
        invitee.require_independent_acceptor()?;
        if let Some(answer) =
            self.repeat_inquiry_join_acceptance(invitee, vault_id, invitation_id, issuer, edge)?
        {
            return Ok(answer);
        }
        let mut counter = None;
        let receipt =
            self.change_shared_membership(invitee, vault_id, None, |txn, actor, now| {
                let effect =
                    self.accept_shared_invitation_in_txn(txn, actor, vault_id, invitation_id, now)?;
                counter = Some(self.join_inquiry_edge_in_txn(txn, issuer, vault_id, actor, edge)?);
                Ok(effect)
            })?;
        let counter = counter.ok_or(crate::error::Error::InvariantViolation(
            "accepted membership did not join its offered inquiry edge",
        ))?;
        Ok((receipt, counter))
    }

    /// The answer of an acceptance with an inquiry edge that already applied,
    /// for its exact retry, in its own writer before the change's: while
    /// `invitee`'s invitation `invitation_id` in `vault_id` is still pending,
    /// `None`, and the first call applies. Once it is accepted, `edge`'s pact
    /// must be logged here as the edge of the seat it gave (any other offer
    /// refuses, as the spent invitation does); the answer is then the
    /// original receipt, read back from the invitee's own notice of it, and
    /// the same counter, from the Connect's exact repeat, which writes
    /// nothing. A seat accepted without an offer, whose edge `edge` attached
    /// later, answers the same (review round 2 of #8372): the retry answers
    /// the seat as it stands, its acceptance and its one inquiry edge, and
    /// both are true whichever door joined the edge. Telling the two apart
    /// would keep a pact id per accepted invitee, a row every erase of that
    /// person must then reach, for no state a member could act on.
    fn repeat_inquiry_join_acceptance(
        &self,
        invitee: &AuthenticatedOwner,
        vault_id: u64,
        invitation_id: &str,
        issuer: &HostSlipIssuer,
        edge: &InquiryJoinOffer,
    ) -> Result<Option<(SharedActExecutionReceipt, ConnectOffer)>> {
        self.with_write_txn_grouped(|txn| {
            let actor = invitee.revalidate_person_in_txn(self, txn)?;
            check_vault(self, txn, vault_id)?;
            let invitation = self.invitation_in_txn(txn, actor, invitation_id)?;
            if invitation.vault_id != vault_id
                || !matches!(invitation.state, SharedInvitationState::Accepted { .. })
            {
                return Ok(None);
            }
            // Only the logged pact is a retry: join_inquiry_edge_in_txn
            // would mint a new edge for any other.
            if !self
                .authority_fold_readonly_in_txn(txn)?
                .federation_pacts
                .contains_key(&edge.connect.pact_id)
            {
                return Err(invalid());
            }
            let receipt = self
                .invitation_acceptance_receipt_in_txn(txn, actor, vault_id, &invitation.id)?
                .ok_or_else(invalid)?;
            let counter = self.join_inquiry_edge_in_txn(txn, issuer, vault_id, actor, edge)?;
            Ok(Some((receipt, counter)))
        })
    }

    /// The receipt of `actor`'s acceptance of `invitation` in `vault_id`,
    /// read back from their own notice of it: every receipt tells its actor.
    fn invitation_acceptance_receipt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        vault_id: u64,
        invitation: &str,
    ) -> Result<Option<SharedActExecutionReceipt>> {
        let prefix = key(OUTCOME_PREFIX, &format!("{}:", actor.to_hex()));
        for entry in self.store.vault_meta.prefix_iter(txn, &prefix)? {
            let (_, bytes) = entry?;
            let outcome: SharedActOutcome = decode(&bytes)?;
            let accepted = matches!(
                &outcome.change,
                SharedVaultChange::InvitationAccepted { invitation: id, .. } if id == invitation
            );
            if outcome.vault_id == vault_id && accepted {
                return self.shared_act_receipt_in_txn(txn, &outcome.receipt_id);
            }
        }
        Ok(None)
    }
}
