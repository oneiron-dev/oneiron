//! The invitee's own credential (FIX 8745): the key an invitation's slips
//! bind comes from the invitee, never from whoever invited them. An
//! `add_member` holder creates or withdraws invitations and names no key;
//! the invitee binds their invitation with an independent live human slip of
//! their own PERSON, and accepts on that binding or on such a slip.

use crate::authority::VerifiedSlip;
use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

use super::{AuthenticatedOwner, CONSENT_ACTOR_CLASS};

/// A person's own independent credential, as their request proved it: the
/// key it binds, its slip id and when its mint ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndependentCredential {
    pub(crate) person: EntityId,
    pub(crate) holder_key: [u8; 32],
    pub(crate) slip_id: [u8; 32],
    pub(crate) expires_at: u64,
}

/// Whether `slip` is `person`'s own ordinary human credential, independent of
/// any invitation: a direct mint to their own key, still proved by that key
/// (not handed to another), naming no invitation, grant, organization,
/// support delegation or contact binding, any of which another person's act
/// keyed or bounds.
pub(crate) fn is_independent_person_credential(slip: &VerifiedSlip, person: &EntityId) -> bool {
    let claims = slip.claims();
    !slip.is_transferred()
        && claims.holder_ref == person.to_hex()
        && claims.actor_class.as_deref() == Some(CONSENT_ACTOR_CLASS)
        && claims.parent_id.is_none()
        && claims.invitation_ref.is_none()
        && claims.grant_ref.is_none()
        && claims.org_ref.is_none()
        && claims.delegation.is_none()
        && claims.trusted_contact.is_none()
}

impl AuthenticatedOwner {
    /// Every slip a transport bound to this proof: the owner's credential,
    /// the person's own and the request's. A proof the host authenticated
    /// itself carries none.
    fn carried_slips(&self) -> impl Iterator<Item = &VerifiedSlip> {
        [
            self.credential.as_deref(),
            self.person_credential.as_deref(),
            self.request_credential.as_deref(),
        ]
        .into_iter()
        .flatten()
    }

    /// The independent credential this person's request came on, revalidated
    /// in `txn`: the key an invitation of theirs binds (FIX 8745). Every slip
    /// the proof carries must be such a credential, presented whole (no
    /// caveat narrows it, so its mint's claims are what it proves).
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof no longer
    /// holds, carries no slip, or carries one that is not the person's own
    /// independent credential ([`is_independent_person_credential`]) or is
    /// attenuated.
    pub(crate) fn independent_credential_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<IndependentCredential> {
        let person = self.revalidate_person_in_txn(vault, txn)?;
        let refused = || {
            Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "an invitation binds the key of the invitee's own independent credential",
            ))
        };
        let mut carried = self.carried_slips().peekable();
        let credential = *carried.peek().ok_or_else(refused)?;
        if !carried
            .all(|slip| slip.is_unattenuated() && is_independent_person_credential(slip, &person))
        {
            return Err(refused());
        }
        let claims = credential.claims();
        Ok(IndependentCredential {
            person,
            holder_key: claims.binding_key,
            slip_id: claims.slip_id,
            expires_at: claims.expires_at,
        })
    }

    /// Refuses an acceptance of `invitation_id` when a slip the proof
    /// carries is neither that invitation's own slip, proved by the key it
    /// was minted to (the binding its liveness checks), nor the person's own
    /// independent credential (FIX 8745). A proof that carries no slip, one
    /// the host authenticated itself, is the host's to vouch for and passes.
    pub(crate) fn require_invitation_acceptor(&self, invitation_id: &str) -> Result<()> {
        let admitted = |slip: &VerifiedSlip| {
            let own_invitation = !slip.is_transferred()
                && slip
                    .claims()
                    .invitation_ref
                    .as_deref()
                    .is_some_and(|own| own.eq_ignore_ascii_case(invitation_id));
            own_invitation || is_independent_person_credential(slip, &self.actor)
        };
        if self.carried_slips().all(admitted) {
            Ok(())
        } else {
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "an invitation is accepted on its bound key or the invitee's own independent credential",
            )))
        }
    }
}
