//! The invitee's own credential (FIX 8745): the key an invitation's slips
//! bind comes from the invitee, never from whoever invited them. An
//! `add_member` holder creates or withdraws invitations and names no key;
//! the invitee binds their invitation with an independent live human slip of
//! their own PERSON, and accepts on that binding or on such a slip.

use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

use super::{AuthenticatedOwner, CONSENT_ACTOR_CLASS};

/// A person's own independent credential, as their request proved it: the
/// key it binds and its slip id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndependentCredential {
    pub(crate) person: EntityId,
    pub(crate) holder_key: [u8; 32],
    pub(crate) slip_id: [u8; 32],
}

/// Whether `slip` is `person`'s own ordinary human credential, independent of
/// any invitation: a direct mint to their own key, still proved by that key
/// (not handed to another), naming no invitation, grant, organization,
/// support delegation or contact binding, any of which another person's act
/// keyed or bounds.
pub(crate) fn is_independent_person_credential(
    slip: &crate::authority::VerifiedSlip,
    person: &EntityId,
) -> bool {
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
    /// The independent credential this person's request came on, revalidated
    /// in `txn`: the key an invitation of theirs binds (FIX 8745).
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof no longer
    /// holds, or no request slip rides it, or that slip is not the person's
    /// own independent credential ([`is_independent_person_credential`]).
    pub(crate) fn independent_credential_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<IndependentCredential> {
        let person = self.revalidate_person_in_txn(vault, txn)?;
        let credential = self
            .request_credential
            .as_deref()
            .filter(|credential| is_independent_person_credential(credential, &person))
            .ok_or(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "an invitation binds the key of the invitee's own independent credential",
            )))?;
        Ok(IndependentCredential {
            person,
            holder_key: credential.claims().binding_key,
            slip_id: credential.claims().slip_id,
        })
    }

    /// Refuses an acceptance of `invitation_id` whose request slip is neither
    /// that invitation's own slip, proved by the key it was minted to (the
    /// binding its liveness checks), nor the person's own independent
    /// credential (FIX 8745). A proof no request slip rides, such as one the
    /// host authenticated itself, is the host's to vouch for and passes.
    pub(crate) fn require_invitation_acceptor(&self, invitation_id: &str) -> Result<()> {
        let Some(credential) = self.request_credential.as_deref() else {
            return Ok(());
        };
        let own_invitation = !credential.is_transferred()
            && credential
                .claims()
                .invitation_ref
                .as_deref()
                .is_some_and(|own| own.eq_ignore_ascii_case(invitation_id));
        if own_invitation || is_independent_person_credential(credential, &self.actor) {
            Ok(())
        } else {
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "an invitation is accepted on its bound key or the invitee's own independent credential",
            )))
        }
    }
}
