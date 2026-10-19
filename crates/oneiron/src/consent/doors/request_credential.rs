//! The slip a person's request arrived with, bound to their proof as a
//! liveness guard alone (FIX 4328, DOOR-140): the shared act doors' proof of
//! a person who does not own the vault, a contact giving or revoking consent
//! among them, carries the slip it was authenticated from into every acting
//! transaction, as the owner's proof carries the owner's. A request queued
//! behind that slip's revocation or expiry commits nothing.
//!
//! The guard lends no authority: it is neither the owner's bound credential
//! nor the person tier's own-slip marker (FIX 4707), so every door admits
//! the proof as it did unbound, a slip handed to another key included. Only
//! the slip's liveness in the acting transaction is new.

use crate::Vault;
use crate::error::{Error, GateError, Result};

use super::AuthenticatedOwner;

impl Vault {
    /// Binds `person`, a proof no transport bound yet, to the verified slip
    /// its request arrived with (FIX 4328): the transport has already
    /// checked that the slip is this person's own. From then on every
    /// revalidation of the proof, person-tier and owner-tier alike, also
    /// refuses once that slip is revoked or expired, in the acting
    /// transaction. Nothing else about the proof changes: the slip adds no
    /// owner authority and no person-tier marker, and it is not checked
    /// again here, so a request admitted before still is.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof is already bound or the slip names another holder.
    pub fn bind_request_credential(
        &self,
        mut person: AuthenticatedOwner,
        credential: crate::authority::VerifiedSlip,
    ) -> Result<AuthenticatedOwner> {
        if person.credential.is_some()
            || person.person_credential.is_some()
            || person.request_credential.is_some()
            || person.host_action.is_some()
            || credential.claims().holder_ref != person.actor.to_hex()
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "credential is not this person's own request slip",
            )));
        }
        person.request_credential = Some(Box::new(credential));
        Ok(person)
    }
}

impl AuthenticatedOwner {
    /// The request slip's liveness in `txn` (FIX 4328), for every
    /// revalidation of this proof: a proof no request slip rides passes.
    pub(super) fn request_credential_holds_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        if let Some(credential) = &self.request_credential
            && !vault.capability_slip_is_live_in_txn(txn, credential)?
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "request credential is no longer live",
            )));
        }
        Ok(())
    }
}
