//! A person's own slip bound to their proof (FIX 4707): the HTTP door of a
//! world's settings holders, who need not own the vault, carries their slip
//! into every acting transaction as the owner door carries the owner's.

use crate::Vault;
use crate::error::{Error, GateError, Result};

use super::{AuthenticatedOwner, CONSENT_ACTOR_CLASS};

impl Vault {
    /// Binds `person`, a proof no transport bound yet, to the verified slip
    /// their request arrived with (FIX 4707): their own human slip, not
    /// handed to another key, and live now. It need not be owner-grade and
    /// its person need not own this vault. From then on every person-tier
    /// revalidation also refuses once that slip is revoked or expired, and
    /// every owner-tier door refuses the proof outright, an owner's too, so
    /// the binding lends no one owner authority.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof is already bound, the slip is not this person's own
    /// human slip or was handed on, or the proof no longer holds now.
    pub fn bind_person_credential(
        &self,
        mut person: AuthenticatedOwner,
        credential: crate::authority::VerifiedSlip,
    ) -> Result<AuthenticatedOwner> {
        let claims = credential.claims();
        if person.credential.is_some()
            || person.person_credential.is_some()
            || person.host_action.is_some()
            || credential.is_transferred()
            || claims.holder_ref != person.actor.to_hex()
            || claims.actor_class.as_deref() != Some(CONSENT_ACTOR_CLASS)
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "credential is not this person's own slip",
            )));
        }
        person.person_credential = Some(Box::new(credential));
        person.revalidate_person(self)?;
        Ok(person)
    }
}
