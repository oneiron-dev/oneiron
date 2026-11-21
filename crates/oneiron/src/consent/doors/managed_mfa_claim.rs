//! A managed person's MFA, as the supervisor claims it on one person action
//! (L7-17 PR 2; Engine RULING L7-17-ORG-ADMIN-ACTS = A, 14 Nov 18:29). A
//! member on a managed host who holds no slip acts on a supervisor-signed
//! person action (FIX 1302), so no step-up record of this vault can name
//! his request. The supervisor's explicit, signed `mfa_verified` claim on
//! that one action stands in for it as that act's org Admin step-up. The
//! engine never assumes the control plane did MFA: a proof without the
//! claim shows none, and an Admin's act on it is refused.

use crate::Vault;
use crate::error::{Error, GateError, Result};

use super::AuthenticatedOwner;

impl Vault {
    /// Marks `person`, a slipless proof built for one managed person action,
    /// with that action's supervisor-signed `mfa_verified` claim: the org
    /// Admin step-up of the act it asks for, and nothing more. Called only
    /// by a managed host's door, after its ingress verified the action's
    /// signature over the claim; the claim adds no owner authority and no
    /// person-tier marker.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof carries a slip or a host action: a request with an
    /// instrument of its own steps up on that instrument.
    pub fn bind_managed_mfa_verified(
        &self,
        mut person: AuthenticatedOwner,
    ) -> Result<AuthenticatedOwner> {
        if person.credential.is_some()
            || person.person_credential.is_some()
            || person.request_credential.is_some()
            || person.host_action.is_some()
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "a supervisor's MFA claim binds only a slipless managed person's proof",
            )));
        }
        person.managed_mfa_verified = true;
        Ok(person)
    }
}
