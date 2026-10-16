//! The verified credential a host bound to a handle, for the engine doors
//! that take the caller's own credential rather than its actor alone (an
//! agent's contact-disclosure offer, `vault.disclosure.offer`).

use super::Memory;
use crate::authority::VerifiedSlip;

impl Memory<'_> {
    /// The credential this handle's caller presented, when a host bound one
    /// ([`Memory::with_read_proof`]); none on an embedded handle.
    pub(crate) fn presented_credential(&self) -> Option<&VerifiedSlip> {
        self.read_proof.as_ref()
    }
}
