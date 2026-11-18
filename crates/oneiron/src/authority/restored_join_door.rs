//! Red pin only (row RESTORED-COPIES-ENROL-EACH-OTHER, PR 2): the owner's
//! join door in PR 1's semantics, where an install born of a restore that
//! no joined machine pairs never joins. It refuses as the root's bootstrap
//! arm refuses, and writes nothing.

use super::machine_answers::RESTORED_NOT_JOINED;
use super::*;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;

impl Vault {
    /// PR 1's answer to the owner's word that no other machine is left: no
    /// way in.
    ///
    /// # Errors
    /// Always [`RESTORED_NOT_JOINED`].
    pub fn join_restored_install(
        &self,
        _issuer: &HostSlipIssuer,
        _owner: &AuthenticatedOwner,
        _role: MachineRole,
    ) -> Result<FoldedMachine> {
        Err(authority_refused(RESTORED_NOT_JOINED))
    }
}
