//! `residence.secret_same_value.exchange` at the home (FIX [SECRETS-SAME-VALUE-FACT]; Engine
//! RULINGS SECRETS-LIST-DUP-GROUPING = A and SECRET-SAMEFACT-HOST-SEES = B): the meeting point of
//! the same-value statements the owner's machines sign. The home keeps each statement as its writer
//! signed it and never opens one. Only a machine of the owner's its socket proved is served.

use super::bundle::denied;
use super::custody::owner_machine;
use crate::Vault;
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::secret_custody::SameValueStatement;

/// Keeps each of `statements` that `peer` signed as its writer and that is later than the one this
/// home holds from `peer`, and answers every statement this home holds whose writer's signature
/// still verifies here ([`crate::secret_custody::SameValueStatement`]).
///
/// # Errors
///
/// A peer that is not a proved machine of the owner's; the store's and the fold's.
pub fn secret_same_value_residence_exchange(
    vault: &Vault,
    peer: PeerMachine,
    statements: Vec<SameValueStatement>,
) -> Result<Vec<SameValueStatement>> {
    owner_machine(vault, peer)?;
    let PeerMachine::Proven { machine, .. } = peer else {
        return Err(denied());
    };
    vault.exchange_same_value_statements_at_home(machine, statements)
}
