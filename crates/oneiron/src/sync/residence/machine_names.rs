//! `residence.machine_names.exchange` at the home (FIX [DEVICE-DISPLAY-NAME]; Engine RULING
//! MACHINE-NAMES-CARRIER = B): the meeting point of the machine-name cells the owner's machines
//! write. Only a machine of the owner's its socket proved is served.

use super::bundle::denied;
use super::custody::owner_machine;
use crate::Vault;
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::machine_names::MachineNameCell;

/// Keeps each cell `peer` wrote that is later than the one this home holds for its machine and
/// kind, and answers every cell this home holds for a machine its fold names
/// ([`crate::machine_names::exchange`]).
///
/// # Errors
///
/// A peer that is not a proved machine of the owner's; the store's and the fold's.
pub fn machine_names_residence_exchange(
    vault: &Vault,
    peer: PeerMachine,
    cells: Vec<MachineNameCell>,
) -> Result<Vec<MachineNameCell>> {
    owner_machine(vault, peer)?;
    let PeerMachine::Proven { machine, .. } = peer else {
        return Err(denied());
    };
    vault.exchange_machine_name_cells_at_home(machine, cells)
}
