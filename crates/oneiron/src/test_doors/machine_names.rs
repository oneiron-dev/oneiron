//! A door for `tests/machine_names_exchange.rs`: a machine's half of its steady-pass exchange of
//! machine-name cells with its residence home, without the socket between them. The home's half
//! is public (`oneiron::sync::residence::machine_names_residence_exchange`). Also the two
//! crate-internal seams of name provenance: the confirm the owner's "yours" doors make, and the
//! read a prompt that names a device makes.

use crate::Vault;
use crate::authority::MachineDeviceClass;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::machine_names::{MachineNameCell, MachineNameSource};
use crate::store::GateDecisionId;

/// The cells `vault` sends its home on a steady pass; `None` while it serves no machine of the
/// fold.
///
/// # Errors
///
/// The store's and the fold's.
pub fn cells_to_send(vault: &Vault) -> Result<Option<Vec<MachineNameCell>>> {
    vault.machine_name_cells_written_here()
}

/// Takes the home's answer as the steady pass does; returns how many cells changed.
///
/// # Errors
///
/// The store's and the fold's.
pub fn take_answer(vault: &Vault, cells: Vec<MachineNameCell>) -> Result<usize> {
    vault.take_machine_name_cells(cells)
}

/// Confirms `name` as the owner's own name for `machine`, as his signed "yours" does, in its own
/// writer; returns the act's Gate receipt, or `None` when an owner name was held.
///
/// # Errors
///
/// Every refusal of the confirm.
pub fn confirm_shown_name(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    machine: EntityId,
    name: &str,
) -> Result<Option<GateDecisionId>> {
    vault.with_write_txn_grouped(|txn| vault.confirm_machine_name_in_txn(txn, owner, machine, name))
}

/// The name `machine`, a device of class `class`, is shown by and its source, read as a prompt
/// that names the device reads them.
///
/// # Errors
///
/// The store's and the fold's.
pub fn prompt_name(
    vault: &Vault,
    machine: EntityId,
    class: MachineDeviceClass,
) -> Result<(String, MachineNameSource)> {
    let txn = vault.store.env.read_txn()?;
    let names = vault.machine_names_in_txn(&txn, machine, class)?;
    Ok((names.name, names.source))
}
