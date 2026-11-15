//! A door for `tests/machine_names_exchange.rs`: a machine's half of its steady-pass exchange of
//! machine-name cells with its residence home, without the socket between them. The home's half
//! is public (`oneiron::sync::residence::machine_names_residence_exchange`).

use crate::Vault;
use crate::error::Result;
use crate::machine_names::MachineNameCell;

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
