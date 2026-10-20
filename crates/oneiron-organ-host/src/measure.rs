//! The organ host's `[limits]` rows (OF-520, Rule 5): what a call counted
//! and carried, measured where the host serves it. Nothing here refuses:
//! past a row the vault asks whether everything is okay, and the call is
//! served whole.

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;

/// Measures `measured` against `row` for an install grant that names
/// `install`: at the row's own setting while the grant keeps the row's
/// factory value, else at the grant's own value, a site-specific bound.
pub(crate) fn install_row(vault: &Vault, row: EngineLimit, install: u64, measured: u64) {
    if install == row.default_bound() {
        vault.measure_limit(row, measured);
    } else {
        vault.measure_limit_at(row, install, measured);
    }
}
