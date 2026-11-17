//! Door for `tests/weave_arc_rederive.rs`: runs the Arc gate's due sweep, the
//! one the Nightly recipe and the home's Macro Timer share (FIX 8058), in one
//! ordinary vault write. No policy, source selection or gate logic is copied.

use crate::{Result, Vault};

/// Runs the due-Arc sweep at `now`, as the home's Timer pass does, with no
/// parent receipt.
///
/// # Errors
/// The sweep's policy, source or store errors.
pub fn sweep_due_arcs(vault: &Vault, now: u64) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::scope_summary::sweep_due_arcs_in_txn(vault, txn, (None, None), now)
    })
}
