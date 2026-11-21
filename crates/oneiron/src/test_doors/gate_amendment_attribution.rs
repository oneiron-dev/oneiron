//! Doors for `tests/gate_amendment_attribution_erase.rs`: the amendment
//! cause rows kept under a Gate decision's receipt, counted by key. Every
//! public cause read skips a row whose judgment is gone, so none can show
//! that an erase left one. And a step run between an attribution writer's
//! reads and its write, where a test races an erase.

use crate::error::Result;
use crate::vault::Vault;

/// The cause rows kept for the amendment receipt `receipt`, in every
/// judge-revision slot, and its entries in the attempt index:
/// `(cause rows, attempt index entries)`.
pub fn amendment_cause_rows(vault: &Vault, receipt: &str) -> Result<(usize, usize)> {
    crate::edit_distance::attribution::amendment_cause_rows_for_test(vault, receipt)
}

/// Runs `step` once, on this thread, after the next amendment evidence door
/// or judge has read what it decides from and before its writer opens.
pub fn before_next_amendment_writer(step: Box<dyn FnOnce(&Vault)>) {
    crate::edit_distance::attribution::set_before_amendment_writer_hook(step);
}
