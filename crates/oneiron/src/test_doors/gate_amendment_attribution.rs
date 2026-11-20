//! Doors for `tests/gate_amendment_attribution_erase.rs`: the amendment
//! cause rows kept under a Gate decision's receipt, counted by key. Every
//! public cause read skips a row whose judgment is gone, so none can show
//! that an erase left one.

use crate::error::Result;
use crate::vault::Vault;

/// The cause rows kept for the amendment receipt `receipt`, in every
/// judge-revision slot, and its entries in the attempt index:
/// `(cause rows, attempt index entries)`.
pub fn amendment_cause_rows(vault: &Vault, receipt: &str) -> Result<(usize, usize)> {
    crate::edit_distance::attribution::amendment_cause_rows_for_test(vault, receipt)
}
