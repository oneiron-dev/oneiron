//! The nightly identity re-check, one page, run from a test, and the open
//! identity asks after it (census item 12, the entity linker cascade).

use crate::dreamer_runner::maintenance::identity::IdentityAsk;
use crate::{Result, Vault};

/// Runs one page of the nightly identity re-check at `now` (seconds) and
/// returns every open identity ask.
pub fn run_identity_recheck(vault: &Vault, now: u64) -> Result<Vec<IdentityAsk>> {
    crate::dreamer_runner::maintenance::identity::recheck_page_for_test(vault, now)
}
