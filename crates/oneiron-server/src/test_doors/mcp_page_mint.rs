//! Door for `tests/mcp_page_continuation_rejudge.rs`: one act run at a vault's
//! next page one mint, after its producer read and before the mint judges
//! which rows its caller read, where a Grant revoked, or a clock step that
//! expires one, while page one is made lands.

use oneiron::Vault;

use super::vault_acts::{ActPoint, run_at_next, run_waiting};

/// Runs `act` once, at the next page one mint on `vault`: after its
/// producer's read, before the mint judges which rows its caller read.
pub fn before_next_page_mint(vault: &Vault, act: impl FnOnce() + Send + 'static) {
    run_at_next(ActPoint::PageMint, vault, act);
}

/// Runs the act waiting for `vault`'s next page one mint, if one waits.
pub(crate) fn run_before_page_mint(vault: &Vault) {
    run_waiting(ActPoint::PageMint, vault);
}
