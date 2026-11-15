//! Door for `tests/mcp_page_continuation_rejudge.rs`: one act run at a vault's
//! next page one mint, after its producer read and before the mint judges
//! which rows its caller read, where a Grant revoked, or a clock step that
//! expires one, while page one is made lands.

use std::sync::{Mutex, PoisonError};

use oneiron::Vault;

type PageMintAct = Box<dyn FnOnce() + Send>;

/// Acts waiting for a vault's next page one mint, by the vault's address, so
/// tests running side by side never take each other's act.
static BEFORE_PAGE_MINT: Mutex<Vec<(usize, PageMintAct)>> = Mutex::new(Vec::new());

/// Runs `act` once, at the next page one mint on `vault`: after its
/// producer's read, before the mint judges which rows its caller read.
pub fn before_next_page_mint(vault: &Vault, act: impl FnOnce() + Send + 'static) {
    BEFORE_PAGE_MINT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((std::ptr::from_ref(vault).addr(), Box::new(act)));
}

/// Runs the act waiting for `vault`'s next page one mint, if one waits.
pub(crate) fn run_before_page_mint(vault: &Vault) {
    let address = std::ptr::from_ref(vault).addr();
    let act = {
        let mut waiting = BEFORE_PAGE_MINT
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        waiting
            .iter()
            .position(|(waiting_on, _)| *waiting_on == address)
            .map(|index| waiting.remove(index).1)
    };
    if let Some(act) = act {
        act();
    }
}
