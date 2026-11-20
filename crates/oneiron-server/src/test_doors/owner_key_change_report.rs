//! Doors for `tests/owner_key_change_report.rs`: the owner key change
//! reporter managed boot installs, on a socket the test serves and with a
//! bound the test picks, and one report sweep over a vault (Engine ruling
//! 21 Nov 06:00).

use std::path::Path;
use std::time::Duration;

use oneiron_vault_contract::TokenHex;

use crate::managed::owner_key_change_report::HypnosOwnerKeyChange;

/// The reporter for `vault` with spawn token `token_hex`, on `socket`, each
/// call bounded by `timeout`.
#[must_use]
pub fn report_client(
    socket: &Path,
    vault: &str,
    token_hex: &str,
    timeout: Duration,
) -> HypnosOwnerKeyChange {
    HypnosOwnerKeyChange::with_timeout(
        socket.to_path_buf(),
        vault.to_owned(),
        TokenHex::new(token_hex.to_owned()),
        timeout,
    )
}

/// Runs one report sweep over `vault` with `report`: every listed change the
/// cursor row does not name is sent, oldest first. The fake supervisor's
/// lines and the cursor row say what the sweep did.
pub fn sweep_once(vault: &oneiron::Vault, report: &HypnosOwnerKeyChange) {
    let _ = crate::managed::owner_key_change_report::sweep_once(vault, report);
}
