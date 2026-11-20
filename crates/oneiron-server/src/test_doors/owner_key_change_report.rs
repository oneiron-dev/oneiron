//! Doors for `tests/owner_key_change_report.rs`: the owner key change
//! reporter managed boot installs, on a socket the test serves and with a
//! bound the test picks, the cursor's boot baseline, and one report sweep
//! over a vault (Engine ruling 21 Nov 06:00).

use std::path::Path;
use std::sync::atomic::AtomicBool;
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

/// Writes the cursor row's baseline over `vault`, as managed boot does
/// before anything serves: every current entry, nothing sent.
pub fn baseline_cursor(vault: &oneiron::Vault) {
    crate::managed::owner_key_change_report::baseline_cursor(vault);
}

/// Runs one report sweep over `vault` with `report`: every listed change the
/// cursor row does not name is sent, oldest first. The fake supervisor's
/// lines and the cursor row say what the sweep did.
pub fn sweep_once(vault: &oneiron::Vault, report: &HypnosOwnerKeyChange) {
    sweep_once_until(vault, report, &AtomicBool::new(false));
}

/// [`sweep_once`] with the stop flag the reporter task sets when it ends:
/// a set `stop` sends nothing more and ends a wait for an ack.
pub fn sweep_once_until(vault: &oneiron::Vault, report: &HypnosOwnerKeyChange, stop: &AtomicBool) {
    let _ = crate::managed::owner_key_change_report::sweep_once(vault, report, stop);
}
