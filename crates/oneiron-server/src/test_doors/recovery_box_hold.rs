//! Doors for `tests/recovery_box_hold_client.rs`: the recovery box hold
//! caller managed boot installs, on a socket the test serves and with a bound
//! the test picks (Fable pass 27 R7).

use std::path::Path;
use std::time::Duration;

use oneiron_vault_contract::TokenHex;

use crate::managed::recovery_box_hold::HypnosRecoveryBoxHold;

/// The caller for `vault` with spawn token `token_hex`, on `socket`, each
/// call bounded by `timeout`.
#[must_use]
pub fn hold_client(
    socket: &Path,
    vault: &str,
    token_hex: &str,
    timeout: Duration,
) -> HypnosRecoveryBoxHold {
    HypnosRecoveryBoxHold::with_timeout(
        socket.to_path_buf(),
        vault.to_owned(),
        TokenHex::new(token_hex.to_owned()),
        timeout,
    )
}
