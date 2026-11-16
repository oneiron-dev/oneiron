//! Doors for `tests/recovery_box_hold_client.rs` and
//! `tests/recovery_box_boot_heal.rs`: the recovery box hold caller managed
//! boot installs, on a socket the test serves and with a bound the test
//! picks (Fable pass 27 R7), the boot heal over a vault the test owns, and
//! the heal gate held shut for the bound row.

use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use oneiron_vault_contract::TokenHex;

use crate::managed::recovery_box_hold::{HealRunning, HypnosRecoveryBoxHold};

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

/// The boot heal over `vault`: what managed boot runs once the managed
/// state exists. `admitted` stands in for the background admission (a reap
/// pause or a deleted vault answers `false` and the marker stays).
pub fn heal_at_boot(
    client: &HypnosRecoveryBoxHold,
    vault: Arc<oneiron::Vault>,
    admitted: bool,
) -> Option<JoinHandle<()>> {
    client.heal_at_boot(
        vault,
        Arc::new(move || admitted.then(|| Box::new(()) as Box<dyn Send>)),
    )
}

/// The heal gate held shut: a switch's hold waits until this drops.
pub struct HealGateClosed {
    _running: HealRunning,
}

/// Closes the client's heal gate until the returned value drops.
pub fn close_heal_gate(client: &HypnosRecoveryBoxHold) -> HealGateClosed {
    HealGateClosed {
        _running: client.close_heal_gate(),
    }
}
