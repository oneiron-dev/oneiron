//! Doors for `tests/recovery_box_hold_client.rs`,
//! `tests/recovery_box_boot_heal.rs` and `tests/recovery_box_kit_only_watch.rs`:
//! the recovery box hold caller managed boot installs, on a socket the test
//! serves and with a bound the test picks (Fable pass 27 R7), the boot heal
//! over a vault the test owns, the heal gate held shut for the bound row, and
//! the watch that follows the owner's kit-only fact, with a fact reader the
//! test picks.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use oneiron_vault_contract::TokenHex;

use crate::managed::recovery_box_hold::kit_only_watch::{KitOnlyFollow, fold_kit_only_fact};
use crate::managed::recovery_box_hold::{HealRunning, HypnosRecoveryBoxHold};
use crate::server::HousekeepingAdmission;

pub use crate::managed::recovery_box_hold::{KitOnlyFact, KitOnlyFactRead, KitOnlyLook};

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
/// state exists, with managed boot's kit-only fact reader. `admitted` stands
/// in for the background admission (a reap pause or a deleted vault answers
/// `false` and the marker stays).
pub fn heal_at_boot(
    client: &HypnosRecoveryBoxHold,
    vault: Arc<oneiron::Vault>,
    admitted: bool,
) -> Option<JoinHandle<()>> {
    heal_at_boot_reading(client, vault, admitted, fold_kit_only_fact())
}

/// [`heal_at_boot`] with `read` as the kit-only fact reader.
pub fn heal_at_boot_reading(
    client: &HypnosRecoveryBoxHold,
    vault: Arc<oneiron::Vault>,
    admitted: bool,
    read: KitOnlyFactRead,
) -> Option<JoinHandle<()>> {
    client.heal_at_boot(vault, admission(admitted), read)
}

/// The background admission: `admitted` or a refusal, every time.
fn admission(admitted: bool) -> HousekeepingAdmission {
    Arc::new(move || admitted.then(|| Box::new(()) as Box<dyn Send>))
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

/// The watch that follows the owner's kit-only fact, one look per call, as
/// managed boot's cadence runs them, over `vault` with `read` as the fact
/// reader.
pub struct KitOnlyWatch {
    client: HypnosRecoveryBoxHold,
    vault: Arc<oneiron::Vault>,
    admit: HousekeepingAdmission,
    read: KitOnlyFactRead,
    follow: KitOnlyFollow,
}

impl KitOnlyWatch {
    /// One look: what managed boot's watch does at each tick.
    pub fn look(&mut self) -> KitOnlyLook {
        self.client
            .look_at_kit_only_fact(&self.vault, &self.admit, &self.read, &mut self.follow)
    }
}

/// The kit-only watch over `vault`, with nothing acknowledged yet, as a
/// process starts it. `admitted` stands in for the background admission.
#[must_use]
pub fn kit_only_watch(
    client: &HypnosRecoveryBoxHold,
    vault: Arc<oneiron::Vault>,
    admitted: bool,
    read: KitOnlyFactRead,
) -> KitOnlyWatch {
    KitOnlyWatch {
        client: client.clone(),
        vault,
        admit: admission(admitted),
        read,
        follow: KitOnlyFollow::default(),
    }
}

/// Managed boot's cadence of the kit-only watch over `vault`: a look at once,
/// then one every `every`, until `stopped` resolves (a stop that came first
/// ends it with no look). Needs a Tokio runtime.
pub fn follow_kit_only_fact(
    client: &HypnosRecoveryBoxHold,
    vault: Arc<oneiron::Vault>,
    read: KitOnlyFactRead,
    every: Duration,
    stopped: impl Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    client.follow_kit_only_fact(vault, admission(true), read, every, stopped)
}
