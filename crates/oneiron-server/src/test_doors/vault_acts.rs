//! The one registry behind the doors that run a test's act at a point of a
//! vault's next request ([`super::mcp_page_mint`],
//! [`super::memory_owner_commit`]). An act waits by its point and the
//! vault's address, so tests running side by side never take each other's
//! act.

use std::sync::{Mutex, PoisonError};

use oneiron::Vault;

/// A point of a request where a waiting act runs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ActPoint {
    /// A vault's next page one mint, after its producer read and before the
    /// mint judges which rows its caller read.
    PageMint,
    /// A vault's next core memory `retract`, `supersede`, `delete` or
    /// `hard_delete` on the owner's path, after the route admitted the owner
    /// and before the vault's door opens its writer.
    OwnerCommit,
}

type VaultAct = Box<dyn FnOnce() + Send>;

/// Acts waiting at a point of a vault's next request, by the point and the
/// vault's address.
static WAITING: Mutex<Vec<(ActPoint, usize, VaultAct)>> = Mutex::new(Vec::new());

/// Runs `act` once, the next time `point` is reached on `vault`.
pub(super) fn run_at_next(point: ActPoint, vault: &Vault, act: impl FnOnce() + Send + 'static) {
    WAITING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((point, std::ptr::from_ref(vault).addr(), Box::new(act)));
}

/// Runs the act waiting at `point` for `vault`, if one waits.
pub(super) fn run_waiting(point: ActPoint, vault: &Vault) {
    let address = std::ptr::from_ref(vault).addr();
    let act = {
        let mut waiting = WAITING.lock().unwrap_or_else(PoisonError::into_inner);
        waiting
            .iter()
            .position(|(at, waiting_on, _)| *at == point && *waiting_on == address)
            .map(|index| waiting.remove(index).2)
    };
    if let Some(act) = act {
        act();
    }
}
