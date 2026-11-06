//! New-copy intake and owner controls for the Mac's embedded vault.
//!
//! Pasteboard objects stay on the main thread. The one worker receives only
//! wiping Rust buffers and uses the existing owner-act mutex and writer lease.

pub(crate) mod controls;
mod watcher;

pub(crate) use watcher::start;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use tauri::{AppHandle, Manager};

use super::{RekeyState, local_owner};

fn with_owner<T>(
    app: &AppHandle,
    action: impl FnOnce(&Vault, &AuthenticatedOwner) -> oneiron::Result<T>,
) -> Result<T, String> {
    let state = app.state::<RekeyState>();
    let _owner_act = state
        .confirming
        .lock()
        .map_err(|_| "the owner-act state is unavailable".to_owned())?;
    let lease = state
        .vault
        .hold_writer_lease_for_owner_act()
        .map_err(|error| error.to_string())?;
    let owner = local_owner(&state.vault, &lease)?;
    action(&state.vault, &owner).map_err(|error| error.to_string())
}
