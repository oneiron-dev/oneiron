//! Doors for `tests/wake_d1_park_release.rs` (#6877, WAKE-D1) on the red base
//! (main 9d546e95f2): only the doors whose items main already has. The owner
//! notice door (`park_notice_seen`) names the notice source #6877 adds, so it
//! is absent here. Compiled only under `--cfg oneiron_test_support`; never
//! API.

use crate::Result;
use crate::vault::Vault;

/// This device's stable client id (`identity::load_or_mint_client_id`), which
/// a wake pass takes as its local node id.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    crate::identity::load_or_mint_client_id(vault)
}
