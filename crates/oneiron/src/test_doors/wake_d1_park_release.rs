//! Doors for `tests/wake_d1_park_release.rs` (#6877, WAKE-D1): the wake
//! pass's local node id and the owner notice a park waiting on the owner's
//! release raises. Compiled only under `--cfg oneiron_test_support`; never
//! API.

use crate::Result;
use crate::dreamer_runner::DreamerParkedAttemptRecord;
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

/// Whether the vault's embedded owner saw `park`'s release notice; `None`
/// when it was never raised.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn park_notice_seen(vault: &Vault, park: &DreamerParkedAttemptRecord) -> Result<Option<bool>> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner");
    let txn = vault.store.env.read_txn()?;
    vault.notification_seen_in_txn(
        &txn,
        &crate::dreamer_runner::park_release_notice_source(park),
        &owner,
    )
}
