//! Doors for `tests/gpu_line_hold_is_the_claim.rs` (row M2-I2): a read snapshot, and the start
//! of a unit claim (`Claimed` -> `Started`), which row M2-C's start gate writes when it inserts
//! the claim's job row.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::gpu_line::ClaimKey;
use crate::vault::Vault;

/// Opens a read snapshot of `vault`.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn read_txn(vault: &Vault) -> Result<heed::RoTxn<'_>> {
    Ok(vault.store.env.read_txn()?)
}

/// Marks the open claim under `key` started, in its own write, as the start gate's
/// compare-and-set does.
///
/// # Errors
/// No claimed unit under `key`, or the store's.
#[doc(hidden)]
pub fn start_claim(vault: &Vault, key: &ClaimKey) -> Result<()> {
    vault.with_write_txn(|txn| {
        let claim = crate::gpu_line::claim_in_txn(vault, txn, key)?.ok_or_else(|| {
            crate::Error::InvalidConfig("no unit claim under this key".to_owned())
        })?;
        crate::gpu_line::claim::start_claim_in_txn(vault, txn, &claim)?
            .map(drop)
            .ok_or_else(|| crate::Error::InvalidConfig("only a claimed unit starts".to_owned()))
    })
}
