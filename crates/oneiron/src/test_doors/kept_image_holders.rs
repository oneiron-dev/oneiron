//! Doors for the restore swap's hold on the bodies of the archive it parks (FIX 6022;
//! REVIEW-10247 round 2). Compiled only under `--cfg oneiron_test_support`; never API.

use crate::{Result, Vault};

/// How many holder records of kept body instances the vault's local key custody keeps: one per
/// kept image copy and one per archive a restore's swap parked. `0` without local custody.
///
/// # Errors
///
/// Custody faults, and a record that does not decode.
pub fn image_holder_record_count(vault: &Vault) -> Result<usize> {
    vault.store.image_holder_record_count()
}
