//! Test-only deletion of a live policy row without touching its restored binding.

use crate::error::Result;
use crate::{EntityId, Vault};

/// Deletes only the named SOURCE_AUDIENCE_POLICY row, preserving every other row.
///
/// # Errors
///
/// Storage failures.
#[cfg(oneiron_test_support)]
pub(crate) fn remove_policy_row(vault: &Vault, policy: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| super::POLICIES.delete(&vault.store, txn, &policy).map(drop))
}

/// The DERIVED side table as stored, for pass 30's bench (never merged):
/// its entries, the bytes of their full keys and of their values.
///
/// # Errors
///
/// Storage failures.
#[cfg(oneiron_test_support)]
pub(crate) fn derived_table_bytes(vault: &Vault) -> Result<(u64, u64, u64)> {
    let txn = vault.store.env.read_txn()?;
    let mut entries = 0_u64;
    let mut key_bytes = 0_u64;
    let mut value_bytes = 0_u64;
    for (row, _) in super::DERIVED.scan(&vault.store, &txn)? {
        entries += 1;
        key_bytes += super::DERIVED.key_bytes(&row).len() as u64;
        value_bytes += super::DERIVED
            .get_bytes(&vault.store, &txn, &row)?
            .map_or(0, |bytes| bytes.len() as u64);
    }
    Ok((entries, key_bytes, value_bytes))
}
