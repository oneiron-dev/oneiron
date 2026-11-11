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
