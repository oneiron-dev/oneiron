//! Release gate for automatic cleanup. Owner posture cannot close release blockers.

use super::*;
#[cfg(test)]
use crate::side_table::{self, Raw, SideTable};

const SYNC_REGATING_CLOSED: bool = false;
const OS_SANDBOX_CLOSED: bool = false;

/// Test-only marker closing both release blockers. Key: (); value: `b"1"`.
#[cfg(test)]
const TEST_BLOCKERS_CLOSED: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_TEST_BLOCKERS_CLOSED);

#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
pub(super) fn auto_enabled(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    #[cfg(test)]
    if TEST_BLOCKERS_CLOSED.contains(&vault.store, txn, &())? {
        return Ok(true);
    }
    let _ = (vault, txn);
    Ok(SYNC_REGATING_CLOSED && OS_SANDBOX_CLOSED)
}

#[cfg(test)]
pub(super) fn close_blockers_for_test(vault: &Vault) {
    vault
        .with_write_txn(|txn| TEST_BLOCKERS_CLOSED.put(&vault.store, txn, &(), &b"1".to_vec()))
        .expect("test-only rollout closure");
}
