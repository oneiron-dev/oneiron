//! Release gate for automatic cleanup. Owner posture cannot close release blockers.

use super::*;

const SYNC_REGATING_CLOSED: bool = false;
const OS_SANDBOX_CLOSED: bool = false;

#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
pub(super) fn auto_enabled(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    #[cfg(test)]
    if vault
        .store
        .vault_meta
        .get(txn, b"vault_cleanup.test_blockers_closed")?
        .is_some()
    {
        return Ok(true);
    }
    let _ = (vault, txn);
    Ok(SYNC_REGATING_CLOSED && OS_SANDBOX_CLOSED)
}

#[cfg(test)]
pub(super) fn close_blockers_for_test(vault: &Vault) {
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .put(txn, b"vault_cleanup.test_blockers_closed", b"1")?;
            Ok(())
        })
        .expect("test-only rollout closure");
}
