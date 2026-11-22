//! Door for `tests/setting_refusal_notice.rs` (row SETTING-PROJECTED-ROW-REFUSING-HOOKS, review
//! round 2 of PR 4): a completed poll of an ICS feed system, as an earlier feed there leaves it.

use crate::Vault;
use crate::error::Result;

/// Records a completed poll of the ICS feed system `system` on this install, as a poll of an
/// earlier feed there leaves it: no later feed is installed on that system here.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn plant_ics_feed_poll(vault: &Vault, system: &str) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::calendar::ingest::feed_door::plant_poll_completion_in_txn(vault, &mut txn, system)?;
    txn.commit()?;
    Ok(())
}
