//! Owner-adjustable completed-TASK retention. Never erases task bytes.

use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

const RETENTION: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_TASK_RETENTION_DAYS);
const DEFAULT_DAYS: u64 = 90;

impl Vault {
    /// Sets completed-task retention; `None` or zero disables this arm.
    /// Like the cleanup posture setter, this is a trusted owner configuration door.
    pub fn set_task_retention_days(&self, days: Option<u32>) -> Result<()> {
        self.with_write_txn(|txn| {
            RETENTION.put(&self.store, txn, &(), &u64::from(days.unwrap_or(0)))?;
            Ok(())
        })
    }

    /// Current retention period. Zero means disabled; an unset vault uses 90 days.
    pub fn task_retention_days(&self) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        retention_days_in_txn(self, &txn)
    }
}

pub(super) fn retention_days_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(RETENTION
        .get(&vault.store, txn, &())?
        .unwrap_or(DEFAULT_DAYS))
}

pub(super) fn task_is_past_retention(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let days = retention_days_in_txn(vault, txn)?;
    if days == 0 {
        return Ok(false);
    }
    let Some(age) = days.checked_mul(86_400) else {
        return Ok(false);
    };
    Ok(crate::task_verb::completed_task_at_in_txn(vault, txn, *id)?
        .is_some_and(|finished| vault.now_recorded_at().saturating_sub(finished) > age))
}
