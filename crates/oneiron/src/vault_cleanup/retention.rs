//! Owner-adjustable completed-TASK retention. Never erases task bytes.

use crate::error::{Error, Result};
use crate::{EntityId, Vault};

const RETENTION_KEY: &[u8] = b"vault_cleanup.task_retention_days.v1";
const DEFAULT_DAYS: u64 = 90;

impl Vault {
    /// Sets completed-task retention; `None` or zero disables this arm.
    /// Like the cleanup posture setter, this is a trusted owner configuration door.
    pub fn set_task_retention_days(&self, days: Option<u32>) -> Result<()> {
        self.with_write_txn(|txn| {
            self.store.vault_meta.put(
                txn,
                RETENTION_KEY,
                &u64::from(days.unwrap_or(0)).to_be_bytes(),
            )?;
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
    vault
        .store
        .vault_meta
        .get(txn, RETENTION_KEY)?
        .map_or(Ok(DEFAULT_DAYS), |raw| {
            let bytes = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("task retention days"))?;
            Ok(u64::from_be_bytes(bytes))
        })
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
