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
        self.with_write_txn_grouped(|txn| set_task_retention_days_in_txn(self, txn, days))
    }

    /// Current retention period. Zero means disabled; an unset vault uses 90 days.
    pub fn task_retention_days(&self) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        retention_days_in_txn(self, &txn)
    }
}

pub(super) fn set_task_retention_days_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    days: Option<u32>,
) -> Result<()> {
    RETENTION.put(&vault.store, txn, &(), &u64::from(days.unwrap_or(0)))
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

/// Seconds in one retention day.
const DAY_SECS: u64 = 86_400;

/// A NOTE whose kind keeps it a set number of days (ARCH-0032: a handoff's
/// 60), born longer ago than that (CALLS: OF-073 NOTE retention). A durable
/// or session-sealed kind never passes. The archive keeps the body and its
/// indexes, and restore brings the NOTE back; nothing here erases.
pub(super) fn note_is_past_retention(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(row) = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, id)?
    else {
        return Ok(false);
    };
    let Ok(note) = crate::note::decode_note_body_in_txn(&vault.store, txn, &row.body) else {
        return Ok(false);
    };
    let Some(kind) =
        crate::note::descriptor_in_txn(&vault.store, txn, note.kind.as_str().as_ref())?
    else {
        return Ok(false);
    };
    let (crate::note::RetentionDefault::ArchiveAfterDays, Some(days)) =
        (kind.retention, kind.archive_after_days)
    else {
        return Ok(false);
    };
    if days == 0 {
        return Ok(false);
    }
    Ok(vault.now_recorded_at().saturating_sub(row.learned_at) > u64::from(days) * DAY_SECS)
}
