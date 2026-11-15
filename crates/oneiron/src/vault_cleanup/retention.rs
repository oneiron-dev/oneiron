//! Owner-adjustable completed-TASK retention. Never erases task bytes.

use super::setting_keys::TASK_RETENTION_DAYS;
use crate::error::Result;
use crate::{EntityId, Vault};

impl Vault {
    /// Current retention period: the catalogue key `cleanup.task_retention_days`,
    /// which the owner sets through `vault.settings.set`. Zero means disabled;
    /// an unset vault uses 90 days.
    pub fn task_retention_days(&self) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        retention_days_in_txn(self, &txn)
    }
}

pub(super) fn retention_days_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(u64::from(
        TASK_RETENTION_DAYS
            .read_in_txn(vault, txn, &[], None)?
            .value,
    ))
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

/// A NOTE whose kind, or its own override, keeps it a set number of days
/// (ARCH-0032: a handoff's 60), born longer ago than that (CALLS: OF-073
/// NOTE retention). A durable or session-sealed NOTE never passes. The
/// archive keeps the body and its indexes, and restore brings the NOTE back;
/// nothing here erases.
pub(super) fn note_is_past_retention(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        note_retention_in_txn(vault, txn, id)?.is_some_and(|(days, learned_at)| {
            vault.now_recorded_at().saturating_sub(learned_at) > u64::from(days) * DAY_SECS
        }),
    )
}

/// The days `id`'s NOTE kind, or its own override, keeps it, beside when it
/// was learned; none for a durable or session-sealed NOTE, a zero period, or
/// a row that does not read as a NOTE.
pub(super) fn note_retention_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(u32, u64)>> {
    let Some(row) = crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, id)?
    else {
        return Ok(None);
    };
    let Ok(note) = crate::note::decode_note_core_in_txn(&vault.store, txn, &row.body) else {
        return Ok(None);
    };
    let kind =
        crate::note::note_defaults_in_txn(&vault.store, txn, id, note.kind.as_str().as_ref())?;
    let (crate::store::note_kind::RetentionDefault::ArchiveAfterDays, Some(days)) =
        (kind.retention, kind.archive_after_days)
    else {
        return Ok(None);
    };
    Ok((days != 0).then_some((days, row.learned_at)))
}
