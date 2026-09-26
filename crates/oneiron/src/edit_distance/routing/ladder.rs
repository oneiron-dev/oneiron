//! Rollout ladder promotion.

use super::keys::{ROW_VERSION, RUNG, RUNG_ROW_LABEL, StoredRung, normalized_task_class};
use super::scope::RolloutRung;
use crate::Vault;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// The rollout ladder
// ---------------------------------------------------------------------------

/// How far `task_class` has been promoted. [`RolloutRung::Shadow`] until an
/// owner says otherwise.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an unusable task class; storage errors;
/// [`Error::CorruptedIndex`] on an undecodable row.
pub fn rollout_rung(vault: &Vault, task_class: &str) -> Result<RolloutRung> {
    let key = normalized_task_class(task_class)?.to_owned();
    let rtxn = vault.store.env.read_txn()?;
    rung_in_txn(vault, &rtxn, &key)
}

/// Promotes or demotes `task_class` on the rollout ladder.
///
/// The ladder moves ONLY through this door — nothing in this module promotes a
/// scope because its numbers looked convincing.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an unusable task class; storage errors.
pub fn set_rollout_rung(vault: &Vault, task_class: &str, rung: RolloutRung) -> Result<()> {
    let key = normalized_task_class(task_class)?.to_owned();
    let row = StoredRung {
        v: ROW_VERSION,
        rung: rung.as_str().to_owned(),
    };
    vault.with_write_txn(|wtxn| RUNG.put(&vault.store, wtxn, &key, &row))
}

pub(super) fn rung_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &String,
) -> Result<RolloutRung> {
    let Some(row) = RUNG.get(&vault.store, rtxn, key)? else {
        return Ok(RolloutRung::Shadow);
    };
    RolloutRung::parse(&row.rung).ok_or(Error::CorruptedIndex(RUNG_ROW_LABEL))
}
