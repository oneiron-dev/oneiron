//! Rollout ladder promotion.

use super::keys::{
    ROW_VERSION, RUNG_KEY_PREFIX, RUNG_ROW_LABEL, StoredRung, decode_row, encode_row, meta_key,
    normalized_task_class,
};
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
    let key = meta_key(
        RUNG_KEY_PREFIX,
        normalized_task_class(task_class)?.as_bytes(),
    );
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
    let key = meta_key(
        RUNG_KEY_PREFIX,
        normalized_task_class(task_class)?.as_bytes(),
    );
    let encoded = encode_row(
        &StoredRung {
            v: ROW_VERSION,
            rung: rung.as_str().to_owned(),
        },
        RUNG_ROW_LABEL,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

pub(super) fn rung_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<RolloutRung> {
    let Some(raw) = vault.store.vault_meta.get(rtxn, key)? else {
        return Ok(RolloutRung::Shadow);
    };
    let row: StoredRung = decode_row(&raw, RUNG_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(RUNG_ROW_LABEL));
    }
    RolloutRung::parse(&row.rung).ok_or(Error::CorruptedIndex(RUNG_ROW_LABEL))
}
