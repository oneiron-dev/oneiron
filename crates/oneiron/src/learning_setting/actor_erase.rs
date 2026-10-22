//! An erased owner out of the seed and pin rows that name it (FIX 3520).

use super::SETTING;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the owner rows. The choice rows ask it too.
pub(crate) use crate::deletion::names_no_actor;

/// Erasing `actor` from the owner's seed and pin rows (FIX 3520): each row
/// it set keeps its value, weight, mode, scope, time and reason, and its
/// setter reads [`ERASED_CALL_IDENTITY`]. A row still steers its knob: no
/// read of the value in force asks who set it. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_setting_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let mut rows = Vec::new();
    for (key, mut row) in SETTING.scan(&vault.store, wtxn)? {
        if row.by == hex {
            row.by = ERASED_CALL_IDENTITY.to_owned();
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        SETTING.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
