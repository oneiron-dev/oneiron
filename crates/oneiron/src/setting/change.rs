//! The change stream: one `SETTING_CHANGE` row per change, written in the commit that makes it,
//! and the erase scrubs over every setting table.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::RowKey;

use super::read::{CONTENT_ROWS, ROWS, StoredRow};
use super::{EncodedValue, Setter, SettingMode, SettingScope};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const CHANGES: SideTable<u64, SettingChange, Named> = SideTable::new(&side_table::SETTING_CHANGE);
const CHANGE_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::SETTING_CHANGE_NEXT);

/// One change to one setting row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingChange {
    /// Its id: what the change feed names it by.
    pub id: EntityId,
    /// Its place in the stream: one more than the change before it.
    pub sequence: u64,
    pub key: String,
    pub item: Option<String>,
    pub scope: SettingScope,
    pub mode: SettingMode,
    /// Who made it; `None` once an erase took that actor out.
    pub by: Option<EntityId>,
    /// In which capacity.
    pub setter: Setter,
    /// The row's value before; `None` when there was no row.
    pub prior: Option<EncodedValue>,
    /// The row's value after; `None` when the change cleared it.
    pub value: Option<EncodedValue>,
    /// When it committed, on the vault's recording clock.
    pub at: u64,
    /// The setter's reason, when it gave one.
    pub why: Option<String>,
}

/// Writes `change` under the next sequence, in the caller's write; returns its sequence.
pub(super) fn record_change_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    mut change: SettingChange,
) -> Result<SettingChange> {
    let sequence = CHANGE_NEXT
        .get(store, txn, &())?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("setting change sequence"))?;
    CHANGE_NEXT.put(store, txn, &(), &sequence)?;
    change.sequence = sequence;
    CHANGES.put(store, txn, &sequence, &change)?;
    Ok(change)
}

/// The last change sequence handed out, or `None` before the first.
pub(crate) fn settings_head_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
    Ok(CHANGE_NEXT
        .get(store, txn, &())?
        .filter(|sequence| *sequence > 0))
}

/// Up to `limit` changes after `after`, oldest first, and the last sequence read.
pub(crate) fn settings_after_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    after: Option<u64>,
    limit: usize,
) -> Result<(Vec<SettingChange>, Option<u64>)> {
    let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut changes = Vec::new();
    let mut through = None;
    for row in CHANGES.iter_range(store, txn, start, Bound::Unbounded)? {
        if changes.len() >= limit {
            break;
        }
        let (sequence, change) = row?;
        through = Some(sequence);
        changes.push(change);
    }
    Ok((changes, through))
}

/// Whether `bytes` hold `needle`: a value names an entity by its hex id.
fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// The rows of `table` an erase of `id` changes: a row whose scope names it goes; a row it set
/// stays, as it was set, and no longer names who set it.
fn scrub_rows_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    table: SideTable<Vec<u8>, StoredRow, Named>,
    id: &EntityId,
) -> Result<()> {
    let mut gone = Vec::new();
    let mut unnamed = Vec::new();
    for row in table.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        if RowKey::decode(&key).is_some_and(|key| key.scope.entity() == Some(*id)) {
            gone.push(key);
        } else if let Ok(stored) = rmp_serde::from_slice::<StoredRow>(&bytes)
            && stored.by == Some(*id)
        {
            unnamed.push((key, StoredRow { by: None, ..stored }));
        }
    }
    for key in gone {
        table.delete(store, txn, &key)?;
    }
    for (key, row) in unnamed {
        table.put(store, txn, &key, &row)?;
    }
    Ok(())
}

/// The change rows an erase of `id` changes: a change at a scope that names it, or whose value
/// or reason names it, goes; a change it made stays and no longer names it.
fn scrub_changes_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let hex = id.to_hex();
    let mut gone = Vec::new();
    let mut unnamed = Vec::new();
    for row in CHANGES.iter_from(store, txn, &[])? {
        let (sequence, change) = row?;
        let names_it = change.scope.entity() == Some(*id)
            || [&change.prior, &change.value]
                .into_iter()
                .flatten()
                .any(|value| holds(&value.0, hex.as_bytes()))
            || change.why.as_deref().is_some_and(|why| why.contains(&hex));
        if names_it {
            gone.push(sequence);
        } else if change.by == Some(*id) {
            unnamed.push((sequence, SettingChange { by: None, ..change }));
        }
    }
    for sequence in gone {
        CHANGES.delete(store, txn, &sequence)?;
    }
    for (sequence, change) in unnamed {
        CHANGES.put(store, txn, &sequence, &change)?;
    }
    Ok(())
}

/// `SETTING`'s actor scrub: an erased actor's own rows go, and the rows it set no longer name it.
pub(crate) fn erase_setting_row_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    scrub_rows_in_txn(&vault.store, txn, ROWS, actor)
}

/// `SETTING_CONTENT`'s actor scrub, as `SETTING`'s.
pub(crate) fn erase_setting_content_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    scrub_rows_in_txn(&vault.store, txn, CONTENT_ROWS, actor)
}

/// `SETTING_CHANGE`'s actor scrub: no change row keeps naming an erased actor.
pub(crate) fn erase_setting_change_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    scrub_changes_in_txn(&vault.store, txn, actor)
}

/// The per-entity eraser: an erased world, project, thread, goal or repository takes every
/// setting row at its scope, and every change that names it, with it.
pub(crate) fn erase_setting_entity_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    scrub_rows_in_txn(store, txn, ROWS, id)?;
    scrub_rows_in_txn(store, txn, CONTENT_ROWS, id)?;
    scrub_changes_in_txn(store, txn, id)
}
