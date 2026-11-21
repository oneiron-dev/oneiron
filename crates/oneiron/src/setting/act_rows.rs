//! The rows of the owner's act that a change of a row belongs to, for a key's hook that judges its
//! row by what the same act does to another row (row SETTING-PROJECTED-ROW-REFUSING-HOOKS, PR 4:
//! the owner's pick of the source a calendar keeps, SETTING-PROJECTED-CALENDAR-SYSTEM-CLAIM = A).
//! A projection pass's change names its signed act, whose rows the log holds. The owner's change
//! of several rows on this install writes every row before any hook runs and signs its act after
//! them ([`super::Vault::set_settings`]), so its rows are held for the thread while it writes
//! them ([`hold_owner_change_rows`]).

use std::cell::RefCell;

use oneiron_authority::authority::{AuthorityOp, authority_log_entity_id_from_hash};
use oneiron_setting_contract::RowKey;

use super::{SetSetting, SettingChange, SettingMode, SettingScope};
use crate::Vault;
use crate::error::Result;

thread_local! {
    /// The rows of the owner's change this thread writes ([`hold_owner_change_rows`]).
    static OWNER_CHANGE_ROWS: RefCell<Vec<ActRow>> = const { RefCell::new(Vec::new()) };
}

/// One row of an owner's act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActRow {
    pub(crate) slot: RowKey,
    /// Whether the act leaves a value there; `false` for a clear.
    pub(crate) sets: bool,
}

/// Holds the rows of `requests`, the owner's change this thread writes, until the returned guard
/// drops.
pub(super) fn hold_owner_change_rows(requests: &[SetSetting]) -> OwnerChangeRows {
    let rows = requests
        .iter()
        .map(|request| ActRow {
            slot: RowKey {
                name: request.key.clone(),
                item: request.item.clone(),
                mode: request.mode,
                scope: request.scope.clone(),
            },
            sets: request.value.as_ref().is_some_and(|value| !value.is_null()),
        })
        .collect();
    OWNER_CHANGE_ROWS.with(|held| *held.borrow_mut() = rows);
    OwnerChangeRows(())
}

/// Lets go of the rows [`hold_owner_change_rows`] held once it drops.
pub(super) struct OwnerChangeRows(());

impl Drop for OwnerChangeRows {
    fn drop(&mut self) {
        OWNER_CHANGE_ROWS.with(|held| held.borrow_mut().clear());
    }
}

/// The rows of the act `change` belongs to, read in `txn`: those of its signed act where it names
/// one (a projection pass's change), else those of the owner's change this thread writes; none
/// for any other change.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn act_rows_of_change_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &SettingChange,
) -> Result<Vec<ActRow>> {
    let Some(act) = change.signed else {
        return Ok(OWNER_CHANGE_ROWS.with(|held| held.borrow().clone()));
    };
    let id = authority_log_entity_id_from_hash(&act)?;
    let Some(entry) = vault.get_authority_log_entry_in_txn(txn, &id)? else {
        return Ok(Vec::new());
    };
    let AuthorityOp::PolicySettingSet(set) = entry.op else {
        return Ok(Vec::new());
    };
    let row = |setting: String, slot: Option<RowKey>, value: Option<[u8; 32]>| ActRow {
        slot: slot.unwrap_or_else(|| RowKey {
            name: setting,
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Vault,
        }),
        sets: value.is_some(),
    };
    let mut rows = vec![row(set.setting, set.slot, set.value)];
    rows.extend(
        set.more
            .into_iter()
            .map(|more| row(more.setting, more.slot, more.value)),
    );
    Ok(rows)
}
