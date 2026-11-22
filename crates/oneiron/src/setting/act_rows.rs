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

use super::beside::{BesideRead, beside_row_id, beside_row_read_in_txn};
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
    /// The value it leaves there, as JSON, where this install holds it: `None` for a clear and
    /// for a value beside the act that is not here.
    pub(crate) value: Option<serde_json::Value>,
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
            value: request.value.clone().filter(|value| !value.is_null()),
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
    let row = |setting: String,
               slot: Option<RowKey>,
               (digest, inline): (Option<[u8; 32]>, Option<Vec<u8>>)|
     -> Result<ActRow> {
        let slot = slot.unwrap_or_else(|| RowKey {
            name: setting,
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Vault,
        });
        let json = match (digest, inline) {
            (_, Some(json)) => Some(json),
            (Some(digest), None) => {
                let row = beside_row_id(&slot, &digest, &act)?;
                match beside_row_read_in_txn(vault, txn, row, digest)? {
                    BesideRead::Here(json) => Some(json),
                    BesideRead::Absent | BesideRead::Unreadable => None,
                }
            }
            (None, None) => None,
        };
        Ok(ActRow {
            slot,
            sets: digest.is_some(),
            value: json.and_then(|json| serde_json::from_slice(&json).ok()),
        })
    };
    let mut rows = vec![row(set.setting, set.slot, (set.value, set.inline))?];
    for more in set.more {
        rows.push(row(more.setting, more.slot, (more.value, more.inline))?);
    }
    Ok(rows)
}
