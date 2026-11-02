//! An erased scope's owner rows and fits go with it (FIX 6038, FIX 11533):
//! its erase deletes every seed and pin laid over that project or goal,
//! whoever set it, and every cached fit keyed by it as a project or a
//! subject, even where no cell is left. Rows over the vault, a type,
//! another project or another goal stay as they are.

use super::fit::parse_setting_fit_key;
use super::{SETTING, SettingScope, parse_row_key};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Deletes the owner setting rows scoped to `entity` as a project or a goal
/// and every cached fit keyed by it as a project or a subject, in the
/// erase's own transaction. A key its codec does not read is passed over
/// with a WARN, never an abort: the erase is the owner's own act.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_setting_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let rows = SETTING
        .iter_raw_from(&vault.store, wtxn, &[])?
        .map(|row| row.map(|(key, _)| key))
        .collect::<Result<Vec<_>>>()?;
    for key in project_row_keys(rows, entity, "setting") {
        SETTING.delete(&vault.store, wtxn, &key)?;
    }
    let fits = crate::learning::project::SETTING_FIT
        .iter_raw_from(&vault.store, wtxn, &[])?
        .map(|row| row.map(|(key, _)| key))
        .collect::<Result<Vec<_>>>()?;
    for raw in fits {
        let Some(stored) = std::str::from_utf8(&raw).ok() else {
            tracing::warn!("a setting fit key that does not read is passed over by an erase");
            continue;
        };
        match parse_setting_fit_key(stored) {
            Some((_, scoped, subject, _))
                if scoped == Some(*entity) || subject == Some(*entity) =>
            {
                crate::learning::project::SETTING_FIT.delete(
                    &vault.store,
                    wtxn,
                    &stored.to_owned(),
                )?;
            }
            Some(_) => {}
            None => {
                tracing::warn!("a setting fit key that does not parse is passed over by an erase");
            }
        }
    }
    Ok(())
}

/// The owner-row keys among `rows` (a setting or choice table's raw keys)
/// whose scope is exactly `entity`, as a project or a goal. A key that does
/// not parse is passed over with a WARN.
pub(crate) fn project_row_keys(
    rows: Vec<Vec<u8>>,
    entity: &EntityId,
    table: &'static str,
) -> Vec<String> {
    let mut out = Vec::new();
    for raw in rows {
        let Some(stored) = String::from_utf8(raw).ok() else {
            tracing::warn!(
                table,
                "an owner row key that does not read is passed over by an erase"
            );
            continue;
        };
        let Some((_, _, scope)) = parse_row_key(&stored) else {
            tracing::warn!(
                table,
                "an owner row key that does not parse is passed over by an erase"
            );
            continue;
        };
        if scope == SettingScope::Project(*entity) || scope == SettingScope::Goal(*entity) {
            out.push(stored);
        }
    }
    out
}
