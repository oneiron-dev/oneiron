//! A learning setting's sourced read, for the cap-order test: the value in
//! force for the whole vault beside the act that decided it.

use crate::learning_setting::{SettingSpec, setting_value_in_scope_sourced_in_txn};
use crate::{EntityId, Result, Vault};

/// The value in force for `spec` over the whole vault, with the rows that
/// decided it (`setting_value_in_scope_sourced_in_txn` with no project and
/// no type).
///
/// # Errors
/// The read's.
#[doc(hidden)]
pub fn setting_value_sourced(
    vault: &Vault,
    spec: &SettingSpec,
) -> Result<(f64, Option<Vec<EntityId>>)> {
    let txn = vault.store.env.read_txn()?;
    setting_value_in_scope_sourced_in_txn(vault, &txn, spec, None, None)
}
