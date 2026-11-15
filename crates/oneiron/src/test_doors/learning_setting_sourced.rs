//! A learned knob's read, for the knob tests: the value in force beside the
//! change or fit that decided it, by the typed key or by the knob's
//! catalogue name (most knobs' keys are crate-private).

use crate::error::Error;
use crate::learning_setting::{
    learned_setting, setting_value_in_scope_sourced_in_txn, setting_value_scoped,
};
use crate::setting::Setting;
use crate::{EntityId, Result, Vault};

/// The value in force for `key` over the whole vault, with the rows that
/// decided it (`setting_value_in_scope_sourced_in_txn` with no project and
/// no type).
///
/// # Errors
/// The read's.
#[doc(hidden)]
pub fn setting_value_sourced(
    vault: &Vault,
    key: &Setting<f64>,
) -> Result<(f64, Option<Vec<EntityId>>)> {
    let txn = vault.store.env.read_txn()?;
    setting_value_in_scope_sourced_in_txn(vault, &txn, key, None, None)
}

/// The learned knob whose catalogue name is `name`.
fn knob_named(name: &str) -> Result<&'static Setting<f64>> {
    learned_setting(name)
        .ok_or_else(|| Error::InvalidConfig(format!("no learned knob is named `{name}`")))
}

/// The value in force for the learned knob named `name` where `project`
/// applies, or for the whole vault when `project` is `None`
/// (`learning_setting::setting_value_scoped` with no type).
///
/// # Errors
/// A name that is no learned knob; the read's.
#[doc(hidden)]
pub fn knob_value(vault: &Vault, name: &str, project: Option<EntityId>) -> Result<f64> {
    setting_value_scoped(vault, knob_named(name)?, project, None)
}

/// [`knob_value`] with the rows that decided it: the setting change that
/// wrote the deciding row, a fit's cell heads, or none for the shipped seed
/// (`setting_value_in_scope_sourced_in_txn` with no type).
///
/// # Errors
/// A name that is no learned knob; the read's.
#[doc(hidden)]
pub fn knob_value_sourced(
    vault: &Vault,
    name: &str,
    project: Option<EntityId>,
) -> Result<(f64, Option<Vec<EntityId>>)> {
    let key = knob_named(name)?;
    let txn = vault.store.env.read_txn()?;
    setting_value_in_scope_sourced_in_txn(vault, &txn, key, project, None)
}
