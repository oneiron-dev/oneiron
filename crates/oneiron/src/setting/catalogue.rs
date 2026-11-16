//! The catalogue: every key the crate declares, assembled by the build script from each
//! `setting_keys.rs`.

use super::{SettingKey, SettingSpec};
use crate::error::{Error, Result};

include!(concat!(env!("OUT_DIR"), "/setting_catalogue.rs"));

/// Every catalogue key, sorted by its name.
#[must_use]
pub fn catalogue() -> Vec<&'static SettingSpec> {
    SETTING_CATALOGUE.iter().map(|key| key.spec()).collect()
}

/// The catalogue row named `name`.
///
/// # Errors
///
/// `InvalidConfig` when no catalogue key has this name.
pub fn spec_named(name: &str) -> Result<&'static SettingSpec> {
    SETTING_CATALOGUE
        .binary_search_by(|key| key.spec().name.cmp(name))
        .map(|index| SETTING_CATALOGUE[index].spec())
        .map_err(|_| Error::InvalidConfig(format!("no setting key is named `{name}`")))
}

/// Whether a leave of a shared vault keeps this `SETTING` or `SETTING_CONTENT` row (`full_key`,
/// with its table's prefix): a row of a key that holds a choice about this machine (`sync:
/// install`), as the leave keeps the other rows the host talks to its home with. A vault key's
/// row, or a row whose key this build does not know, goes with the vault's other rows.
#[cfg(feature = "sync")]
pub(crate) fn leave_keeps_row(full_key: &[u8]) -> bool {
    [
        &crate::side_table::SETTING,
        &crate::side_table::SETTING_CONTENT,
    ]
    .iter()
    .find_map(|decl| full_key.strip_prefix(decl.prefix))
    .and_then(oneiron_setting_contract::RowKey::decode)
    .and_then(|key| spec_named(&key.name).ok())
    .is_some_and(|spec| spec.sync == super::SettingSync::Install)
}
