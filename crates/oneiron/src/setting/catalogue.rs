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
