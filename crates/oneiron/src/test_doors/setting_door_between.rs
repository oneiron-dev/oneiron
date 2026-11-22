//! The test door for a change in force between the Setting door's read and write.

use crate::Vault;
use crate::error::Result;
use crate::setting::{SetSetting, SetSettingOutcome, SettingCaller};

/// [`Vault::set_setting`] with `between` run after the door asked and before it takes the key's
/// write turn and opens its write.
///
/// # Errors
/// As [`Vault::set_setting`].
pub fn set_setting_between(
    vault: &Vault,
    caller: SettingCaller<'_>,
    request: SetSetting,
    between: impl FnOnce(),
) -> Result<SetSettingOutcome> {
    vault.set_setting_between(caller, request, between)
}
