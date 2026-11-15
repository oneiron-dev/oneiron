//! Doors for the Setting primitive's tests (DESIGN 15-setting-primitive, stage 0.1).

#[cfg(feature = "test-support")]
use crate::Vault;
#[cfg(feature = "test-support")]
use crate::consent::AuthenticatedOwner;
#[cfg(feature = "test-support")]
use crate::error::{Error, Result};
#[cfg(feature = "test-support")]
use crate::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};

pub use super::setting_keys::hooked_changes;

/// Plants bytes no row encodes to as `key`'s value row at `scope`: a damaged store.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(feature = "test-support")]
pub fn plant_undecodable_row(vault: &Vault, key: &str, scope: SettingScope) -> Result<()> {
    crate::setting::put_stored_bytes(vault, key, SettingMode::Value, scope, &[0xc1, 0xc1])
}

/// Makes each of `requests` as the owner through `Vault::set_setting_in_txn`, all in one write,
/// then fails that write when `fail` is set: the changes commit together or not at all.
///
/// # Errors
///
/// A change's refusal; `InvalidConfig` when `fail` is set; storage errors.
#[cfg(feature = "test-support")]
pub fn set_settings_in_one_write(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    requests: &[SetSetting],
    fail: bool,
) -> Result<Vec<SetSettingOutcome>> {
    vault.with_write_txn_grouped(|txn| {
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            outcomes.push(vault.set_setting_in_txn(txn, SettingCaller::Owner(owner), request)?);
        }
        if fail {
            return Err(Error::InvalidConfig(
                "the caller's write fails after its changes".into(),
            ));
        }
        Ok(outcomes)
    })
}
