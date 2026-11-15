//! Publisher share dial: explicit, install-profile, and compiled-default resolution.
//!
//! Both dials are catalogue keys (`edit_distance::setting_keys`): the owner sets them with
//! `vault.settings.set`, and every change is a row of the settings change stream.

use crate::Vault;
use crate::edit_distance::setting_keys::{PUBLISHER_ENABLED, PUBLISHER_INSTALL_DEFAULT};
use crate::error::Error;
use crate::setting::SettingSource;

use super::PublisherResult;

/// The compiled fallback: disabled.
///
/// The engine cannot know its own posture, and it is the OSS/self-hostable
/// artifact — "self-host picks posture at install" (§9) means a build that
/// never picked must not send to a publisher nobody chose. This is posture
/// resolution, not a wall: one write to either key flips it.
pub const PUBLISHER_ENABLED_COMPILED_DEFAULT: bool = false;

/// Resolves the effective publisher dial.
///
/// Order: the owner's explicit dial, then the install profile, then the
/// compiled default. The explicit dial sits on top deliberately — an install
/// profile that overrode a dial the owner set would make it a wall, and this
/// is ratified as a dial (worklog D4). A dial row that does not read reads as
/// off.
///
/// # Errors
///
/// Storage errors.
pub fn publisher_enabled(vault: &Vault) -> PublisherResult<bool> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(publisher_enabled_in_txn(vault, &rtxn)?)
}

/// [`publisher_enabled`] on the caller's transaction, for a check made under
/// a writer: the publisher delivery rechecks the dial where it admits a send
/// (OF-420).
///
/// # Errors
///
/// As [`publisher_enabled`].
pub(crate) fn publisher_enabled_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<bool> {
    let explicit = PUBLISHER_ENABLED.read_in_txn(vault, txn, &[], None)?;
    if explicit.source != SettingSource::Default {
        return Ok(explicit.value);
    }
    Ok(PUBLISHER_INSTALL_DEFAULT
        .read_in_txn(vault, txn, &[], None)?
        .value)
}

/// The key of the setting the effective dial reads from: the owner's explicit
/// dial, else the install profile's default. `None`: no row holds the dial and
/// the compiled default stands.
///
/// # Errors
///
/// As [`publisher_enabled`].
pub(crate) fn publisher_dial_row_ref_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<Option<String>> {
    for key in [&PUBLISHER_ENABLED, &PUBLISHER_INSTALL_DEFAULT] {
        if key.read_in_txn(vault, txn, &[], None)?.source != SettingSource::Default {
            return Ok(Some(key.spec.name.to_owned()));
        }
    }
    Ok(None)
}
