//! Whether a served host is a device of another home
//! (`crate::device_sync::dials_home`), as plain serve and a managed vault's
//! coordinator ask it before the AI host attaches, and where serve finds the
//! enrolment it reads (FIX-LIST HOME-SELF-MARK-STALE-AS-DEVICE,
//! `tests/device_home_dial_unreadable_enrolment.rs`).

use std::path::PathBuf;

use oneiron::Vault;

use crate::config::ServeConfig;

/// Whether plain serve takes this machine for a device of another home, by
/// `config`'s `[device_sync]` section or the enrolment beside its key
/// directory.
#[must_use]
pub fn dials_home(config: &ServeConfig, vault: &Vault) -> bool {
    crate::device_sync::dials_home(config, vault)
}

/// [`dials_home`] as a managed vault's coordinator asks it: an enrolment
/// counts only beside `config`'s key directory.
#[must_use]
pub fn dials_home_managed(config: &ServeConfig, vault: &Vault) -> bool {
    crate::device_sync::dials_home_managed(config, vault)
}

/// The enrolment record `oneiron device enrol` writes for `vault` beside
/// `config`'s key directory, and serve reads.
///
/// # Errors
///
/// No key directory: `config` names none and neither XDG_STATE_HOME nor HOME
/// names one.
pub fn enrolment_record(config: &ServeConfig, vault: &Vault) -> anyhow::Result<PathBuf> {
    Ok(crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, vault)?.record)
}
