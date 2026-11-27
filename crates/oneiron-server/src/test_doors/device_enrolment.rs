//! `oneiron device enrol` against the files serve reads, for the
//! re-enrolment of a machine that is enrolled already (`device enrol
//! --replace`, review r1 of #10417; `tests/device_enrol_replace.rs`).

use std::path::PathBuf;

use oneiron::Vault;

use crate::config::ServeConfig;

/// The enrolment record and the credential file `oneiron device enrol`
/// writes for `vault` beside `config`'s key directory.
///
/// # Errors
///
/// No key directory: `config` names none and neither XDG_STATE_HOME nor HOME
/// names one.
pub fn enrolment_files(config: &ServeConfig, vault: &Vault) -> anyhow::Result<(PathBuf, PathBuf)> {
    let files = crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, vault)?;
    Ok((files.record, files.credential))
}

/// Enrols `vault`'s machine from `link` into those files, as `oneiron device
/// enrol` does for a copy of its home's vault; `replace` is `--replace`.
///
/// # Errors
///
/// Why the enrolment was refused or failed.
pub fn enrol(config: &ServeConfig, vault: &Vault, link: &str, replace: bool) -> anyhow::Result<()> {
    let files = crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, vault)?;
    crate::device_sync::enrol(vault, &files, link, None, replace).map(drop)
}

/// Replaces the stored enrolment as `device enrol --replace` stores the one
/// its home answered: with the record stored now, and `credential`.
///
/// # Errors
///
/// No readable enrolment, or why the replacement failed.
pub fn replace_enrolment(
    config: &ServeConfig,
    vault: &Vault,
    credential: &str,
) -> anyhow::Result<()> {
    let files = crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, vault)?;
    let record = files
        .read()?
        .ok_or_else(|| anyhow::anyhow!("this vault holds no enrolment to replace"))?;
    files.replace(credential, &record)
}
