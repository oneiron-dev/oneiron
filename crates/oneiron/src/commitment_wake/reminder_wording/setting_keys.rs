//! The reminder wording's owner Setting key (DESIGN 15-setting-primitive; restriction wave 16,
//! C122): the longest wording a worder may file. The crate's build script lists the row in the
//! setting catalogue. Default = today: nothing changes until the owner sets the key.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::COMMITMENT_REMINDER_WORDING_MAX_BYTES;
use crate::setting::{Kind, SettingValue, lower_is_tighter};
use crate::{Error, Result, Vault};

/// The `commitment.reminder.max_wording_bytes` value: the longest reminder wording, in bytes, a
/// worder may file. At least one byte; a larger value is the looser one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ReminderWordingMaxBytes(pub(crate) u32);

impl SettingValue for ReminderWordingMaxBytes {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            Err(Error::InvalidConfig(
                "a reminder wording's longest size is at least one byte".into(),
            ))
        } else {
            Ok(self)
        }
    }
}

/// 4,096 bytes: the longest wording a worder could file before the bound became a key.
fn default_wording_max_bytes() -> ReminderWordingMaxBytes {
    ReminderWordingMaxBytes(
        u32::try_from(COMMITMENT_REMINDER_WORDING_MAX_BYTES).unwrap_or(u32::MAX),
    )
}

crate::setting::setting_keys! {
    /// The longest wording, in bytes, a model or persona worder may file for one of the owner's
    /// commitment reminders (default 4,096). A longer wording is refused, and the reminder sends
    /// its fixed wording. At least one byte. A larger value is looser, so only the owner raises
    /// it; an agent's raise waits on the owner's answer.
    pub(crate) REMINDER_WORDING_MAX_BYTES: ReminderWordingMaxBytes = "commitment.reminder.max_wording_bytes" {
        kind: Kind::new(default_wording_max_bytes)
            .strictest(default_wording_max_bytes)
            .tighter(lower_is_tighter::<ReminderWordingMaxBytes>),
    };
}

/// The longest wording in force, in bytes: the owner's row, a key holder's tighter row within
/// it, or the default when none stands. It reads in a read of its own: both filing doors check
/// the wording before they open their write.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn reminder_wording_max_bytes(vault: &Vault) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let max = REMINDER_WORDING_MAX_BYTES
        .read_in_txn(vault, &txn, &[], None)?
        .value;
    Ok(usize::try_from(max.0).unwrap_or(usize::MAX))
}
