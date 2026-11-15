//! The settings `secret_custody` keeps (DESIGN 15-setting-primitive): each row is one catalogue
//! key, and the crate's build script lists it in the setting catalogue.

use serde::{Deserialize, Serialize};

use super::REVEAL_ASK_TTL_SECS;
use crate::setting::{Kind, SettingValue, lower_is_tighter};
use crate::{Error, Result, Vault};

/// How long an agent's reveal waits for the owner's answer, and a covered reveal for its
/// collection, in seconds: the value of the owner's setting `secrets.reveal.ask_window_secs`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct RevealAskWindowSecs(pub u64);

impl RevealAskWindowSecs {
    /// One hour, the window before the key existed.
    fn shipped() -> Self {
        Self(REVEAL_ASK_TTL_SECS)
    }
}

impl SettingValue for RevealAskWindowSecs {
    /// At least one second: a window of none ends every ask, and every covered reveal, in the
    /// write that files it.
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "a reveal's window is at least one second".into(),
            ));
        }
        Ok(self)
    }
}

crate::setting::setting_keys! {
    /// How long an agent's reveal ask waits for the owner's answer, and a covered reveal for its
    /// collection, in seconds. A longer window loosens. Each reveal keeps the window it was filed
    /// with, so a change applies to the reveals filed after it. Absent, one hour.
    pub(crate) REVEAL_ASK_WINDOW: RevealAskWindowSecs = "secrets.reveal.ask_window_secs" {
        kind: Kind::new(RevealAskWindowSecs::shipped)
            .tighter(lower_is_tighter::<RevealAskWindowSecs>),
    };
}

/// The reveal window in force in `txn`, in seconds ([`REVEAL_ASK_WINDOW`]).
///
/// # Errors
///
/// An unreadable deciding row (the key names no strictest value); storage errors.
pub(crate) fn reveal_ask_window_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(REVEAL_ASK_WINDOW
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0)
}
