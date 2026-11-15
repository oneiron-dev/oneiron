//! The commitment owner Setting keys: rows the setting catalogue reads from this file.
//!
//! Each key ships a good default plus an owner opt-out. The default is exactly today's constant,
//! so nothing changes until the owner moves it. A raise is the loosening. Only the owner sets
//! these keys.

use serde::{Deserialize, Serialize};

use super::types::{CommitmentContent, MAX_COMMITMENT_TEXT_BYTES};
use crate::Vault;
use crate::commitment_wake::{COMMITMENT_REMINDER_WORDING_MAX_BYTES, MAX_QUOTED_PROMISE_CHARS};
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The most bytes a new commitment's text may hold: 1 to 65,536.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct CommitmentTextCap(pub(crate) u32);

impl SettingValue for CommitmentTextCap {
    fn check(self) -> Result<Self> {
        if !(1..=65_536).contains(&self.0) {
            return Err(Error::InvalidConfig(
                "a commitment text cap is 1 byte to 65,536 bytes".into(),
            ));
        }
        Ok(self)
    }
}

/// The most chars of the promise a commitment reminder quotes: 1 to 65,536.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ReminderQuoteCap(pub(crate) u32);

impl SettingValue for ReminderQuoteCap {
    fn check(self) -> Result<Self> {
        if !(1..=65_536).contains(&self.0) {
            return Err(Error::InvalidConfig(
                "a reminder quote cap is 1 char to 65,536 chars".into(),
            ));
        }
        Ok(self)
    }
}

/// The most bytes a filed commitment reminder wording may hold: 1 to 65,536.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ReminderWordingCap(pub(crate) u32);

impl SettingValue for ReminderWordingCap {
    fn check(self) -> Result<Self> {
        if !(1..=65_536).contains(&self.0) {
            return Err(Error::InvalidConfig(
                "a reminder wording cap is 1 byte to 65,536 bytes".into(),
            ));
        }
        Ok(self)
    }
}

/// Eight KiB: the cap before the owner moves it, and what an unreadable row reads as.
fn commitment_text_default() -> CommitmentTextCap {
    CommitmentTextCap(MAX_COMMITMENT_TEXT_BYTES as u32)
}

/// Four hundred chars: the cap before the owner moves it, and what an unreadable row reads as.
fn reminder_quote_default() -> ReminderQuoteCap {
    ReminderQuoteCap(MAX_QUOTED_PROMISE_CHARS as u32)
}

/// Four KiB: the cap before the owner moves it, and what an unreadable row reads as.
fn reminder_wording_default() -> ReminderWordingCap {
    ReminderWordingCap(COMMITMENT_REMINDER_WORDING_MAX_BYTES as u32)
}

crate::setting::setting_keys! {
    /// The most bytes a new commitment's text may hold; 8,192 by default. A raise lets new
    /// commitments hold more text, and is the looser value. Only the owner sets it.
    pub(crate) COMMITMENT_MAX_TEXT_BYTES: CommitmentTextCap = "commitment.content.max_text_bytes" {
        kind: Kind::new(commitment_text_default)
            .strictest(commitment_text_default)
            .tighter(lower_is_tighter::<CommitmentTextCap>),
    };
    /// How many chars of the promise a commitment reminder quotes; 400 by default. A raise
    /// quotes more of the promise, and is the looser value. Only the owner sets it.
    pub(crate) REMINDER_MAX_QUOTED_CHARS: ReminderQuoteCap = "commitment.reminder.max_quoted_chars" {
        kind: Kind::new(reminder_quote_default)
            .strictest(reminder_quote_default)
            .tighter(lower_is_tighter::<ReminderQuoteCap>),
    };
    /// The most bytes a filed commitment reminder wording may hold; 4,096 by default. A raise
    /// lets longer wordings be filed, and is the looser value. Only the owner sets it.
    pub(crate) REMINDER_WORDING_MAX_BYTES: ReminderWordingCap = "commitment.reminder.max_wording_bytes" {
        kind: Kind::new(reminder_wording_default)
            .strictest(reminder_wording_default)
            .tighter(lower_is_tighter::<ReminderWordingCap>),
    };
}

/// Refuses caller-new `content` over the text cap in force, in `txn`. Births call it. Decodes,
/// status changes and series instances never do, so a stored row always decodes.
pub(crate) fn check_commitment_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    content: &CommitmentContent,
) -> Result<()> {
    let cap = COMMITMENT_MAX_TEXT_BYTES
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0;
    super::codec::validate_non_empty_bounded(
        &content.text,
        cap as usize,
        "commitment content text must be non-empty and bounded",
    )
}

/// The reminder quote cap in force, in `txn`: how many chars of the promise a reminder quotes.
pub(crate) fn reminder_quote_cap_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<usize> {
    Ok(REMINDER_MAX_QUOTED_CHARS
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0 as usize)
}

/// The reminder wording cap in force, in `txn`: the most bytes a filed wording may hold.
pub(crate) fn reminder_wording_cap_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<usize> {
    Ok(REMINDER_WORDING_MAX_BYTES
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0 as usize)
}
