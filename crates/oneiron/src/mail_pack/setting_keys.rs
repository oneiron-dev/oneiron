//! The mail and calendar pack's Setting keys (owner ruling PACK-SETTINGS-ALL = B): how many
//! people one drafted reply may name, and the span of time a Microsoft 365 calendar source's
//! view tracks. Each default is the shipped value. The owner changes a value; an agent's change
//! waits on the owner's approval.
//!
//! Direction: the reply ceiling bounds how many people outside the vault one agent-drafted
//! reply reaches, so a lower ceiling is tighter, and a row that does not decode reads as a reply
//! to one person. The calendar view brings the owner's own calendar into the owner's vault and
//! has no safe side, so it has no order, and a row that does not decode reads as the shipped
//! span.

use serde::{Deserialize, Serialize};

use super::microsoft365_calendar::{
    VIEW_AFTER_MAX_SECS, VIEW_AFTER_MIN_SECS, VIEW_AFTER_SECS, VIEW_BEFORE_MAX_SECS,
    VIEW_BEFORE_SECS,
};
use super::reply_recipients::MAX_REPLY_RECIPIENTS;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The most recipients one drafted reply names, To and Cc together: at least 1, the person
/// answered.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ReplyRecipientCeiling(pub(crate) u32);

impl SettingValue for ReplyRecipientCeiling {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a reply names at least one recipient".to_owned(),
            ))
        }
    }
}

/// Seconds a Microsoft 365 calendar view starts before its opening: 0 to
/// [`VIEW_BEFORE_MAX_SECS`] (366 days).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct CalendarViewBeforeSecs(pub(crate) u64);

impl SettingValue for CalendarViewBeforeSecs {
    fn check(self) -> Result<Self> {
        if self.0 <= VIEW_BEFORE_MAX_SECS {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a calendar view starts at most {VIEW_BEFORE_MAX_SECS} seconds before its opening"
            )))
        }
    }
}

/// Seconds a Microsoft 365 calendar view ends after its opening: [`VIEW_AFTER_MIN_SECS`] (the
/// month a view stands, so a view always holds the present) to [`VIEW_AFTER_MAX_SECS`] (three
/// leap years, so the view and the span before it stay inside one Graph calendar view's five
/// years).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct CalendarViewAfterSecs(pub(crate) u64);

impl SettingValue for CalendarViewAfterSecs {
    fn check(self) -> Result<Self> {
        if (VIEW_AFTER_MIN_SECS..=VIEW_AFTER_MAX_SECS).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a calendar view ends {VIEW_AFTER_MIN_SECS} to {VIEW_AFTER_MAX_SECS} seconds after its opening"
            )))
        }
    }
}

fn reply_max_recipients() -> ReplyRecipientCeiling {
    ReplyRecipientCeiling(u32::try_from(MAX_REPLY_RECIPIENTS).unwrap_or(u32::MAX))
}

fn reply_to_one() -> ReplyRecipientCeiling {
    ReplyRecipientCeiling(1)
}

fn view_before() -> CalendarViewBeforeSecs {
    CalendarViewBeforeSecs(VIEW_BEFORE_SECS)
}

fn view_after() -> CalendarViewAfterSecs {
    CalendarViewAfterSecs(VIEW_AFTER_SECS)
}

crate::setting::setting_keys! {
    /// The most recipients one drafted reply names, To and Cc together (default 50). A reply
    /// that names more is refused, never cut. Lower is tighter: fewer people outside the vault
    /// receive one reply an agent drafts.
    pub(crate) MAIL_REPLY_MAX_RECIPIENTS: ReplyRecipientCeiling =
        "mail_calendar.reply.max_recipients" {
        kind: Kind::new(reply_max_recipients)
            .strictest(reply_to_one)
            .tighter(lower_is_tighter::<ReplyRecipientCeiling>),
    };
    /// Seconds before its opening at which a Microsoft 365 calendar source's view starts
    /// (default 2,678,400: 31 days). A view opens again each month, and a new value takes effect
    /// at the next opening. No order: the owner's own calendar comes into the owner's vault.
    pub(crate) MICROSOFT365_CALENDAR_VIEW_BEFORE: CalendarViewBeforeSecs =
        "mail_calendar.microsoft365_calendar.view_before_secs" {
        kind: Kind::new(view_before).strictest(view_before),
    };
    /// Seconds after its opening at which a Microsoft 365 calendar source's view ends (default
    /// 31,622,400: 366 days); the opening's far listing reads the four years after it once. A
    /// new value takes effect at the next opening. No order: the owner's own calendar comes into
    /// the owner's vault.
    pub(crate) MICROSOFT365_CALENDAR_VIEW_AFTER: CalendarViewAfterSecs =
        "mail_calendar.microsoft365_calendar.view_after_secs" {
        kind: Kind::new(view_after).strictest(view_after),
    };
}

/// The most recipients one drafted reply names in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn reply_max_recipients_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<usize> {
    let ceiling = MAIL_REPLY_MAX_RECIPIENTS
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0;
    Ok(usize::try_from(ceiling).unwrap_or(usize::MAX))
}

/// The span a Microsoft 365 calendar view opened now tracks, at the vault scope: seconds before
/// its opening, then seconds after it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn microsoft365_calendar_view(vault: &crate::Vault) -> Result<(u64, u64)> {
    let txn = vault.store.env.read_txn()?;
    let before = MICROSOFT365_CALENDAR_VIEW_BEFORE
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0;
    let after = MICROSOFT365_CALENDAR_VIEW_AFTER
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0;
    Ok((before, after))
}
