//! The calendar's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B): when and for which
//! meetings a prep pack is put in front of the owner and how long it may be; and when a meeting
//! check-in is asked, asked once more, and kept. Each default is the shipped value: the prep
//! keys default to [`PrepPolicy::default`], the re-ask hour to [`super::wake`]'s, and the two
//! check-in windows to [`CHECK_IN_CATCH_UP_SECS`]. The owner changes a value; an agent's change
//! waits on the owner's approval.
//!
//! Direction: no key contacts anyone but the owner, and none has a safe side, so none has an
//! order. A row that does not decode reads as the shipped value: with no safe side there is
//! nothing stricter, and the card pass must go on for every other meeting.

use serde::{Deserialize, Serialize};

use super::wake::{CHECK_IN_RE_ASK_LOCAL_HOUR, DEFAULT_PREP_LEAD_SECS, PrepPolicy};
use crate::calendar::inbox_card::CHECK_IN_CATCH_UP_SECS;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue};

/// An hour of the owner's local day, 0 to 23.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct LocalHour(pub(crate) u8);

impl SettingValue for LocalHour {
    fn check(self) -> Result<Self> {
        if self.0 < 24 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "an hour of the day is 0 to 23".to_owned(),
            ))
        }
    }
}

/// The most words a prep pack holds: at least 1 (a ceiling of 0 would deliver every pack empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct PrepWordCeiling(pub(crate) u32);

impl SettingValue for PrepWordCeiling {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a prep pack holds at least one word".to_owned(),
            ))
        }
    }
}

/// The longest check-in window: about 285 million years, and a number every SDK carries exactly.
const CHECK_IN_WINDOW_MAX_SECS: u64 = (1 << 53) - 1;

/// Seconds a check-in window lasts: at least 1 (a catch-up window of 0 would ask no check-in the
/// pass did not reach at the very second it came due) and at most [`CHECK_IN_WINDOW_MAX_SECS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct CheckInWindowSecs(pub(crate) u64);

impl SettingValue for CheckInWindowSecs {
    fn check(self) -> Result<Self> {
        if (1..=CHECK_IN_WINDOW_MAX_SECS).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a check-in window is 1 to {CHECK_IN_WINDOW_MAX_SECS} seconds"
            )))
        }
    }
}

fn re_ask_hour() -> LocalHour {
    LocalHour(CHECK_IN_RE_ASK_LOCAL_HOUR)
}

fn prep_lead() -> u64 {
    DEFAULT_PREP_LEAD_SECS
}

fn prep_external_only() -> bool {
    PrepPolicy::default().external_only
}

fn prep_max_words() -> PrepWordCeiling {
    PrepWordCeiling(u32::try_from(PrepPolicy::default().max_words).unwrap_or(u32::MAX))
}

fn check_in_window() -> CheckInWindowSecs {
    CheckInWindowSecs(CHECK_IN_CATCH_UP_SECS)
}

crate::setting::setting_keys! {
    /// The hour of the owner's local day at which a meeting check-in left unanswered is asked
    /// once more, on the day after it was first asked (default 9, so 09:00). No order: the
    /// re-ask goes to the owner alone.
    pub(crate) CALENDAR_CHECK_IN_RE_ASK_HOUR: LocalHour = "calendar.check_in.re_ask_local_hour" {
        kind: Kind::new(re_ask_hour).strictest(re_ask_hour),
    };
    /// Seconds after a meeting's end and the vault's grace during which a check-in the card pass
    /// has not yet asked is still asked (default 86,400: a host that was down for a day still
    /// asks, and a year of imported past meetings is never asked at once). No order: the
    /// check-in goes to the owner alone.
    pub(crate) CALENDAR_CHECK_IN_CATCH_UP: CheckInWindowSecs = "calendar.check_in.catch_up_secs" {
        kind: Kind::new(check_in_window).strictest(check_in_window),
    };
    /// Seconds a rested check-in stays in the INBOX after its re-ask settled (default 86,400).
    /// No order: the card is the owner's.
    pub(crate) CALENDAR_CHECK_IN_RESTED_KEEP: CheckInWindowSecs =
        "calendar.check_in.rested_keep_secs" {
        kind: Kind::new(check_in_window).strictest(check_in_window),
    };
    /// Whether a meeting with no outside attendee (internal-only or solo) needs its own opt-in
    /// before a prep pack is built for it (default true: ARCH-0060 "External meetings only
    /// (default)"). No order: the pack goes to the owner alone.
    pub(crate) CALENDAR_PREP_EXTERNAL_ONLY: bool = "calendar.prep.external_only" {
        kind: Kind::new(prep_external_only).strictest(prep_external_only),
    };
    /// Seconds before a meeting's start at which its prep pack is built and put in front of the
    /// owner (default 2,700: T-45, ARCH-0060 "T-45 default"). No order: the pack is the owner's.
    pub(crate) CALENDAR_PREP_LEAD: u64 = "calendar.prep.lead_secs" {
        kind: Kind::new(prep_lead).strictest(prep_lead),
    };
    /// The most words a prep pack holds, counted after ordering (default 250: ARCH-0060
    /// "<=250 words"). No order: the pack is the owner's.
    pub(crate) CALENDAR_PREP_MAX_WORDS: PrepWordCeiling = "calendar.prep.max_words" {
        kind: Kind::new(prep_max_words).strictest(prep_max_words),
    };
}

/// The vault's prep policy in `txn`: its lead from [`CALENDAR_PREP_LEAD`], its word ceiling from
/// [`CALENDAR_PREP_MAX_WORDS`], and its opt-in rule from [`CALENDAR_PREP_EXTERNAL_ONLY`].
///
/// # Errors
///
/// Storage errors.
pub(crate) fn prep_policy_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<PrepPolicy> {
    let max_words = CALENDAR_PREP_MAX_WORDS
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0;
    Ok(PrepPolicy {
        lead_secs: CALENDAR_PREP_LEAD.read_in_txn(vault, txn, &[], None)?.value,
        max_words: usize::try_from(max_words).unwrap_or(usize::MAX),
        external_only: CALENDAR_PREP_EXTERNAL_ONLY
            .read_in_txn(vault, txn, &[], None)?
            .value,
    })
}

/// [`prep_policy_in_txn`] in a read transaction of its own, for a door that holds none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn prep_policy(vault: &crate::Vault) -> Result<PrepPolicy> {
    let rtxn = vault.store.env.read_txn()?;
    prep_policy_in_txn(vault, &rtxn)
}

/// The owner's local hour for a check-in's morning re-ask, from
/// [`CALENDAR_CHECK_IN_RE_ASK_HOUR`].
///
/// # Errors
///
/// Storage errors.
pub(crate) fn check_in_re_ask_hour_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<u8> {
    Ok(CALENDAR_CHECK_IN_RE_ASK_HOUR
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0)
}

/// The vault's two check-in windows, read once per card pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckInWindows {
    /// From [`CALENDAR_CHECK_IN_CATCH_UP`].
    pub(crate) catch_up_secs: u64,
    /// From [`CALENDAR_CHECK_IN_RESTED_KEEP`].
    pub(crate) rested_keep_secs: u64,
}

/// The vault's check-in windows in `txn`.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn check_in_windows_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<CheckInWindows> {
    Ok(CheckInWindows {
        catch_up_secs: CALENDAR_CHECK_IN_CATCH_UP
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
        rested_keep_secs: CALENDAR_CHECK_IN_RESTED_KEEP
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
    })
}
