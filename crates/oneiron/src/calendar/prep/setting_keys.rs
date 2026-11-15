//! The calendar's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B): when a meeting's prep
//! pack is put in front of the owner, and the hour an unanswered check-in is asked once more.
//! Each default is the shipped value of [`super::wake`]. The owner changes a value; an agent's
//! change waits on the owner's approval.
//!
//! Direction: neither key contacts anyone but the owner, and neither has a safe side, so neither
//! has an order. A row that does not decode reads as the shipped value: with no safe side there
//! is nothing stricter, and the card pass must go on for every other meeting.

use serde::{Deserialize, Serialize};

use super::wake::{CHECK_IN_RE_ASK_LOCAL_HOUR, DEFAULT_PREP_LEAD_SECS, PrepPolicy};
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

fn re_ask_hour() -> LocalHour {
    LocalHour(CHECK_IN_RE_ASK_LOCAL_HOUR)
}

fn prep_lead() -> u64 {
    DEFAULT_PREP_LEAD_SECS
}

crate::setting::setting_keys! {
    /// The hour of the owner's local day at which a meeting check-in left unanswered is asked
    /// once more, on the day after it was first asked (default 9, so 09:00). No order: the
    /// re-ask goes to the owner alone.
    pub(crate) CALENDAR_CHECK_IN_RE_ASK_HOUR: LocalHour = "calendar.check_in.re_ask_local_hour" {
        kind: Kind::new(re_ask_hour).strictest(re_ask_hour),
    };
    /// Seconds before a meeting's start at which its prep pack is built and put in front of the
    /// owner (default 2,700: T-45, ARCH-0060 "T-45 default"). No order: the pack is the owner's.
    pub(crate) CALENDAR_PREP_LEAD: u64 = "calendar.prep.lead_secs" {
        kind: Kind::new(prep_lead).strictest(prep_lead),
    };
}

/// The vault's prep policy in `txn`: its lead from [`CALENDAR_PREP_LEAD`], every other field the
/// shipped one.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn prep_policy_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<PrepPolicy> {
    Ok(PrepPolicy {
        lead_secs: CALENDAR_PREP_LEAD.read_in_txn(vault, txn, &[], None)?.value,
        ..PrepPolicy::default()
    })
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
