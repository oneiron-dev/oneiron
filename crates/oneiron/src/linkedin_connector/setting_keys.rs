//! The LinkedIn pack's seat Setting keys (owner ruling PACK-SETTINGS-ALL = B; RULING
//! PACK-KEYS-LINKEDIN-SWEEPS = A): whether a request its host flags as a sweep may go, on whose
//! clock a seat's daily caps reset when its host names no reset, and how far back an inbox sync
//! reads a seat's messages. Each default is the shipped behaviour. The owner changes a value; an
//! agent's change waits on the owner's approval.
//!
//! Direction: a sweep reaches more people outside the vault, so allowing sweeps is looser and
//! needs the owner's device yes; a row that does not decode reads as no sweeps. The cap day has
//! no safe side, so it has no order, and a row that does not decode reads as the UTC day. A
//! longer backfill is more automated reads of the owner's seat, so a shorter one is tighter, and
//! a row that does not decode reads as no backfill.

use serde::{Deserialize, Serialize};

use super::{DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS, MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS};
use crate::commitment_wake::CommitmentReminderRoute;
use crate::error::{Error, Result};
use crate::linkedin_connector::LinkedInSeatSandboxPolicy;
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The day a LinkedIn seat's daily caps count over when its host names no reset instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinkedInCapDayReset {
    /// The caps reset at the next UTC midnight.
    UtcMidnight,
    /// The caps reset at the next midnight on the owner's clock: the zone or offset of the
    /// owner's reminder route, else UTC.
    OwnerLocalMidnight,
}

impl SettingValue for LinkedInCapDayReset {}

/// Seconds of a LinkedIn seat's message history an inbox sync reads: 0 (none) to
/// [`MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS`] (366 days), the ceiling every sync config keeps.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct InboxBackfillSecs(pub(crate) u64);

impl SettingValue for InboxBackfillSecs {
    fn check(self) -> Result<Self> {
        if self.0 <= MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a LinkedIn inbox backfill is at most {MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS} seconds"
            )))
        }
    }
}

const fn no_sweeps() -> bool {
    false
}

const fn utc_midnight() -> LinkedInCapDayReset {
    LinkedInCapDayReset::UtcMidnight
}

const fn backfill_default() -> InboxBackfillSecs {
    InboxBackfillSecs(DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS)
}

const fn backfill_max() -> InboxBackfillSecs {
    InboxBackfillSecs(MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS)
}

const fn no_backfill() -> InboxBackfillSecs {
    InboxBackfillSecs(0)
}

crate::setting::setting_keys! {
    /// Whether a LinkedIn send, connect request or profile read its host flags as a sweep may go
    /// (default false: every sweep is suppressed, `linkedin.no_sweeps`). When true, a sweep is
    /// judged as any other request: the kill switch, the session, the seat's daily caps and its
    /// cadence still bound it. false is tighter; turning it on needs the owner's device yes.
    pub(crate) LINKEDIN_SWEEPS_ALLOWED: bool = "linkedin.sweeps_allowed" {
        kind: Kind::new(no_sweeps)
            .strictest(no_sweeps)
            .tighter(lower_is_tighter::<bool>),
    };
    /// The midnight at which a LinkedIn seat's daily caps reset when its host names no reset
    /// instant (default utc_midnight; owner_local_midnight is the owner's clock: the reminder
    /// route's zone or offset, else UTC). It names only when a send a daily cap holds is tried
    /// again: the vault's own count of a seat's DMs and connect requests is a rolling 24 h
    /// window, so a switch never gives one day two caps. No order: neither day sends more.
    pub(crate) LINKEDIN_SEAT_CAP_DAY_RESET: LinkedInCapDayReset = "linkedin.seat.cap_day_reset" {
        kind: Kind::new(utc_midnight).strictest(utc_midnight),
    };
    /// Seconds of history the inbox sync of a seat the vault serves reads on each poll: a
    /// message older than this when the poll first sees it is skipped (default 604,800: 7 days).
    /// [`LINKEDIN_INBOX_BACKFILL_MAX`] bounds it. Shorter is tighter: fewer automated reads of the
    /// owner's seat.
    pub(crate) LINKEDIN_INBOX_BACKFILL_DEFAULT: InboxBackfillSecs =
        "linkedin.inbox.backfill_default_secs" {
        kind: Kind::new(backfill_default)
            .strictest(no_backfill)
            .tighter(lower_is_tighter::<InboxBackfillSecs>),
    };
    /// The longest history any LinkedIn inbox sync reads, whatever its own config names (default
    /// 31,622,400: 366 days, the ceiling every sync config keeps). Shorter is tighter: fewer
    /// automated reads of the owner's seat.
    pub(crate) LINKEDIN_INBOX_BACKFILL_MAX: InboxBackfillSecs =
        "linkedin.inbox.backfill_max_secs" {
        kind: Kind::new(backfill_max)
            .strictest(no_backfill)
            .tighter(lower_is_tighter::<InboxBackfillSecs>),
    };
}

/// The owner's LinkedIn inbox backfill, read once for one enqueue pass or one poll.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkedInInboxBackfill {
    default_secs: u64,
    max_secs: u64,
}

impl LinkedInInboxBackfill {
    /// The backfill in force at the vault scope.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn read(vault: &crate::Vault) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let default_secs = LINKEDIN_INBOX_BACKFILL_DEFAULT
            .read_in_txn(vault, &txn, &[], None)?
            .value
            .0;
        let max_secs = LINKEDIN_INBOX_BACKFILL_MAX
            .read_in_txn(vault, &txn, &[], None)?
            .value
            .0;
        Ok(Self {
            default_secs,
            max_secs,
        })
    }

    /// The history a served seat's poll reads: the owner's default, never past the owner's
    /// ceiling.
    #[must_use]
    pub(crate) fn served_window_secs(self) -> u64 {
        self.default_secs.min(self.max_secs)
    }

    /// `window_secs`, a sync config's own history, cut to the owner's ceiling.
    #[must_use]
    pub(crate) fn bounded_window_secs(self, window_secs: u64) -> u64 {
        window_secs.min(self.max_secs)
    }
}

/// The history a served seat's poll reads under the vault's backfill keys: a test door, built
/// only under `--cfg oneiron_test_support`.
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn served_inbox_backfill_secs(vault: &crate::Vault) -> Result<u64> {
    Ok(LinkedInInboxBackfill::read(vault)?.served_window_secs())
}

/// The day a seat's caps reset on, as one evaluation reads it.
#[derive(Debug, Clone, Default)]
enum CapDay {
    /// The UTC day.
    #[default]
    Utc,
    /// The owner's day: the reminder route in force, when the owner set one.
    Owner(Option<CommitmentReminderRoute>),
}

/// The owner's LinkedIn seat settings, read once for one seat evaluation. The default is the
/// shipped behaviour: no sweeps, the UTC day.
#[derive(Debug, Clone, Default)]
pub(crate) struct LinkedInSeatSettings {
    sweeps_allowed: bool,
    cap_day: CapDay,
}

impl LinkedInSeatSettings {
    /// The settings in force at the vault scope, with the owner's reminder route when the caps
    /// reset on the owner's day.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn read(vault: &crate::Vault) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let sweeps_allowed = LINKEDIN_SWEEPS_ALLOWED
            .read_in_txn(vault, &txn, &[], None)?
            .value;
        let cap_day = match LINKEDIN_SEAT_CAP_DAY_RESET
            .read_in_txn(vault, &txn, &[], None)?
            .value
        {
            LinkedInCapDayReset::UtcMidnight => CapDay::Utc,
            LinkedInCapDayReset::OwnerLocalMidnight => {
                CapDay::Owner(vault.commitment_reminder_route_in_txn(&txn)?)
            }
        };
        Ok(Self {
            sweeps_allowed,
            cap_day,
        })
    }

    /// `policy` under these settings at `now`: the owner's sweep setting named, and the instant
    /// its daily caps reset after `now`, the host's own while it is ahead, else the next midnight
    /// of the owner's cap day.
    #[must_use]
    pub(crate) fn apply(
        &self,
        policy: LinkedInSeatSandboxPolicy,
        now: u64,
    ) -> LinkedInSeatSandboxPolicy {
        let policy = policy.with_sweeps_allowed(self.sweeps_allowed);
        match &self.cap_day {
            CapDay::Utc => policy.with_caps_reset_after(now),
            CapDay::Owner(route) => policy.with_caps_reset_after_on(now, |at| {
                route
                    .as_ref()
                    .and_then(|route| route.utc_offset_minutes_at(at))
                    .unwrap_or(0)
            }),
        }
    }
}

/// `policy` under the vault's seat settings at `now`, as the outbound seat wall and the transport
/// apply them: a test door, built only under `--cfg oneiron_test_support`.
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn seat_policy_under_settings(
    vault: &crate::Vault,
    policy: LinkedInSeatSandboxPolicy,
    now: u64,
) -> Result<LinkedInSeatSandboxPolicy> {
    Ok(LinkedInSeatSettings::read(vault)?.apply(policy, now))
}
