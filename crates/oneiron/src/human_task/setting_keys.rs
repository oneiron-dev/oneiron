//! The human-task follow-up ladder's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B): the
//! three intervals between the nudges a person gets about a TASK assigned to them. Each default
//! is the shipped ladder of [`oneiron_base::human_task_followup`]. The owner changes a value; an
//! agent's change, either way, waits on the owner's approval.
//!
//! Direction: these keys make the engine contact another person, so more or sooner contact is
//! looser. A longer interval is tighter: the person is contacted no sooner and no more often
//! than it says. A row that does not decode reads as never, so a damaged row stops the nudges and
//! never fails the TASK write that registers a cursor.

use oneiron_base::human_task_followup::{
    DIGEST_AFTER_SECONDS, ESCALATION_AFTER_SECONDS, FollowupTimings, REMINDER_AFTER_SECONDS,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, higher_is_tighter};

/// The longest interval: about 285 million years, so never in practice, and a number every SDK
/// carries exactly. An unreadable row reads as this.
const NEVER_SECS: u64 = (1 << 53) - 1;

/// Seconds between two follow-up stages: at least 1 (0 would send again on every pass) and at
/// most [`NEVER_SECS`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct FollowupIntervalSecs(pub(crate) u64);

impl SettingValue for FollowupIntervalSecs {
    fn check(self) -> Result<Self> {
        if (1..=NEVER_SECS).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a follow-up interval is 1 to {NEVER_SECS} seconds"
            )))
        }
    }
}

fn reminder_after() -> FollowupIntervalSecs {
    FollowupIntervalSecs(REMINDER_AFTER_SECONDS)
}

fn digest_after() -> FollowupIntervalSecs {
    FollowupIntervalSecs(DIGEST_AFTER_SECONDS)
}

fn escalation_after() -> FollowupIntervalSecs {
    FollowupIntervalSecs(ESCALATION_AFTER_SECONDS)
}

fn never() -> FollowupIntervalSecs {
    FollowupIntervalSecs(NEVER_SECS)
}

crate::setting::setting_keys! {
    /// Seconds a person assigned a TASK that names no notice and no deadline waits before the
    /// first direct nudge (default 24 h). Longer is tighter: the cursor the TASK's write opens is
    /// first due no sooner than this after the write (register_human_followup_in_txn).
    pub(crate) HUMAN_TASK_REMINDER_AFTER: FollowupIntervalSecs =
        "human_task.followup.reminder_after_secs" {
        kind: Kind::new(reminder_after)
            .strictest(never)
            .tighter(higher_is_tighter::<FollowupIntervalSecs>),
    };
    /// Seconds from the first nudge to the open-loop digest entry (default 3 days). Longer is
    /// tighter: the digest is sent no sooner than this after the nudge (the follow-up driver's
    /// run_due).
    pub(crate) HUMAN_TASK_DIGEST_AFTER: FollowupIntervalSecs =
        "human_task.followup.digest_after_secs" {
        kind: Kind::new(digest_after)
            .strictest(never)
            .tighter(higher_is_tighter::<FollowupIntervalSecs>),
    };
    /// Seconds from the digest to the first escalation, and between escalations (default 7
    /// days). Longer is tighter: each escalation is sent no sooner than this after the stage
    /// before it (the follow-up driver's run_due).
    pub(crate) HUMAN_TASK_ESCALATION_AFTER: FollowupIntervalSecs =
        "human_task.followup.escalation_after_secs" {
        kind: Kind::new(escalation_after)
            .strictest(never)
            .tighter(higher_is_tighter::<FollowupIntervalSecs>),
    };
}

/// The ladder's three intervals in force in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn followup_timings_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<FollowupTimings> {
    let read = |key: &crate::setting::Setting<FollowupIntervalSecs>| {
        key.read_in_txn(vault, txn, &[], None)
            .map(|resolved| resolved.value.0)
    };
    Ok(FollowupTimings {
        reminder_after_secs: read(&HUMAN_TASK_REMINDER_AFTER)?,
        digest_after_secs: read(&HUMAN_TASK_DIGEST_AFTER)?,
        escalation_after_secs: read(&HUMAN_TASK_ESCALATION_AFTER)?,
    })
}
