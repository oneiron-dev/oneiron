//! The emergency reschedule's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B): how many
//! replacement times one plan offers the counterparty, the fewest live times a plan may offer
//! before it refuses and leaves the booking to the owner, and how far past the affected window it
//! searches for them. Each default is the shipped value (3, 2 and seven days). The owner changes
//! a value; an agent's change waits on the owner's approval.
//!
//! Direction: the count and the search span change which times one apology offers, never
//! whether anyone is contacted or how often, so neither has an order, and a row of either that
//! does not decode reads as the shipped value. The floor is tighter higher: below it the plan
//! refuses, no automated apology goes out, and the owner handles the booking; an unreadable floor
//! reads as the highest, so every plan refuses. The floor never exceeds the count: a change that
//! would put it above refuses, and a pair that arrives so by sync or a restore makes every plan
//! refuse (the plan collects at most the count, which is fewer than the floor).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingChange, SettingValue, higher_is_tighter};

/// The shipped count of replacement times one emergency plan offers.
pub(crate) const DEFAULT_EMERGENCY_MAX_PROPOSALS: u8 = 3;

/// The shipped floor: a plan with fewer live replacement times refuses.
pub(crate) const DEFAULT_EMERGENCY_MIN_PROPOSALS: u8 = 2;

/// The shipped search span past the affected window: seven days.
pub(crate) const DEFAULT_EMERGENCY_SEARCH_SPAN_SECS: u64 = 7 * 86_400;

/// The shortest search span: a day, so a plan always looks past the rest of the affected day.
const MIN_EMERGENCY_SEARCH_SPAN_SECS: u64 = 86_400;

/// The longest search span: a number every SDK carries exactly. The solver still bounds the
/// search by the event type's own booking window.
const MAX_EMERGENCY_SEARCH_SPAN_SECS: u64 = (1 << 53) - 1;

/// A count of replacement times: at least 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct EmergencyProposalCount(pub(crate) u8);

impl SettingValue for EmergencyProposalCount {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "an emergency plan counts at least one replacement time".to_owned(),
            ))
        }
    }
}

/// Seconds past the affected window a plan searches: at least a day and at most
/// [`MAX_EMERGENCY_SEARCH_SPAN_SECS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct EmergencySearchSpanSecs(pub(crate) u64);

impl SettingValue for EmergencySearchSpanSecs {
    fn check(self) -> Result<Self> {
        if (MIN_EMERGENCY_SEARCH_SPAN_SECS..=MAX_EMERGENCY_SEARCH_SPAN_SECS).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "an emergency search span is {MIN_EMERGENCY_SEARCH_SPAN_SECS} to \
                 {MAX_EMERGENCY_SEARCH_SPAN_SECS} seconds"
            )))
        }
    }
}

fn max_proposals() -> EmergencyProposalCount {
    EmergencyProposalCount(DEFAULT_EMERGENCY_MAX_PROPOSALS)
}

fn min_proposals() -> EmergencyProposalCount {
    EmergencyProposalCount(DEFAULT_EMERGENCY_MIN_PROPOSALS)
}

fn highest_min_proposals() -> EmergencyProposalCount {
    EmergencyProposalCount(u8::MAX)
}

fn search_span() -> EmergencySearchSpanSecs {
    EmergencySearchSpanSecs(DEFAULT_EMERGENCY_SEARCH_SPAN_SECS)
}

crate::setting::setting_keys! {
    /// How many replacement times one emergency reschedule plan offers the counterparty, its
    /// solver's top live ones (default 3). No order: one apology goes out whatever the count.
    pub(crate) BOOKING_EMERGENCY_MAX_PROPOSALS: EmergencyProposalCount =
        "booking.emergency.max_proposals" {
        kind: Kind::new(max_proposals).strictest(max_proposals),
        on_change: Some(refuse_floor_above_count),
    };
    /// The fewest live replacement times an emergency reschedule plan may offer (default 2, at
    /// most `booking.emergency.max_proposals`). Higher is tighter: with fewer, the plan refuses,
    /// no automated apology goes out, and the owner handles the booking.
    pub(crate) BOOKING_EMERGENCY_MIN_PROPOSALS: EmergencyProposalCount =
        "booking.emergency.min_proposals" {
        kind: Kind::new(min_proposals)
            .strictest(highest_min_proposals)
            .tighter(higher_is_tighter::<EmergencyProposalCount>),
        on_change: Some(refuse_floor_above_count),
    };
    /// Seconds past the affected window an emergency reschedule plan searches for replacement
    /// times (default 604,800: seven days; at least a day). No order: it changes which times one
    /// apology offers, not whether one goes out.
    pub(crate) BOOKING_EMERGENCY_SEARCH_SPAN: EmergencySearchSpanSecs =
        "booking.emergency.search_span_secs" {
        kind: Kind::new(search_span).strictest(search_span),
    };
}

/// What one emergency reschedule plan offers: read once per plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmergencyProposalPolicy {
    /// From [`BOOKING_EMERGENCY_MAX_PROPOSALS`].
    pub(crate) max_proposals: u8,
    /// From [`BOOKING_EMERGENCY_MIN_PROPOSALS`].
    pub(crate) min_proposals: u8,
    /// From [`BOOKING_EMERGENCY_SEARCH_SPAN`].
    pub(crate) search_span_secs: u64,
}

/// The vault's emergency proposal policy in `txn`.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn emergency_proposal_policy_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<EmergencyProposalPolicy> {
    Ok(EmergencyProposalPolicy {
        max_proposals: BOOKING_EMERGENCY_MAX_PROPOSALS
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
        min_proposals: BOOKING_EMERGENCY_MIN_PROPOSALS
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
        search_span_secs: BOOKING_EMERGENCY_SEARCH_SPAN
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
    })
}

/// [`emergency_proposal_policy_in_txn`] in a read transaction of its own.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn emergency_proposal_policy(vault: &crate::Vault) -> Result<EmergencyProposalPolicy> {
    let rtxn = vault.store.env.read_txn()?;
    emergency_proposal_policy_in_txn(vault, &rtxn)
}

/// Refuses a change to the count or the floor that leaves the floor above the count. The changed
/// row is already in `txn`, so the pair read here is the one the write would commit.
fn refuse_floor_above_count(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    let policy = emergency_proposal_policy_in_txn(vault, txn)?;
    if policy.min_proposals > policy.max_proposals {
        return Err(Error::InvalidConfig(format!(
            "booking.emergency.min_proposals ({}) must not exceed \
             booking.emergency.max_proposals ({})",
            policy.min_proposals, policy.max_proposals
        )));
    }
    Ok(())
}
