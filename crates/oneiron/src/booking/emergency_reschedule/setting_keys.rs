//! The emergency reschedule's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B): how many
//! replacement times one plan offers the counterparty, the fewest live times a plan may offer
//! before it refuses and leaves the booking to the owner, and how far past the affected window it
//! searches for them. Each default is the shipped value (3, 2 and seven days). The owner changes
//! a value; an agent's change waits on the owner's approval.
//!
//! Direction: the count and the search span change which times one apology offers, never
//! whether anyone is contacted or how often, so neither has an order, and a row of either that
//! does not decode reads as the shipped value. The floor is tighter higher: below it the plan
//! refuses, no automated apology goes out, and the owner handles the booking; a floor row that
//! does not decode refuses every plan, whatever the solver finds. The floor never exceeds the
//! count: a change that would put it above refuses, and a pair that arrives so by sync or a
//! restore makes every plan refuse, with words that name the floor above the count. So does a
//! pair two machines set at once, each one side (SETTING-PROJECTED-EMERGENCY-PAIR = A): each
//! machine's pass lands the other's act though the hook refuses it, so the pair reads alike
//! everywhere, and the owner's notice of the refusal leads with "Emergency rescheduling is off"
//! and offers both values in one act. The commit of a plan checks it against the floor in force
//! then, so a floor raised after planning refuses the plan; the count has no order, so a plan made
//! under a larger count still commits.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, RefusedProjection, SettingChange, SettingSource, SettingValue};

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
        refusal_peers: Some(emergency_pair_peer),
        refused_projection: RefusedProjection::Land { conflict: floor_above_count_words },
    };
    /// The fewest live replacement times an emergency reschedule plan may offer (default 2, at
    /// most `booking.emergency.max_proposals`). Higher is tighter: with fewer, the plan refuses,
    /// no automated apology goes out, and the owner handles the booking.
    pub(crate) BOOKING_EMERGENCY_MIN_PROPOSALS: EmergencyProposalCount =
        "booking.emergency.min_proposals" {
        kind: Kind::new(min_proposals)
            .strictest(highest_min_proposals)
            .higher(),
        on_change: Some(refuse_floor_above_count),
        refusal_peers: Some(emergency_pair_peer),
        refused_projection: RefusedProjection::Land { conflict: floor_above_count_words },
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
    /// From [`BOOKING_EMERGENCY_MIN_PROPOSALS`]; `None` when its deciding row does not decode,
    /// and then every plan refuses.
    pub(crate) min_proposals: Option<u8>,
    /// From [`BOOKING_EMERGENCY_SEARCH_SPAN`].
    pub(crate) search_span_secs: u64,
}

impl EmergencyProposalPolicy {
    /// The floor and the count where the floor is above the count: no plan collects enough times.
    fn floor_above_count(&self) -> Option<(u8, u8)> {
        self.min_proposals
            .filter(|floor| *floor > self.max_proposals)
            .map(|floor| (floor, self.max_proposals))
    }

    /// Admits a plan of `count` live replacement times: at least the floor, and at least one.
    ///
    /// # Errors
    ///
    /// The refusal's text when `count` is under the floor, the floor is above the count, or the
    /// floor's row does not decode: no automated apology goes out, and the owner handles the
    /// booking.
    pub(crate) fn admit(&self, count: usize) -> std::result::Result<(), String> {
        let Some(floor) = self.min_proposals else {
            return Err(
                "booking.emergency.min_proposals does not decode, so no emergency plan \
                 goes out until the owner sets it"
                    .to_owned(),
            );
        };
        if let Some((floor, max)) = self.floor_above_count() {
            return Err(format!(
                "emergency rescheduling is off: booking.emergency.min_proposals ({floor}) is \
                 above booking.emergency.max_proposals ({max}), so no emergency plan goes out \
                 until the owner fixes the pair"
            ));
        }
        let floor = floor.max(1);
        if count < usize::from(floor) {
            return Err(format!(
                "this booking has fewer than {floor} live solver proposals"
            ));
        }
        Ok(())
    }
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
    let floor = BOOKING_EMERGENCY_MIN_PROPOSALS.read_in_txn(vault, txn, &[], None)?;
    Ok(EmergencyProposalPolicy {
        max_proposals: BOOKING_EMERGENCY_MAX_PROPOSALS
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
        min_proposals: match floor.source {
            SettingSource::Unreadable(_) => None,
            _ => Some(floor.value.0),
        },
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
/// row is already in `txn`, so the pair read here is the one the write would commit. A floor row
/// that does not decode has no value to compare: every plan refuses until the owner sets it.
fn refuse_floor_above_count(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    if let Some((floor, max)) = emergency_proposal_policy_in_txn(vault, txn)?.floor_above_count() {
        return Err(Error::InvalidConfig(format!(
            "booking.emergency.min_proposals ({floor}) must not exceed \
             booking.emergency.max_proposals ({max})"
        )));
    }
    Ok(())
}

/// The owner's words of a floor above the count in force, which the notice of a refused
/// projection of either leads with (SETTING-PROJECTED-EMERGENCY-PAIR = A); `None` while the floor
/// is at most the count.
fn floor_above_count_words(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    _slot: &oneiron_setting_contract::RowKey,
) -> Result<Option<String>> {
    Ok(emergency_proposal_policy_in_txn(vault, txn)?
        .floor_above_count()
        .map(|(floor, max)| {
            format!("Emergency rescheduling is off: you set min {floor} above max {max}. Fix it?")
        }))
}

/// The row the count's and the floor's hook judges one of them against: the row that decides the
/// other of the pair, its pin where a pin decides it, so the owner's notice of a refused
/// projection of either names both acts, on every machine, and its tap edits the row the hook
/// reads (row SETTING-PROJECTED-ROW-REFUSING-HOOKS).
fn emergency_pair_peer(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    slot: &oneiron_setting_contract::RowKey,
    _value: Option<&serde_json::Value>,
) -> Result<Vec<oneiron_setting_contract::RowKey>> {
    let other = if slot.name == BOOKING_EMERGENCY_MAX_PROPOSALS.spec.name {
        &BOOKING_EMERGENCY_MIN_PROPOSALS
    } else {
        &BOOKING_EMERGENCY_MAX_PROPOSALS
    };
    Ok(vec![other.deciding_slot_in_txn(vault, txn, None)?])
}
