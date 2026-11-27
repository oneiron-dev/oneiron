//! Every default and bound of a GPU line's settings, in one place (design
//! pass 32 section 3.1; pass 34 section 3.1; Engine ruling EM-21). The
//! engine ships only neutral defaults: nothing pinned, no floor, no new-idea
//! slot, no reserve, and the owner seats every family. A lane's numbers (the
//! open-models lane's 96 GPU-hours a fortnight, its pinned third, its floors
//! and rung caps) come in a preset document the lane's kit passes to
//! `vault.gpu.lines.set`.
//!
//! The period length, the allowance and the rung caps have no engine
//! default: a line that leaves them out is refused.
use std::ops::RangeInclusive;

use super::fold::{DrawStep, RuleRef, Track, TrackDrawOrder};

/// The track the pinned share pays for; unused while nothing is pinned.
pub const PINNED_TRACK: Track = Track::Interest;
/// Nothing pinned.
pub const PINNED_PARTS: (u32, u32) = (0, 1);
pub const FLOOR_ARMS: u32 = 0;
/// The owner seats every demand family (LE-7's option B).
pub const SEAT_CAP: u32 = 0;
/// The owner seats every family on the pinned track ("interest seats stay
/// owner-only").
pub const PINNED_SEAT_CAP: u32 = 0;
pub const SEAT_RESERVE_FLOORS: u32 = 0;
pub const NEW_IDEA_SLOTS_PER_PERIOD: u32 = 0;
/// A new idea is funded in the period it was seated and the next one.
pub const NEW_IDEA_PERIODS: u32 = 2;
/// A reviewer books nothing unless the line says so.
pub const REVIEW_CHECK_SECS: u64 = 0;
/// 72 hours.
pub const HOLD_TTL_SECS: u64 = 259_200;
/// Ten minutes from reservation to start (the lead, 25 Nov 00:04).
pub const CLAIM_CUSTODY_SECS: u64 = 600;
/// No running cap per family.
pub const MAX_RUNNING_PER_FAMILY: u32 = 0;
pub const FORECAST_REQUIRED: bool = false;
/// Forecasts are scored once this many arms have one.
pub const FORECAST_SCORE_AFTER: u32 = 20;
pub const RULES: [RuleRef; 1] = [RuleRef::PAYOFF_SHARE_1];
pub const WINDOW_PERIODS: u32 = 1;
/// posterior_sampling@1 divides its pool into at most this many slots.
pub const POSTERIOR_MAX_SLOTS: u32 = 4_096;
/// posterior_sampling@1 scales a family's wins and losses down together when they sum past this.
pub const POSTERIOR_MAX_EVIDENCE: u32 = 1_023;

/// The draw order of pass 32 section 4.2: what the three tracks mean, not a
/// lane's number. Demand: the hold, the floor, the market. Interest: the
/// hold, the floor, the pinned pool, the market. A new idea: the hold and its
/// slot, at rung 1 only (LE-6).
#[must_use]
pub fn draw_orders() -> Vec<TrackDrawOrder> {
    use DrawStep::{FirstAllowance, Floor, Market, Pinned};
    vec![
        TrackDrawOrder {
            track: Track::Demand,
            first_rung: vec![FirstAllowance, Floor, Market],
            later_rungs: vec![Market],
        },
        TrackDrawOrder {
            track: Track::Interest,
            first_rung: vec![FirstAllowance, Floor, Pinned, Market],
            later_rungs: vec![Pinned, Market],
        },
        TrackDrawOrder {
            track: Track::NewIdea,
            first_rung: vec![FirstAllowance, Floor],
            later_rungs: Vec::new(),
        },
    ]
}

/// The bounds `vault.gpu.lines.set` checks. Inside them no step of the mint
/// overflows a `u128` and no positive weight truncates to zero.
pub const PERIOD_SECS_BOUNDS: RangeInclusive<u64> = 3_600..=31_536_000;
pub const ALLOWANCE_UNITS_BOUNDS: RangeInclusive<u64> = 1..=(1 << 40);
/// The pinned share's denominator: `0 <= numerator < denominator <= this`.
pub const MAX_PINNED_DENOMINATOR: u32 = 1_000;
pub const RUNG_COUNT_BOUNDS: RangeInclusive<usize> = 1..=8;
pub const MAX_FLOOR_ARMS: u32 = 64;
pub const MAX_NEW_IDEA_SLOTS_PER_PERIOD: u32 = 64;
pub const NEW_IDEA_PERIODS_BOUNDS: RangeInclusive<u32> = 1..=26;
/// The starter and one rival for the comparison.
pub const RULE_COUNT_BOUNDS: RangeInclusive<usize> = 1..=2;
pub const WINDOW_PERIODS_BOUNDS: RangeInclusive<u32> = 1..=26;
pub const POSTERIOR_MAX_SLOTS_BOUNDS: RangeInclusive<u32> = 1..=4_096;
pub const POSTERIOR_MAX_EVIDENCE_BOUNDS: RangeInclusive<u32> = 1..=1_023;
