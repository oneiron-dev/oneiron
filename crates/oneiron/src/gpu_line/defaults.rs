//! Every default and bound of a GPU line's settings, in one place (design
//! pass 32 section 3.1; lead 25 Nov 00:04, policy as settings). The engine
//! holds no lane number anywhere else: a line names the values it changes and
//! takes these for the rest.
//!
//! The defaults are today's recommended values for the lane: 14-day periods
//! of 96 GPU-hours, a pinned third for the interest track, two rung-1
//! allowances a floor, rung caps of 30 minutes, 3 hours and 48 hours.
use std::ops::RangeInclusive;

use super::fold::{DrawStep, RuleRef, Track, TrackDrawOrder};

/// 14 days.
pub const PERIOD_SECS: u64 = 1_209_600;
/// 96 GPU-hours a period.
pub const ALLOWANCE_UNITS: u64 = 345_600;
pub const PINNED_TRACK: Track = Track::Interest;
/// One third.
pub const PINNED_PARTS: (u32, u32) = (1, 3);
pub const FLOOR_ARMS: u32 = 2;
pub const RUNG_CAPS_SECS: [u64; 3] = [1_800, 10_800, 172_800];
/// LE-7.
pub const SEAT_CAP: u32 = 6;
pub const SEAT_RESERVE_FLOORS: u32 = 1;
/// LE-6.
pub const NEW_IDEA_SLOTS_PER_PERIOD: u32 = 4;
/// LE-8.
pub const REVIEW_CHECK_SECS: u64 = 600;
/// 72 hours.
pub const HOLD_TTL_SECS: u64 = 259_200;
pub const FORECAST_REQUIRED: bool = true;
pub const RULES: [RuleRef; 1] = [RuleRef::PAYOFF_SHARE_1];
pub const WINDOW_PERIODS: u32 = 3;

/// The draw order of section 4.2. Demand: the hold, the floor, the market.
/// Interest: the hold, the floor, the pinned pool, the market. A new idea:
/// the hold and its slot, at rung 1 only (LE-6).
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
/// The starter and one rival for the comparison.
pub const RULE_COUNT_BOUNDS: RangeInclusive<usize> = 1..=2;
pub const WINDOW_PERIODS_BOUNDS: RangeInclusive<u32> = 1..=26;
