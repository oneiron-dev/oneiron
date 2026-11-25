//! The lane economy's shared shapes and its pure fold (design pass 32,
//! sections 3 and 4).
//!
//! A GPU line is the owner's policy for one lane project: a wallet of
//! `gpu_seconds` per period, a pinned share for one track, a floor per seated
//! family, rung caps and the allowance rules in force. Each period gets one
//! record, written once: its pools and the market ceilings each rule gave,
//! under the budget policy it copied whole.
//!
//! No balance is stored. A pool's room is a fold over the period's spend
//! rows: the first-allowance holds of admitted arms and the draws of
//! reserved units, each unit charged as its job stands (live, settled or
//! void). [`plan_draws`] walks the line's draw order (section 4.2) over that
//! room. Everything here is pure and integer, so a replay gives the same
//! answer.

mod draw;
mod room;
mod types;

pub use draw::{BudgetDenied, DrawAsk, DrawPurpose, draw_order, plan_draws};
pub use room::{AllowanceHold, Bucket, Draw, DrawSource, PeriodRoom, SpendRow, UnitCharge};
pub use types::{
    AllowanceRule, AllowanceTable, BudgetPolicy, DrawStep, FamilyFloor, FamilyPayoff, FamilySeat,
    GpuLine, GpuLinePeriod, Graduation, InvalidCost, LineRole, PeriodAllocation, PeriodClockError,
    PinnedMode, RuleRef, SeatAtMint, Side, Track, TrackDrawOrder,
};
