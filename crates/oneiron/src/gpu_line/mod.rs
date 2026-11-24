//! The lane economy's GPU line (design pass 32, FABLE-LANE-ECONOMY): the
//! owner's policy for one lane's GPU time, the record each period's mint
//! writes, and the pure fold over a period's spend that says how much room
//! each bucket has and which buckets cover an ask.
//!
//! Money moves one way: the owner's Grant funds a wallet (a host allocation
//! in `gpu_seconds`, one generation per period), a unit leases a slice of it
//! through one GPU job, and the job settles the seconds its fleet record
//! measured. The economy is the rule about who may take a lease: the pinned
//! share, the floor per family and the market ceilings the mint divides by
//! payoff.
mod doors;
mod doors_caller;
mod fold;
mod mint;
mod store;
pub(crate) mod tables;
mod wire;

pub use doors::{
    GpuLineError, VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET,
};
pub use mint::{
    BUILT_RULES, GPU_SECONDS, LineInvalid, MintError, NO_WIN_PRIOR_RUNGS, PAYOFF_SCORE_SCALE,
    SettledTally, inputs_digest, mint_period, payoff_share,
};
pub(crate) use store::erase_line_actor_in_txn;
pub use store::{
    ARM_TEAM_REF_PREFIX, gpu_seconds, line_allocation_id, line_in_txn, period_in_txn,
    period_view_in_txn, settled_tallies_in_txn, stored_period_in_txn,
};
pub use wire::{
    GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineRef, GpuLineSetRequest, GpuLineView,
};

pub use fold::{
    AllowanceHold, AllowanceRule, AllowanceTable, Bucket, BudgetDenied, Draw, DrawAsk, DrawPurpose,
    DrawSource, FamilyFloor, FamilyPayoff, FamilySeat, GpuLine, GpuLinePeriod, InvalidCost,
    PayoffSeed, PeriodRoom, PinnedMode, RuleRef, SpendRow, Track, UnitCharge, draw_order,
    plan_draws,
};
