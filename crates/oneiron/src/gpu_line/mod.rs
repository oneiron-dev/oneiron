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
pub(crate) mod claim;
mod fold;
mod intent;
pub(crate) mod tables;

pub use claim::{
    AllocationSettle, AllocationStanding, ClaimAdmissionRefused, ClaimHold, ClaimHoldRefused,
    ClaimKey, ClaimState, UnattributedJob, UnitClaim, UnitEnd, UnitEndReport, UnitPurpose,
    UnitSettleRefused, UnitSettlement, UnitTerminal, allocation_standing_in_txn, claim_hold_in_txn,
    claim_in_txn, claims_at_rung_in_txn, open_claim_in_txn, record_node_answer_in_txn,
    settle_unit_in_txn,
};
pub(crate) use intent::erase_intent_asker_in_txn;
pub use intent::{DIFFERENT_ASK, IntentAsk, IntentRefused, IntentStand, LaneIntent};

pub use fold::{
    AllowanceHold, AllowanceRule, AllowanceTable, Bucket, BudgetDenied, Draw, DrawAsk, DrawPurpose,
    DrawSource, FamilyFloor, FamilyPayoff, FamilySeat, GpuLine, GpuLinePeriod, InvalidCost,
    PayoffSeed, PeriodRoom, PinnedMode, RuleRef, SpendRow, Track, UnitCharge, draw_order,
    plan_draws,
};
