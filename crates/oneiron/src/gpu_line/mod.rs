//! The lane economy's GPU line (design pass 32, FABLE-LANE-ECONOMY): the
//! owner's policy for one lane's GPU time, the record each period's mint
//! writes, and the pure fold over a period's spend that says how much room
//! each bucket has and which buckets cover an ask.
//!
//! Money moves one way: the owner's Grant funds a wallet (a host allocation
//! in `gpu_seconds`, one generation per period), a unit leases a slice of it
//! through one GPU job, and the job settles the seconds the machine
//! measured. The economy is the rule about who may take a lease: the pinned
//! share, the floor per seat, the new-idea slots and the market ceilings the
//! mint divides by payoff. Every number of it is a setting of the line
//! ([`defaults`]).
pub(crate) mod claim;
mod cohort;
pub mod defaults;
mod doors;
pub(crate) mod doors_caller;
mod fold;
mod graduate;
mod intent;
mod mint;
mod preset;
mod refusal;
mod store;
pub(crate) mod tables;
mod tally;
mod wire;

pub use claim::{
    AllocationSettle, AllocationStanding, ClaimAdmissionRefused, ClaimHold, ClaimHoldRefused,
    ClaimKey, ClaimState, UnattributedJob, UnattributedRecord, UnitClaim, UnitEnd, UnitEndReport,
    UnitPurpose, UnitSettleRefused, UnitSettlement, UnitTerminal, allocation_standing_in_txn,
    claim_hold_in_txn, claim_in_txn, claims_at_rung_in_txn, claims_in_txn, custody_lapsed_in_txn,
    open_claim_in_txn, record_node_answer_in_txn, settle_unit_in_txn, unattributed_in_txn,
};
pub use cohort::{COHORT_BLOCK_ARMS, cohort_rule, cohort_seed_commit};
pub use doors::{
    GpuLineError, VAULT_GPU_LINES_FAMILIES_ADMIT, VAULT_GPU_LINES_GET, VAULT_GPU_LINES_SET,
};
pub use graduate::{GpuLineFamilyGraduateRequest, VAULT_GPU_LINES_FAMILIES_GRADUATE};
pub(crate) use intent::erase_intent_asker_in_txn;
pub(crate) use intent::intent_row_asker;
pub use intent::{DIFFERENT_ASK, IntentAsk, IntentRefused, IntentStand, LaneIntent};
pub use mint::{
    BUILT_RULES, GPU_SECONDS, LineInvalid, MintError, PAYOFF_WEIGHT_SHIFT, Pools, SettledTally,
    economic_digest, even_split, line_allocation_id, mint_period, payoff_share, period_balances,
    pools, posterior_sampling,
};
pub use preset::{LinePresetDocument, LinePresetRef, check_document, lay_over, resolve_policy};
pub use refusal::{LineRefusal, LineRefusalKey, line_refusals_in_txn};
pub(crate) use refusal::{erase_refusal_actor_in_txn, record_line_refusal_in_txn};
pub(crate) use store::erase_line_actor_in_txn;
pub(crate) use store::period_row_seals_seed;
pub use store::{
    MintedLine, gpu_seconds, line_in_txn, mint_first_in_txn, offer_line_managed_in_txn,
    period_view_in_txn, stored_period_in_txn,
};
pub use tally::settled_tallies_in_txn;
pub use wire::{
    GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLinePolicyFields, GpuLineRef, GpuLineSetRequest,
    GpuLineSetWire, GpuLineView,
};

pub use fold::{
    AllowanceHold, AllowanceRule, AllowanceTable, Bucket, BudgetDenied, BudgetPolicy, Draw,
    DrawAsk, DrawPurpose, DrawSource, DrawStep, FamilyFloor, FamilyPayoff, FamilySeat, GpuLine,
    GpuLinePeriod, Graduation, InvalidCost, LineRole, PeriodAllocation, PeriodClockError,
    PeriodRoom, PinnedMode, RuleRef, SeatAtMint, Side, SpendRow, Track, TrackDrawOrder, UnitCharge,
    draw_order, plan_draws,
};
