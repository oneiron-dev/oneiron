//! Moved from `crates/oneiron/src/agent_dispatch/budget_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A launch scope, or an attempt's scope id, as returned by a budget read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendScopeRequest {
    pub scope: String,
}

/// The maximum the customer set and saw when opening a launch lease.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenSpendLeaseRequest {
    pub launch: String,
    pub cap_units: u64,
    /// The engine's named lease unit; a monetary line names its money unit.
    pub unit: String,
    pub shown_at_ms: u64,
    /// An owner's agent grant (32 hex) whose wallet funds this lease's whole
    /// tree (FIX 7766): a live Access grant that names a wallet, stands for
    /// its agent now and matches its counted signed mint. Frozen on the
    /// lease; every host-paid call under it draws on that wallet's
    /// allocation or is refused. Omitted: the lease draws on the host's live
    /// allocation, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_grant_ref: Option<EntityId>,
}

/// A replacement maximum, not an increment: replay cannot add funds twice.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopUpSpendLeaseRequest {
    pub scope: String,
    pub expected_cap_units: u64,
    pub cap_units: u64,
    pub unit: String,
    pub shown_at_ms: u64,
    /// Another asker's approved check-in for exactly this raise, 32 hex:
    /// the owner applies it on their own proof, and the top-up's writer
    /// spends it (2k10). Omitted: the owner's own top-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

/// A held run's root attempt, in lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetHoldRequest {
    pub run: String,
}

/// An agent's own dispatched attempt, in lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfBudgetRequest {
    pub attempt: String,
    /// Root of the same run; the attempt itself when absent.
    #[serde(default)]
    pub run: Option<String>,
}

/// The worker's own lease fence and checkpoint for a resumable budget hold.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetLandRequest {
    pub attempt: String,
    pub run: String,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub marker: String,
    #[serde(default)]
    pub artifact_ref: Option<String>,
    pub reason: String,
}

/// The device-local runner counter to observe before and after owner restore.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalRunnerBudgetRequest {
    pub budget_id: String,
}

/// `counter: None` means this device has not initialized this counter. A
/// read never creates one, which makes restore-reset observation meaningful.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LocalRunnerBudgetView {
    pub budget_id: String,
    pub counter: Option<LocalRunnerBudgetCounter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LocalRunnerBudgetCounter {
    pub total_units: u64,
    pub remaining_units: u64,
    pub reserved_units: u64,
    /// `total_units - remaining_units - reserved_units`, plus spend settled
    /// beyond the total: what settled.
    pub spent_units: u64,
    /// Spend settled beyond what was left: incurred, never refused.
    /// Nonzero only while `remaining_units` is 0.
    pub overdraft_units: u64,
    /// Admitted calls whose terminal usage is still owed to this line:
    /// each is charged when it settles.
    pub owed_calls: u64,
    pub updated_at: u64,
}

/// One page of a device-local runner counter's live reservations.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerBudgetReservationsRequest {
    pub budget_id: String,
    /// The previous page's `next`; this page starts after that job ref.
    #[serde(default)]
    pub after: Option<String>,
    /// Reservations in this page: `vault.runs.checkpoint`'s default when
    /// absent, at most its ceiling. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The counter and one page of the reservations held against it, read in
/// one snapshot. `counter: None` means this device has not initialized the
/// counter; a read never creates one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerBudgetReservationsView {
    pub budget_id: String,
    pub counter: Option<LocalRunnerBudgetCounter>,
    /// In job-ref order.
    pub reservations: Vec<RunnerBudgetReservation>,
    /// The `after` of the next page; none past the last reservation.
    pub next: Option<String>,
    /// Always true: the counter is this device's private runner row, not a
    /// replicated vault budget (ARCH-0026), and its reservations are this
    /// device's runner's own.
    pub local_only: bool,
}

/// Units one child attempt holds against the counter until it settles.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerBudgetReservation {
    /// 32-hex id of the reserving child attempt.
    pub job_ref: String,
    pub reserved_units: u64,
    /// Measured spend this child owes that no settlement has charged yet;
    /// its settlement or abort charges it.
    pub owed_units: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Persisted settlements of the physical rungs a served run sent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSettlementsRequest {
    pub run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunSettlementsView {
    pub run: String,
    /// False when this host has not bound its usage ledger to an account.
    pub metering_enabled: bool,
    pub settlements: Vec<RunRungSettlement>,
}

/// Which path wrote a settled call's usage record (FIX 5724). Neither
/// changes whether or how the call counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageEventOrigin {
    /// The serving engine recorded the call it admitted and settled.
    Engine,
    /// An accepted usage post recorded it, with the poster's own stamps.
    Posted,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunRungSettlement {
    pub instance: String,
    pub lease: String,
    /// The run the call was admitted on.
    pub run: String,
    pub revision: u32,
    pub model: Option<String>,
    pub offer: String,
    pub route: String,
    /// The label the call carried (FIX 4453): its envelope purpose, or a
    /// paid connector call's bound item's.
    pub purpose: Option<String>,
    /// The path that first wrote the call's record: `engine` or `posted`.
    /// A replay never relabels it.
    pub source: UsageEventOrigin,
    /// The agent, free-time cycle, item and spend scope a bound run's call
    /// served (FIX 4453): on an `engine` record as the engine stamped them
    /// before the run began, on a `posted` one as the poster stamped them;
    /// `None` on every unbound run.
    pub agent: Option<String>,
    pub cycle: Option<String>,
    pub item: Option<String>,
    pub spend_scope: Option<String>,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub unit: String,
    pub usage_reported: bool,
    pub settlement_refused: bool,
    pub occurred_at: u64,
    /// Stamped provider-list cost, never a price reconstructed at read time.
    /// Money amounts use 10^-9 units of `currency`; absent is unpriced.
    pub cost_amount: Option<u64>,
    pub currency: Option<String>,
    pub price_table_snapshot: Option<String>,
}
