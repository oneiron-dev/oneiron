//! Typed doors over launch spend leases, budget holds and the local runner
//! counter with its reservations.
//! Owner controls take the same proof as the owner routes. `self.budget`
//! reads only the attempt whose stored dispatch actor is the caller.

use serde::{Deserialize, Serialize};

use super::{AgentDispatcher, PartialResultHold, SpendRead, SpendScope, SpendScopeId};
use crate::attempt_queue::{
    AttemptCancelReceipt, AttemptId, AttemptLanding, AttemptLandingReserve, AttemptQueue,
    AttemptResumePoint, LandingTrigger,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerBudgetRecord, DreamerRunnerStore, owner_read_page_limit};
use crate::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault};

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
}

/// One persisted lease and its effective allowance, including its hard ancestor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpendLeaseView {
    pub lease: SpendScope,
    pub spend: SpendRead,
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

/// Durable budget facts for the same work, without claiming a process-local
/// token guard is a monetary lease. An unmetered attempt has no lease.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentBudgetView {
    pub attempt: String,
    pub lease: Option<SpendLeaseView>,
    pub landing_reserve: AttemptLandingReserve,
    pub ordinary_limit_units: u64,
    pub landing: Option<AttemptLanding>,
    pub budget_notices: Vec<AttemptCancelReceipt>,
    pub checkpoint: Option<AttemptResumePoint>,
    pub hold: Option<PartialResultHold>,
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

pub fn open_spend_lease_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &OpenSpendLeaseRequest,
) -> Result<SpendLeaseView> {
    let scope = SpendScopeId::launch(&input.launch)?;
    let maximum = maximum(input.cap_units, &input.unit)?;
    let dispatcher = AgentDispatcher::new(vault);
    let mut txn = vault.store.env.write_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    dispatcher.open_root_spend_scope_in_txn(
        &mut txn,
        scope.clone(),
        maximum,
        Some(MaximumShown {
            at_ms: input.shown_at_ms,
        }),
        crate::unix_seconds_now(),
    )?;
    txn.commit()?;
    lease_view(&dispatcher, &scope)
}

pub fn spend_lease_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SpendScopeRequest,
) -> Result<SpendLeaseView> {
    owner.revalidate(vault)?;
    lease_view(&AgentDispatcher::new(vault), &scope_id(&input.scope)?)
}

pub fn top_up_spend_lease_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &TopUpSpendLeaseRequest,
) -> Result<SpendLeaseView> {
    let scope = scope_id(&input.scope)?;
    let dispatcher = AgentDispatcher::new(vault);
    dispatcher.top_up_spend_scope_as_owner(
        owner,
        &scope,
        input.expected_cap_units,
        maximum(input.cap_units, &input.unit)?,
        MaximumShown {
            at_ms: input.shown_at_ms,
        },
    )?;
    lease_view(&dispatcher, &scope)
}

pub fn budget_hold_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &BudgetHoldRequest,
) -> Result<Option<PartialResultHold>> {
    owner.revalidate(vault)?;
    AgentDispatcher::new(vault).refresh_budget_hold(attempt_id(&input.run)?)
}

pub fn resume_budget_hold_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &BudgetHoldRequest,
) -> Result<PartialResultHold> {
    let actor = owner.revalidate_principal_ref(vault)?;
    let root = attempt_id(&input.run)?;
    let dispatcher = AgentDispatcher::new(vault);
    let hold = dispatcher
        .refresh_budget_hold(root)?
        .ok_or_else(|| invalid("run has no budget hold"))?;
    if !hold.resume_ready {
        return Err(invalid(
            "top up the held run's binding lease before resuming",
        ));
    }
    dispatcher.resume_budget_hold(root, actor, crate::unix_seconds_now())
}

pub fn local_runner_budget_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &LocalRunnerBudgetRequest,
) -> Result<LocalRunnerBudgetView> {
    owner.revalidate(vault)?;
    let counter = DreamerRunnerStore::new(vault)
        .budget(&input.budget_id)?
        .as_ref()
        .map(runner_counter)
        .transpose()?;
    Ok(LocalRunnerBudgetView {
        budget_id: input.budget_id.clone(),
        counter,
    })
}

/// Reads, in one snapshot, a device-local runner counter and one page of the
/// child reservations held against it, in job-ref order. A read never
/// creates, initializes or refills the counter.
pub fn runner_budget_reservations_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &RunnerBudgetReservationsRequest,
) -> Result<RunnerBudgetReservationsView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let limit =
        owner_read_page_limit(input.limit).ok_or_else(|| invalid("limit must be positive"))?;
    let after = input
        .after
        .as_deref()
        .map(|after| {
            attempt_id(after.trim())
                .map_err(|_| invalid("after must be the job ref a previous page named as next"))
        })
        .transpose()?;
    let store = DreamerRunnerStore::new(vault);
    let counter = store.budget_in_txn(&txn, &input.budget_id)?;
    if counter
        .as_ref()
        .is_some_and(|row| row.budget_id != input.budget_id)
    {
        return Err(crate::Error::InvariantViolation(
            "runner budget row names another budget",
        ));
    }
    let mut rows =
        store.budget_reservations_in_txn(&txn, &input.budget_id, after, limit.saturating_add(1))?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let reservations: Vec<_> = rows
        .into_iter()
        .map(|row| RunnerBudgetReservation {
            job_ref: crate::entity_id::bytes_to_hex_lower(row.attempt_id.as_bytes()),
            reserved_units: row.reserved_units,
            owed_units: row.owed_units,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
        .collect();
    Ok(RunnerBudgetReservationsView {
        budget_id: input.budget_id.clone(),
        counter: counter.as_ref().map(runner_counter).transpose()?,
        next: reservations
            .last()
            .filter(|_| more)
            .map(|row| row.job_ref.clone()),
        reservations,
        local_only: true,
    })
}

/// The counter as the owner reads it, with what settled as spent, an
/// overdraft among it (FIX 8702). A row whose remaining and reserved units
/// exceed its total refuses: the runner never writes one.
fn runner_counter(row: &DreamerBudgetRecord) -> Result<LocalRunnerBudgetCounter> {
    let spent_units = row.spent_units().ok_or(crate::Error::InvariantViolation(
        "dreamer budget counter is inconsistent",
    ))?;
    Ok(LocalRunnerBudgetCounter {
        total_units: row.total_units,
        remaining_units: row.remaining_units,
        reserved_units: row.reserved_units,
        spent_units,
        overdraft_units: row.overdraft_units,
        owed_calls: row.owed_calls,
        updated_at: row.updated_at,
    })
}

/// The saved dispatch must bind this exact attempt to the credential-backed
/// memory handle's actor. A root is readable only within that same run.
pub fn self_budget(
    memory: &Memory<'_>,
    input: &SelfBudgetRequest,
) -> MemoryResult<AgentBudgetView> {
    let row = own_attempt(memory, &input.attempt)?;
    let root = same_run_root(memory.vault(), &row, input.run.as_deref())?;
    let dispatcher = AgentDispatcher::new(memory.vault());
    let lease = dispatcher
        .spend_scope_for_attempt(row.id)?
        .map(|scope| lease_view(&dispatcher, &scope))
        .transpose()?;
    Ok(AgentBudgetView {
        attempt: crate::entity_id::bytes_to_hex_lower(row.id.as_bytes()),
        lease,
        landing_reserve: row.landing_reserve(),
        ordinary_limit_units: row.ordinary_budget_limit_units(),
        landing: row.landing().cloned(),
        budget_notices: row
            .cancel_receipts()
            .iter()
            .filter(|receipt| receipt.trigger == Some(LandingTrigger::BudgetWarning))
            .cloned()
            .collect(),
        checkpoint: row.resume_point().cloned(),
        hold: dispatcher.plan_hold(root)?,
    })
}

/// A worker parks only its own dispatched attempt, through the existing
/// lease-fenced hold door. It supplies its checkpoint, never a terminal result.
pub fn land_for_budget(
    memory: &Memory<'_>,
    input: &BudgetLandRequest,
) -> MemoryResult<PartialResultHold> {
    {
        let txn = memory
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        memory.verify_actor_write_in_txn(&txn)?;
    }
    let row = own_attempt(memory, &input.attempt)?;
    let root = same_run_root(memory.vault(), &row, Some(&input.run))?;
    let now = crate::unix_seconds_now();
    let dispatcher = AgentDispatcher::new(memory.vault());
    let hold = dispatcher.hold_for_budget(
        root,
        super::BudgetHoldLease {
            attempt: row.id,
            lease_owner: input.lease_owner.clone(),
            attempt_count: input.attempt_count,
            resume_point: AttemptResumePoint {
                marker: input.marker.clone(),
                artifact_ref: input.artifact_ref.clone(),
                recorded_at: now,
            },
        },
        None,
        &input.reason,
        now,
    )?;
    if dispatcher.deliver_budget_notice(root)?.is_some() {
        dispatcher
            .acknowledge_budget_notice(root, now)
            .map_err(MemoryError::from)
    } else {
        Ok(hold)
    }
}

fn own_attempt(
    memory: &Memory<'_>,
    attempt: &str,
) -> MemoryResult<crate::attempt_queue::AttemptRecord> {
    let vault = memory.vault();
    memory.read_key()?;
    let row = AttemptQueue::new(vault)
        .get(attempt_id(attempt)?)?
        .ok_or_else(|| MemoryError::bad_request("budget attempt is missing"))?;
    let actor = super::codec::record_dispatch_input(&row)
        .and_then(|input| super::agent_dispatch_actor(&input).ok());
    if actor != Some(crate::WriteActor::new(memory.actor(), memory.actor_class())) {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a self budget door acts only on the caller's own dispatched attempt",
            &["Name an attempt dispatched as this credential's actor."],
        ));
    }
    Ok(row)
}

fn same_run_root(
    vault: &Vault,
    row: &crate::attempt_queue::AttemptRecord,
    run: Option<&str>,
) -> MemoryResult<AttemptId> {
    let Some(run) = run else {
        return Ok(row.id);
    };
    let root = attempt_id(run)?;
    if root != row.id {
        let root_row = AttemptQueue::new(vault)
            .get(root)?
            .ok_or_else(|| MemoryError::bad_request("budget root is missing"))?;
        if row.run_id.is_none() || row.run_id != root_row.run_id {
            return Err(MemoryError::bad_request(
                "budget root belongs to another run",
            ));
        }
    }
    Ok(root)
}

fn lease_view(dispatcher: &AgentDispatcher<'_>, scope: &SpendScopeId) -> Result<SpendLeaseView> {
    let lease = dispatcher
        .read_spend_scope(scope)?
        .ok_or_else(|| invalid("spend scope is missing"))?;
    Ok(SpendLeaseView {
        lease,
        spend: dispatcher.spend_read(scope)?,
    })
}

fn maximum(units: u64, unit: &str) -> Result<DeclaredMaximum> {
    let unit = LeaseUnit::new(unit).map_err(|_| invalid("invalid lease unit"))?;
    Ok(DeclaredMaximum { units, unit })
}

fn scope_id(value: &str) -> Result<SpendScopeId> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(SpendScopeId::for_attempt(&attempt_id(value)?));
    }
    SpendScopeId::launch(value)
}

fn attempt_id(value: &str) -> Result<AttemptId> {
    let entity = EntityId::from_hex(value)?;
    AttemptId::from_bytes(entity.as_bytes())
}

fn invalid(reason: &str) -> crate::Error {
    crate::Error::InvalidConfig(reason.to_owned())
}
