//! Typed doors over launch spend leases, budget holds and the local runner counter.
//! Owner controls take the same proof as the owner routes. `self.budget`
//! reads only the attempt whose stored dispatch actor is the caller.

use serde::{Deserialize, Serialize};

use super::{AgentDispatcher, PartialResultHold, SpendRead, SpendScope, SpendScopeId};
use crate::attempt_queue::{
    AttemptCancelReceipt, AttemptId, AttemptLanding, AttemptLandingReserve, AttemptQueue,
    AttemptResumePoint, LandingTrigger,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::DreamerRunnerStore;
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunRungSettlement {
    pub instance: String,
    pub lease: String,
    pub revision: u32,
    pub model: Option<String>,
    pub offer: String,
    pub route: String,
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
        .map(|row| LocalRunnerBudgetCounter {
            total_units: row.total_units,
            remaining_units: row.remaining_units,
            reserved_units: row.reserved_units,
            updated_at: row.updated_at,
        });
    Ok(LocalRunnerBudgetView {
        budget_id: input.budget_id.clone(),
        counter,
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
