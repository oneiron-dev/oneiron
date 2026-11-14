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

#[doc(hidden)]
pub use oneiron_verb_wire::agent_dispatch::budget_doors::{
    BudgetHoldRequest, BudgetLandRequest, LocalRunnerBudgetCounter, LocalRunnerBudgetRequest,
    LocalRunnerBudgetView, OpenSpendLeaseRequest, RunRungSettlement, RunSettlementsRequest,
    RunSettlementsView, RunnerBudgetReservation, RunnerBudgetReservationsRequest,
    RunnerBudgetReservationsView, SelfBudgetRequest, SpendScopeRequest, TopUpSpendLeaseRequest,
    UsageEventOrigin,
};

/// One persisted lease and its effective allowance, including its hard ancestor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpendLeaseView {
    pub lease: SpendScope,
    pub spend: SpendRead,
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
    let shown = Some(MaximumShown {
        at_ms: input.shown_at_ms,
    });
    match input.funding_grant_ref {
        // FIX 7766: the owner's selected Grant proves itself in this writer,
        // immediately before the root is put.
        Some(grant) => dispatcher.open_root_spend_scope_funded_in_txn(
            &mut txn,
            scope.clone(),
            maximum,
            shown,
            None,
            owner,
            grant,
            crate::unix_seconds_now(),
        )?,
        None => dispatcher.open_root_spend_scope_in_txn(
            &mut txn,
            scope.clone(),
            maximum,
            shown,
            crate::unix_seconds_now(),
        )?,
    };
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

/// `vault.budgets.lease` for a caller other than the owner (slice 6.5a,
/// S65-BUDGET = A): a lease in the scope tree of a run the caller is the
/// actor of, that is its own attempt's scope or one its run reserved below
/// it, at any depth. The view is the owner's: the lease, what it may still
/// spend and the hard ancestor that binds it. Opening and raising a lease
/// stay the owner's acts; reserving and settling stay the engine's
/// accounting.
///
/// One snapshot proves the caller's read authority
/// (`Memory::prove_read_authority_in_txn`: a bound credential that was
/// revoked or has expired reads nothing), places the scope in a run of the
/// caller's own, and reads the lease.
///
/// # Errors
///
/// A malformed scope id; a caller whose bound credential grants it no read
/// or no longer holds, and a scope outside the caller's own runs'
/// (`FORBIDDEN`); a missing scope; storage errors.
pub fn spend_lease_as_reader(
    memory: &Memory<'_>,
    input: &SpendScopeRequest,
) -> MemoryResult<SpendLeaseView> {
    let scope = scope_id(&input.scope)?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.prove_read_authority_in_txn(&txn)?;
    if !in_own_scope_tree_in_txn(memory, &txn, &scope)? {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "vault.budgets.lease reads the owner's leases and those of the caller's own runs",
            &["Call it as the vault's owner, or for a scope your run spends under or reserved."],
        ));
    }
    let lease = super::spend_record::SCOPE
        .get(&vault.store, &txn, &scope.0)?
        .ok_or_else(|| invalid("spend scope is missing"))?;
    let spend = AgentDispatcher::new(vault).spend_read_at_in_txn(&txn, &scope)?;
    Ok(SpendLeaseView { lease, spend })
}

/// `vault.budgets.lease` on an in-process handle: the embedded owner's read,
/// or [`spend_lease_as_reader`] for any other caller.
///
/// # Errors
///
/// As the read it takes.
pub fn spend_lease_embedded(
    memory: &Memory<'_>,
    input: &SpendScopeRequest,
) -> MemoryResult<SpendLeaseView> {
    match memory.embedded_owner("vault.budgets.lease") {
        Ok(owner) => spend_lease_as_owner(memory.vault(), &owner, input).map_err(MemoryError::from),
        Err(_) => spend_lease_as_reader(memory, input),
    }
}

/// `vault.budgets.settlements` for a person or agent on a verified slip of
/// its own: of one served run's settlements `rows`, as the host's usage
/// ledger read them, those whose stamp names the caller as the agent the call
/// served (`RunRungSettlement::agent`: the engine's stamp on an `engine`
/// record, the poster's on a `posted` one). An unbound call names no agent,
/// and no call names a person, so a person reads none. The owner reads every
/// row on its own proof.
///
/// The caller's read authority is proved after the ledger read the rows, so
/// a credential revoked or expired before that proof reads nothing
/// (`Memory::prove_read_authority_in_txn`).
///
/// # Errors
///
/// A caller whose bound credential grants it no read or no longer holds
/// (`FORBIDDEN`); storage errors.
pub fn own_run_settlements_as_reader(
    memory: &Memory<'_>,
    rows: Vec<RunRungSettlement>,
) -> MemoryResult<Vec<RunRungSettlement>> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    memory.prove_read_authority_in_txn(&txn)?;
    let caller = memory.actor().to_hex();
    Ok(rows
        .into_iter()
        .filter(|row| row.agent.as_deref() == Some(caller.as_str()))
        .collect())
}

/// Whether `scope`, or a scope above it in its tree, is the spend scope of an
/// attempt the caller is the actor of, as `txn` reads it. A launch root names
/// no attempt.
fn in_own_scope_tree_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    scope: &SpendScopeId,
) -> MemoryResult<bool> {
    let vault = memory.vault();
    let caller = crate::WriteActor::new(memory.actor(), memory.actor_class());
    let mut seen = std::collections::HashSet::new();
    let mut next = Some(scope.clone());
    while let Some(id) = next {
        // A tree's parents end at its root; a scope met twice is a corrupt row.
        if !seen.insert(id.clone()) {
            return Err(crate::Error::CorruptedIndex("spend scope parent cycle").into());
        }
        if let Ok(attempt) = attempt_id(id.as_str())
            && crate::snapshot_read::is_attempt_actor_in_txn(vault, txn, caller, attempt)?
        {
            return Ok(true);
        }
        next = super::spend_record::SCOPE
            .get(&vault.store, txn, &id.0)?
            .and_then(|row| row.parent);
    }
    Ok(false)
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
        None,
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
