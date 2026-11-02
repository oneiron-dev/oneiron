//! Typed host triggers (ARCH-0080 §5). The served doors supply the caller's
//! owner proof; the ordinary verb boundary owns their pre and post chains.
//! Compaction uses the existing cheap backend and pre-swap gate. A wake uses
//! the host scheduling door. A budget hit reads accounting, never accepts it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_dispatch::{AgentDispatcher, SpendRead, SpendScope, SpendScopeId};
use crate::attempt_queue::AttemptId;
use crate::compaction::{CompactionBackend, CompactionGatePolicy, CompactionWindowMessage};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{BudgetExhaustionPolicy, EntityId, Vault};

use super::{BudgetHit, InvocationId};

/// A conversation's host-rendered message window, with the lines that must
/// survive word for word. The session owns the resulting keyframe.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostCompactRequest {
    pub session_ref: EntityId,
    pub window: Vec<CompactionWindowMessage>,
    pub keep_list: Vec<String>,
    pub token_ceiling: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostCompactResult {
    pub epoch: u64,
    pub summary: EntityId,
    pub text: String,
    pub keep_list: Vec<String>,
    pub first_turn: u64,
    pub last_turn: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostWakeKind {
    Compaction,
    SessionEnd,
    Event,
    Timer,
}

impl HostWakeKind {
    fn trigger(self) -> crate::dreamer_wake::WakeTrigger {
        use crate::dreamer_wake::WakeTrigger;
        match self {
            Self::Compaction => WakeTrigger::Compaction,
            Self::SessionEnd => WakeTrigger::SessionEnd,
            Self::Event => WakeTrigger::Event,
            Self::Timer => WakeTrigger::Timer,
        }
    }
}

/// The trigger is nominal: Timer schedules its maintenance lanes in the
/// same write as consolidation, rather than becoming a generic enqueue.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostWakeRequest {
    pub wake_kind: HostWakeKind,
    /// The host's queue snapshot, carried to the hooks and the queued wake.
    pub queue_head: Vec<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostWakeResult {
    pub wake_kind: HostWakeKind,
    pub queue_head: Vec<EntityId>,
    pub attempt: String,
    pub already_queued: bool,
    /// Timer only: every job the wake queued carries it as its run id, beneath `attempt`.
    pub request_id: Option<crate::dreamer_wake::NightStepRequestId>,
}

/// Names an existing durable spend scope. Its cap's policy is Suspend;
/// neither the policy nor accounting can be changed by this notification.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostBudgetHitRequest {
    pub seat: String,
    pub policy: BudgetExhaustionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostBudgetAccounting {
    pub line: SpendScope,
    pub root: SpendScope,
    pub spend: SpendRead,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostBudgetHitResult {
    pub seat: String,
    pub policy: BudgetExhaustionPolicy,
    pub accounting: HostBudgetAccounting,
}

/// Shared by embedded and served boundaries before any host trigger hook.
/// In particular an unspent line is not a budget-hit event.
pub fn admit_trigger(vault: &Vault, verb: &str, args: &Value) -> MemoryResult<()> {
    if verb == super::HOST_BUDGET_HIT {
        let input: HostBudgetHitRequest = serde_json::from_value(args.clone())
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        budget_accounting_in(vault, &txn, &input)?;
    }
    Ok(())
}

/// Host-owned arguments are immutable, except for add-only compaction pins
/// and add-only wake material (FIX 8722). Every transport uses this check
/// beside its ordinary rewrite admission.
pub fn check_rewrite(verb: &str, before: &Value, after: &Value) -> Result<(), String> {
    match verb {
        "host.compact" => crate::compaction::check_host_compact_rewrite(before, after),
        "host.wake" => crate::dreamer_wake::check_host_wake_rewrite(before, after),
        "host.budget.hit" if before != after => Err("a host verb's args are the host's".to_owned()),
        _ => Ok(()),
    }
}

pub fn compact_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: HostCompactRequest,
    backend: &dyn CompactionBackend,
    policy: &CompactionGatePolicy,
) -> MemoryResult<HostCompactResult> {
    crate::compaction::host_compact_as_owner(memory, owner, input, backend, policy)
}

pub fn wake_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    invocation: InvocationId,
    input: HostWakeRequest,
) -> MemoryResult<HostWakeResult> {
    let vault = memory.vault();
    let mut txn = vault.store.env.write_txn().map_err(crate::Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    memory.verify_actor_write_in_txn(&txn)?;
    let payload = DreamerAttemptPayload {
        attempt_type: input
            .wake_kind
            .trigger()
            .default_scope()
            .as_str()
            .to_owned(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
    };
    let request_id = matches!(input.wake_kind, HostWakeKind::Timer)
        .then(|| crate::dreamer_wake::NightStepRequestId::from_invocation(invocation));
    let outcome = match request_id {
        Some(request_id) => crate::dreamer_wake::request_night_step_in_txn(
            &DreamerRunnerStore::new(vault),
            &mut txn,
            Some(format!("host.wake:{}", invocation.to_hex())),
            request_id,
            vault.now_recorded_at(),
        )?,
        None => crate::dreamer_wake::request_wake_in_txn(
            &DreamerRunnerStore::new(vault),
            &mut txn,
            input.wake_kind.trigger(),
            payload,
            Some(format!("host.wake:{}", invocation.to_hex())),
            None,
            vault.now_recorded_at(),
        )?,
    };
    let (status, already_queued) = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status) => (status, false),
        EnqueueDreamerAttemptOutcome::Existing(status) => (status, true),
    };
    txn.commit().map_err(crate::Error::from)?;
    vault.store.notify_attempt_observers();
    vault.store.notify_proactivity_changes();
    Ok(HostWakeResult {
        wake_kind: input.wake_kind,
        queue_head: input.queue_head,
        attempt: crate::entity_id::bytes_to_hex_lower(status.attempt.id.as_bytes()),
        already_queued,
        request_id,
    })
}

pub fn budget_hit_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    invocation: InvocationId,
    input: HostBudgetHitRequest,
) -> MemoryResult<HostBudgetHitResult> {
    let vault = memory.vault();
    // Re-read under the same snapshot as the live proof. This never opens,
    // tops up, settles, or otherwise changes the original line.
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    let accounting = budget_accounting_in(vault, &txn, &input)?;
    drop(txn);
    vault.budget_hit_hooks(BudgetHit {
        seat: &input.seat,
        policy: input.policy,
        accounting: serde_json::to_value(&accounting)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?,
        actor: memory.actor(),
        invocation,
    });
    Ok(HostBudgetHitResult {
        seat: input.seat,
        policy: input.policy,
        accounting,
    })
}

fn budget_accounting_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &HostBudgetHitRequest,
) -> MemoryResult<HostBudgetAccounting> {
    if input.policy != BudgetExhaustionPolicy::Suspend {
        return Err(MemoryError::bad_request(
            "a durable spend scope's policy is Suspend",
        ));
    }
    let scope = if input.seat.len() == 32 && input.seat.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        let id = EntityId::from_hex(&input.seat)?;
        SpendScopeId::for_attempt(&AttemptId::from_bytes(id.as_bytes())?)
    } else {
        SpendScopeId::launch(&input.seat)?
    };
    let dispatcher = AgentDispatcher::new(vault);
    let (line, root) = dispatcher
        .scope_with_root_in_txn(txn, &scope)?
        .ok_or_else(|| MemoryError::bad_request("budget seat has no spend scope"))?;
    let spend = dispatcher.spend_read_at_in_txn(txn, &scope)?;
    if spend.available_units != 0 {
        return Err(MemoryError::bad_request(
            "the budget seat has not hit its cap",
        ));
    }
    Ok(HostBudgetAccounting { line, root, spend })
}
