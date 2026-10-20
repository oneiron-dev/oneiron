//! Owner reads of recipe receipts and their Dreamer/Coach descendants.
//! Completion of a recipe receipt alone never claims its children settled.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::store::{PARKED, RUN_TREE};
use super::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_RECIPE_WAKE_ATTEMPT_KIND,
    decode_dreamer_attempt_payload,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_wake::nightly::{CONTINUE_ATTEMPT, PLAN_ATTEMPT};
use crate::dreamer_wake::{NightStepRequestId, WakePolicyTrigger, WakeRecipeInputView};
use crate::memory::DreamerParkCauseView;
use crate::{EntityId, Error, Result, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeSettlementsRequest {
    pub after: Option<EntityId>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeSettlementRequest {
    pub wake: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeSettlementsPage {
    pub wakes: Vec<WakeSettlementView>,
    /// Resume after this wake when more receipts remain.
    pub next: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeSettlementView {
    pub wake: EntityId,
    pub input: Option<WakeRecipeInputView>,
    /// Every descendant is terminal, not merely the recipe dispatcher.
    pub settled: bool,
    pub jobs: Vec<WakeRecipeJobView>,
    /// The night step a Timer `host.wake` asked for, when this root is its
    /// `dreamer.timer.plan`: the run id every job it queued carries.
    pub request_id: Option<NightStepRequestId>,
    /// What the jobs came to, read with them. `settled` alone never means
    /// success.
    pub outcome: WakeOutcomeView,
}

/// What a root's jobs came to, reduced in the read that lists them. Each
/// list names jobs of `jobs` by `attempt`; a try a retry superseded is in
/// none of them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeOutcomeView {
    pub state: WakeOutcomeState,
    /// Queued, leased, landing or scheduled: work not yet done.
    pub waiting_on: Vec<EntityId>,
    /// Parked, or paused by an operator.
    pub parked: Vec<WakeParkedJob>,
    /// Failed, and no retry took its place.
    pub failed: Vec<EntityId>,
    /// Cancelled or abandoned.
    pub stopped: Vec<EntityId>,
    /// The nightly remainder, left for a later interval and not waited for.
    pub deferred: Vec<WakeDeferredJob>,
    /// The completed jobs' result references, once each, in job order.
    pub result_refs: Vec<String>,
    /// The completed jobs' conclusions, once each, in job order.
    pub conclusions: Vec<EntityId>,
}

/// `running` while any job still waits; then `failed` for any failure no
/// retry recovered; then `partial` for any parked, paused, stopped or
/// deferred job; else `succeeded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WakeOutcomeState {
    Running,
    Succeeded,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeParkedJob {
    pub attempt: EntityId,
    /// `None` for an operator's pause, which writes no park row.
    pub cause: Option<DreamerParkCauseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeDeferredJob {
    pub attempt: EntityId,
    /// When it is due, in Unix seconds: its retry's scheduled instant, else
    /// the due its payload names.
    pub due: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeRecipeJobView {
    pub attempt: EntityId,
    pub parent: Option<EntityId>,
    /// The try this job retries, when a retry minted it.
    pub retry_of: Option<EntityId>,
    pub kind: String,
    pub state: AttemptState,
    pub created_at: u64,
    pub updated_at: u64,
    /// The actual Dreamer, Coach or resident principal, never inferred from a name.
    pub actor: Option<EntityId>,
    pub facet: Option<String>,
    pub authority_receipt: Option<[u8; 16]>,
    pub park_cause: Option<DreamerParkCauseView>,
    pub parked_at: Option<u64>,
    pub result_ref: Option<String>,
    /// Exact claim identities retained by the promotion/merge output ledgers.
    pub conclusions: Vec<EntityId>,
}

fn entity(id: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*id.as_bytes()).map_err(Error::from)
}

/// The request a Timer `host.wake`'s plan root carries as its run (FIX 6903).
fn night_step_request(record: &AttemptRecord) -> Option<NightStepRequestId> {
    if record.kind != DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != PLAN_ATTEMPT {
        return None;
    }
    record
        .run_id
        .as_deref()
        .and_then(NightStepRequestId::parse_hex)
}

/// When a pending nightly remainder is due: its retry's scheduled instant,
/// else the due its payload names. `None` for every other job.
fn remainder_due(record: &AttemptRecord) -> Option<Option<u64>> {
    if record.state.is_terminal() || record.kind != DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != CONTINUE_ATTEMPT {
        return None;
    }
    Some(record.scheduled_at.or_else(|| payload.input.as_u64()))
}

/// The one outcome policy of a root's jobs (CALLS row: night-step outcome,
/// FIX 6903). A try another job's `retry_of` names is superseded and
/// counted nowhere. A pending nightly remainder (`remainder`, with its due)
/// that is not leased or landing is deferred: one night step is one
/// budget-bounded snapshot, so the remainder is reported, never waited for.
/// Any other unfinished job is parked when it is paused or holds a park
/// row, else it is waited on. Then: anything waited on is `running`; else
/// any failure is `failed`; else anything parked, cancelled, abandoned or
/// deferred is `partial`; else `succeeded`. The completed jobs' outputs are
/// kept once each, in job order.
fn reduce_outcome(
    jobs: &[WakeRecipeJobView],
    remainder: &BTreeMap<EntityId, Option<u64>>,
) -> WakeOutcomeView {
    let superseded: BTreeSet<EntityId> = jobs.iter().filter_map(|job| job.retry_of).collect();
    let mut outcome = WakeOutcomeView {
        state: WakeOutcomeState::Succeeded,
        waiting_on: Vec::new(),
        parked: Vec::new(),
        failed: Vec::new(),
        stopped: Vec::new(),
        deferred: Vec::new(),
        result_refs: Vec::new(),
        conclusions: Vec::new(),
    };
    for job in jobs.iter().filter(|job| !superseded.contains(&job.attempt)) {
        match job.state {
            AttemptState::Completed => {
                if let Some(reference) = &job.result_ref
                    && !outcome.result_refs.contains(reference)
                {
                    outcome.result_refs.push(reference.clone());
                }
                for conclusion in &job.conclusions {
                    if !outcome.conclusions.contains(conclusion) {
                        outcome.conclusions.push(*conclusion);
                    }
                }
            }
            AttemptState::Failed => outcome.failed.push(job.attempt),
            AttemptState::Cancelled | AttemptState::Abandoned => outcome.stopped.push(job.attempt),
            state => match remainder.get(&job.attempt) {
                Some(due) if !state.is_running() => outcome.deferred.push(WakeDeferredJob {
                    attempt: job.attempt,
                    due: *due,
                }),
                _ if state == AttemptState::Paused || job.park_cause.is_some() => {
                    outcome.parked.push(WakeParkedJob {
                        attempt: job.attempt,
                        cause: job.park_cause,
                    });
                }
                _ => outcome.waiting_on.push(job.attempt),
            },
        }
    }
    outcome.state = if !outcome.waiting_on.is_empty() {
        WakeOutcomeState::Running
    } else if !outcome.failed.is_empty() {
        WakeOutcomeState::Failed
    } else if outcome.parked.is_empty() && outcome.stopped.is_empty() && outcome.deferred.is_empty()
    {
        WakeOutcomeState::Succeeded
    } else {
        WakeOutcomeState::Partial
    };
    outcome
}

fn settlement_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: EntityId,
) -> Result<Option<WakeSettlementView>> {
    let queue = AttemptQueue::new(vault);
    let root = AttemptId::from_bytes(wake.as_bytes())?;
    let Some(record) = queue.get_in_txn(txn, root)? else {
        return Ok(None);
    };
    let tree: BTreeMap<_, _> = RUN_TREE.scan(&vault.store, txn)?.into_iter().collect();
    if !tree.contains_key(&root)
        || tree[&root].parent_attempt.is_some()
        || vault.dreamer_attempt_authority_in_txn(txn, root)?.is_none()
    {
        return Err(Error::InvalidConfig(
            "wake must name a shared-runner root".into(),
        ));
    }
    let input = if record.kind == DREAMER_RECIPE_WAKE_ATTEMPT_KIND {
        let payload = decode_dreamer_attempt_payload(&record.payload)?;
        let trigger: WakePolicyTrigger = serde_json::from_str(
            payload
                .input
                .as_str()
                .ok_or_else(|| Error::InvalidConfig("invalid recipe input".into()))?,
        )
        .map_err(|_| Error::InvalidConfig("invalid recipe input".into()))?;
        Some(WakeRecipeInputView::from(&trigger))
    } else {
        None
    };
    let request_id = night_step_request(&record);
    let mut selected = BTreeSet::from([root]);
    loop {
        let before = selected.len();
        for (id, link) in &tree {
            if link
                .parent_attempt
                .is_some_and(|parent| selected.contains(&parent))
            {
                selected.insert(*id);
            }
        }
        if before == selected.len() {
            break;
        }
    }
    let mut jobs = Vec::new();
    let mut remainder = BTreeMap::new();
    let mut settled = true;
    for id in selected {
        let record = queue
            .get_in_txn(txn, id)?
            .ok_or(Error::CorruptedIndex("recipe child missing"))?;
        let authority = vault.dreamer_attempt_authority_in_txn(txn, id)?;
        let park = PARKED.get(&vault.store, txn, &id)?;
        settled &= record.state.is_terminal();
        if let Some(due) = remainder_due(&record) {
            remainder.insert(entity(id)?, due);
        }
        jobs.push(WakeRecipeJobView {
            attempt: entity(id)?,
            parent: tree
                .get(&id)
                .and_then(|link| link.parent_attempt)
                .map(entity)
                .transpose()?,
            retry_of: record.retry_of.map(entity).transpose()?,
            kind: record.kind,
            state: record.state,
            created_at: record.created_at,
            updated_at: record.updated_at,
            actor: authority.as_ref().map(|stamp| stamp.actor),
            facet: authority.as_ref().map(|stamp| stamp.facet.clone()),
            authority_receipt: authority.map(|stamp| stamp.receipt_id),
            park_cause: park.as_ref().map(|park| park.cause.into()),
            parked_at: park.as_ref().map(|park| park.parked_at),
            result_ref: record.result_ref.map(|reference| reference.into_string()),
            conclusions: crate::dreamer_consolidation::nightly_merge::outputs_in_txn(
                vault, txn, id,
            )?,
        });
    }
    let outcome = reduce_outcome(&jobs, &remainder);
    Ok(Some(WakeSettlementView {
        wake,
        input,
        settled,
        jobs,
        request_id,
        outcome,
    }))
}

pub fn settlement_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &WakeSettlementRequest,
) -> Result<Option<WakeSettlementView>> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_as_vault_owner_in_txn(vault, &txn)?;
    settlement_in_txn(vault, &txn, input.wake)
}

pub fn settlements_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &WakeSettlementsRequest,
) -> Result<WakeSettlementsPage> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_as_vault_owner_in_txn(vault, &txn)?;
    let mut wakes = Vec::new();
    let mut more = false;
    if input.limit == 0 {
        return Err(Error::InvalidConfig(
            "settlement page limit must be positive".into(),
        ));
    }
    for row in RUN_TREE.iter_from(&vault.store, &txn, &[])? {
        let (id, link) = row?;
        if link.parent_attempt.is_some() {
            continue;
        }
        let wake = entity(id)?;
        if input.after.is_some_and(|after| wake <= after) {
            continue;
        }
        if vault.dreamer_attempt_authority_in_txn(&txn, id)?.is_none() {
            continue;
        }
        if wakes.len() >= input.limit as usize {
            more = true;
            break;
        }
        if let Some(view) = settlement_in_txn(vault, &txn, wake)? {
            wakes.push(view);
        }
    }
    let next = if more {
        wakes.last().map(|wake| wake.wake)
    } else {
        None
    };
    Ok(WakeSettlementsPage { wakes, next })
}
