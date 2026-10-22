//! Budgeted interest-queue spending, one thing per entity or topic (OF-498c,
//! see `things`): its world, facet and private thread, and the entity a
//! span's reading bound, else the structural topic. A thing may span
//! conversations, and its child in each project reads it across them (FIX
//! 7524, 8724).
//!
//! A Timer wake that names no partition (FIX 336) plans the same spending
//! at its enqueue: a typed parent, its children and the remainder land in
//! the enqueue's own commit, and the parent only completes when it runs.

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::{
    ConsolidationWatermark, enqueue_parented_branch_plans_in_txn, partition_turns_in_txn,
    read_partition_turns_in_txn,
};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{Result, Vault};

use super::{recipes, sieve};

mod exposure;
mod things;

pub(crate) const CONTINUE_ATTEMPT: &str = "dreamer.nightly.continue";
/// The typed parent a Timer wake with no partition plans its spending under
/// (FIX 336). Its own dedupe domain: a caller's key never coalesces it with
/// an explicit partition's consolidation.
pub(crate) const PLAN_ATTEMPT: &str = "dreamer.timer.plan";

pub(crate) fn schedule_remainder_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<()> {
    remainder_in_txn(vault, txn, &attempt.status, now)
}

/// The remainder cadence under `parent`: what the interest queue still
/// holds is spent again a policy interval later.
fn remainder_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAttemptStatus,
    now: u64,
) -> Result<()> {
    if !sieve::interest_left_in_txn(vault, txn)? {
        return Ok(());
    }
    let due = now.saturating_add(super::policy::policy_in_txn(vault, txn)?.nightly_secs);
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Macro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: CONTINUE_ATTEMPT.into(),
            input: rmpv::Value::from(due),
            parent_attempt: Some(parent.attempt.id),
        },
        Some(CONTINUE_ATTEMPT.into()),
        parent.attempt.run_id.clone(),
        now,
    )?;
    Ok(())
}

/// A Timer wake with no partition (FIX 336): one typed parent on the Macro
/// lane, and, only when this call enqueued it, the existing Nightly spending
/// planned under it in the caller's commit: its children within the policy
/// limits, their merge, and the remainder at the policy cadence. An existing
/// parent plans nothing again, so a replay spends no span twice. Empty work
/// is a parent that completes.
pub(crate) fn enqueue_timer_plan_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent_attempt: Option<AttemptId>,
    dedupe_key: Option<String>,
    run_id: Option<String>,
    now: u64,
) -> Result<EnqueueDreamerAttemptOutcome> {
    let outcome = store.enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Macro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: PLAN_ATTEMPT.into(),
            input: rmpv::Value::Nil,
            parent_attempt,
        },
        dedupe_key.map(|key| format!("{PLAN_ATTEMPT}:{key}")),
        run_id,
        now,
    )?;
    match &outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status) => {
            plan_children_in_txn(store.vault(), txn, status, now)?;
            remainder_in_txn(store.vault(), txn, status, now)?;
        }
        EnqueueDreamerAttemptOutcome::Existing(status)
            if status.payload.parent_attempt != parent_attempt =>
        {
            // Names the plan that stands, so the caller can join it.
            return Err(crate::Error::InvalidConfig(format!(
                "timer plan dedupe cannot change its parent; plan attempt {} stands under it",
                crate::entity_id::bytes_to_hex_lower(status.attempt.id.as_bytes())
            )));
        }
        EnqueueDreamerAttemptOutcome::Existing(_) => {}
    }
    Ok(outcome)
}

pub(crate) fn continue_nightly(
    attempt: &DreamerAdmittedAttempt,
    ctx: &super::WakeAttemptContext<'_>,
) -> Result<super::DreamerAttemptExecution> {
    let now = ctx.now_ms / 1_000;
    let due = attempt
        .status
        .payload
        .input
        .as_u64()
        .ok_or(crate::Error::InvalidConfig(
            "invalid nightly continuation".into(),
        ))?;
    if now < due {
        return Ok(super::DreamerAttemptExecution::Deferred {
            completed_units: 0,
            retry_at: due,
        });
    }
    let (left, interval) = ctx.vault.with_write_txn_grouped(|txn| {
        children_in_txn(ctx.vault, txn, attempt, now)?;
        Ok((
            sieve::interest_left_in_txn(ctx.vault, txn)?,
            super::policy::policy_in_txn(ctx.vault, txn)?.nightly_secs,
        ))
    })?;
    ctx.vault.store.notify_attempt_observers();
    if left {
        Ok(super::DreamerAttemptExecution::Deferred {
            completed_units: 0,
            retry_at: now.saturating_add(interval),
        })
    } else {
        Ok(super::DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}

pub(crate) fn children_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<()> {
    plan_children_in_txn(vault, txn, &attempt.status, now)
}

/// The Nightly children under `attempt`: owed rungs for the highest scored
/// spans, then the structural partitions their turns fall in, in score
/// order within the policy's limits, one child per thing inside each, their
/// merge, and the spans they spend.
fn plan_children_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAttemptStatus,
    now: u64,
) -> Result<()> {
    let policy = recipes::policy_in_txn(vault, txn)?;
    let spans = sieve::recipe_spans_in_txn(vault, txn, policy.nightly_spans as usize)?;
    let store = DreamerRunnerStore::new(vault);
    let mut ids = BTreeSet::new();
    for span in &spans {
        if span.owed.is_empty() {
            ids.insert(span.turn);
        } else {
            sieve::enqueue_rungs_in_txn(&store, txn, attempt, span, false, now)?;
        }
    }
    let scope = DreamerConsolidationScope::Macro;
    let turns =
        read_partition_turns_in_txn(vault, txn, scope, &ids.into_iter().collect::<Vec<_>>())?;
    let watermark = ConsolidationWatermark::bootstrap();
    let mut plans = partition_turns_in_txn(vault, txn, &turns, &watermark)?;
    // Partition iteration is structural order; spending order must instead
    // follow the highest scored span of each topic.
    plans.sort_by_key(|plan| {
        spans
            .iter()
            .position(|span| plan.turns.iter().any(|turn| turn.turn_id == span.turn))
            .unwrap_or(usize::MAX)
    });
    // The limit counts topics, as before; every thing a kept topic holds
    // gets its children, so the night spends the spans it spent before.
    plans.truncate(policy.nightly_children as usize);
    let audiences = things::audiences_in_txn(vault, txn, &plans)?;
    let exposures = exposure::exposures_in_txn(vault, txn, &plans);
    let thing_plans = things::plan_things(&plans, &spans, &audiences, &exposures);
    let child_plans: Vec<_> = thing_plans
        .iter()
        .flat_map(|thing| thing.children.iter().cloned())
        .collect();
    tracing::debug!(
        partitions = plans.len(),
        things = thing_plans.len(),
        bound = thing_plans
            .iter()
            .filter(|thing| thing.key.entity.is_some())
            .count(),
        children = child_plans.len(),
        spanning = child_plans
            .iter()
            .filter(|child| child.parts.len() > 1)
            .count(),
        "nightly children planned, one per thing and project"
    );
    let outcomes = enqueue_parented_branch_plans_in_txn(
        vault,
        txn,
        scope,
        &child_plans,
        attempt.attempt.id,
        attempt.attempt.run_id.as_deref(),
        now,
    )?;
    if outcomes.len() != child_plans.len() {
        return Err(crate::Error::InvariantViolation(
            "nightly children and their enqueue outcomes differ in count",
        ));
    }
    let children = outcomes
        .iter()
        .map(|outcome| match outcome {
            crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status)
            | crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status) => {
                status.attempt.id
            }
        })
        .collect();
    crate::dreamer_consolidation::nightly_merge::enqueue_in_txn(
        vault, txn, attempt, children, now,
    )?;
    // Each spent span names its own thing's child that carries its TURN,
    // enqueued now or standing, never this parent (FIX 7498, 8723): a TURN
    // several things hold is carried by each, and each span by its own.
    let mut at = 0_usize;
    for thing in &thing_plans {
        let end = at + thing.children.len();
        let carriers = sieve::consumed_carriers(&child_plans[at..end], &outcomes[at..end])?;
        at = end;
        for span in &thing.spans {
            // A spent span rides with its own thing, one of whose children
            // holds its TURN: a missing carrier is a fault.
            let carrier =
                carriers
                    .get(&span.turn)
                    .copied()
                    .ok_or(crate::Error::InvariantViolation(
                        "a spent sieve span's TURN has no carrying child",
                    ))?;
            sieve::spend_consumed_in_txn(&vault.store, txn, span, carrier, now)?;
        }
    }
    Ok(())
}
