//! Budgeted interest-queue spending. A topic is the existing structural
//! conversation/world/facet partition, not a guessed entity identity.
//!
//! A Timer wake that names no partition (FIX 336) plans the same spending
//! at its enqueue: a typed parent, its children and the remainder land in
//! the enqueue's own commit, and the parent only completes when it runs.

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::{
    ConsolidationWatermark, enqueue_parented_partition_plans_in_txn, partition_turns_in_txn,
    read_partition_turns_in_txn,
};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{Result, Vault};

use super::{recipes, sieve};

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
            return Err(crate::Error::InvalidConfig(
                "timer plan dedupe cannot change its parent".into(),
            ));
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
/// order within the policy's limits, their merge, and the spans they spend.
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
    plans.truncate(policy.nightly_children as usize);
    let outcomes = enqueue_parented_partition_plans_in_txn(
        vault,
        txn,
        scope,
        &plans,
        attempt.attempt.id,
        attempt.attempt.run_id.as_deref(),
        now,
    )?;
    let children = outcomes
        .into_iter()
        .map(|(_, outcome)| match outcome {
            crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status)
            | crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status) => {
                status.attempt.id
            }
        })
        .collect();
    crate::dreamer_consolidation::nightly_merge::enqueue_in_txn(
        vault, txn, attempt, children, now,
    )?;
    let spent: BTreeSet<_> = plans
        .iter()
        .flat_map(|plan| plan.turns.iter().map(|turn| turn.turn_id))
        .collect();
    for span in spans
        .iter()
        .filter(|span| span.owed.is_empty() && spent.contains(&span.turn))
    {
        sieve::spend_consumed_in_txn(&vault.store, txn, span, attempt.attempt.id, now)?;
    }
    Ok(())
}
