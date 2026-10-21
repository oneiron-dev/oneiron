//! The agent-health review over one agent attempt (OF-568 L1, L2): on its
//! terminal receipt, and at each Dreamer wake while it runs, over what it has
//! streamed so far (agent-mind §3: "On each terminal receipt", "During long
//! attempts"). It runs the per-attempt detectors on that attempt's own
//! evidence (its run's calls and checks, its waits, its sealed receipt, its
//! widen proposals and its TASK's done evidence) and lands their findings on
//! the nightly review's cards, so a repeat merges into the same DIAGNOSTIC
//! and the same card.
//!
//! A call receipt names no attempt, so the call-receipt `loop` and
//! `failed_check_repeat` halves stay with the nightly review. So do
//! `duplicate_work`, which pairs an attempt against every run in the review
//! window, `cost_spike`, whose baseline is every retained run of the task
//! type, and the TTL climb over every card. Its output is the nightly
//! review's cards and DIAGNOSTICs, nothing else.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    Attempts, CALL_RECEIPTS, COACH_AGENT_HEALTH_FACET, DialBook, Dispatched, Dispatches, Traps,
    check_repeat, land, long_wait_findings, misalignment_findings, run_loop, silent_findings,
    unsupported_done_findings, widen_denial_findings,
};
use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND;
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore,
    decode_dreamer_attempt_payload,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::llm::open_trap_waits;
use crate::receipt::CallReceipt;
use crate::{EntityId, Error, Result, Vault};

/// Dedupe namespace of a terminal review: one per attempt and the lease
/// generation it settled under.
const TERMINAL_KEY: &str = "coach.agent_health.terminal";
/// Dedupe namespace of a live review: one per attempt and the wake that
/// queued it.
const LIVE_KEY: &str = "coach.agent_health.live";

/// What one `coach.agent_health` job reviews. A Nil input is the nightly
/// review, as every job queued before this input existed is.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum HealthReviewInput {
    /// The scoped background review, each scope over its own window.
    Nightly,
    /// One agent attempt at its terminal receipt.
    Terminal {
        attempt: AttemptId,
        /// The lease generation it settled under.
        generation: u32,
        /// The settle's pack receipt, when it minted one. It is evidence of
        /// the settle, never the agent's identity: its actor is whoever
        /// settled the row.
        receipt: Option<String>,
    },
    /// One live agent attempt at a Dreamer wake.
    Live {
        attempt: AttemptId,
        /// The recipe-wake receipt whose wake queued it.
        wake: AttemptId,
    },
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid agent-health review input".into())
}

fn decode(input: &Value) -> Result<HealthReviewInput> {
    if input.is_nil() {
        return Ok(HealthReviewInput::Nightly);
    }
    serde_json::from_str(input.as_str().ok_or_else(invalid)?).map_err(|_| invalid())
}

/// Runs one `coach.agent_health` job on its input. Returns the cards it
/// touched.
pub(crate) fn review(vault: &Vault, input: &Value, now: u64) -> Result<u64> {
    let attempt = match decode(input)? {
        HealthReviewInput::Nightly => {
            // Outcome receipts whose learning row did not land go first,
            // whether or not any scope is reviewed. A failure here is logged
            // and never stops the review.
            if let Err(error) = super::outcomes::reproject_pending(vault, now) {
                tracing::warn!(
                    kind = ?error.kind(),
                    "agent-health review receipts not re-applied"
                );
            }
            return super::run(vault, now);
        }
        HealthReviewInput::Terminal {
            attempt,
            generation,
            receipt,
        } => {
            tracing::debug!(
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                generation,
                receipt = ?receipt,
                "agent-health review at a terminal receipt"
            );
            attempt
        }
        HealthReviewInput::Live { attempt, wake } => {
            tracing::debug!(
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                wake = %bytes_to_hex_lower(wake.as_bytes()),
                "agent-health review at a Dreamer wake"
            );
            attempt
        }
    };
    review_attempt(vault, attempt, now)
}

/// Whether `record` is an agent dispatch, the only work the check judges.
fn agent_work(record: &AttemptRecord) -> bool {
    record.kind == DREAMER_RUNNER_ATTEMPT_KIND
        && decode_dreamer_attempt_payload(&record.payload)
            .is_ok_and(|payload| payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
}

/// The review of one attempt: the per-attempt detectors over its own
/// evidence, landed on the nightly review's cards. The card's subject is the
/// dispatch's own actor and nobody else: an attempt whose dispatch names no
/// actor is reviewed unattributed, and that is no finding and no card.
fn review_attempt(vault: &Vault, attempt: AttemptId, now: u64) -> Result<u64> {
    let queue = AttemptQueue::new(vault);
    let Some(record) = queue.get(attempt)? else {
        return Ok(0);
    };
    let Some(dispatch) = Dispatched::of(&record) else {
        return Ok(0);
    };
    let key = *record.id.as_bytes();
    let mut attempts = Attempts::new();
    // Its spawner, which its card goes to as well.
    if let Some(parent) = dispatch.parent
        && let Some(row) = queue.get(parent)?
    {
        attempts.insert(*parent.as_bytes(), row);
    }
    let actor = dispatch.actor;
    let leased = record.state == AttemptState::Leased;
    let claimed = record.claimed_at.unwrap_or(record.updated_at);
    attempts.insert(key, record);
    let dispatched = Dispatches::from([(key, dispatch)]);
    let book = DialBook::read(vault, &dispatched)?;
    let (review, window) = {
        let dials = book.of(dispatched.get(&key));
        (dials.review, dials.window_secs)
    };
    if !review {
        return Ok(0);
    }
    let since = now.saturating_sub(window);
    let mut traps = Traps::new();
    for wait in open_trap_waits(vault)? {
        if wait.attempt == attempt {
            traps.entry(key).or_default().push(wait);
        }
    }
    // A leased attempt's actor's newest call says it is not silent. That
    // call is read as activity only: a call receipt names no attempt.
    let activity = if leased {
        newest_call(vault, actor, claimed)?
    } else {
        BTreeMap::new()
    };
    let unbound = BTreeMap::new();
    let mut findings = run_loop::run_loop_findings(vault, &dispatched, &attempts, &book, since)?;
    findings.extend(check_repeat::check_repeat_findings(
        vault,
        &unbound,
        &dispatched,
        &attempts,
        &book,
        since,
    )?);
    findings.extend(silent_findings(
        vault,
        &activity,
        &dispatched,
        &attempts,
        &traps,
        &book,
        now,
    )?);
    findings.extend(long_wait_findings(
        &dispatched,
        &attempts,
        &traps,
        &book,
        since,
        now,
    ));
    findings.extend(misalignment_findings(vault, &dispatched, &attempts, since)?);
    findings.extend(widen_denial_findings(
        vault,
        &dispatched,
        &attempts,
        &book,
        since,
    )?);
    findings.extend(unsupported_done_findings(
        vault,
        &dispatched,
        &attempts,
        since,
        now,
    )?);
    land(
        vault,
        findings,
        &[],
        &dispatched,
        &attempts,
        &book,
        now,
        false,
    )
}

/// The actor's newest call receipt at or after `since`, read newest first.
fn newest_call(
    vault: &Vault,
    actor: EntityId,
    since: u64,
) -> Result<BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut calls = BTreeMap::new();
    let mut read: u64 = 0;
    for row in CALL_RECEIPTS.iter_rev_from(&vault.store, &rtxn, &[])? {
        read += 1;
        let Ok((id, receipt)) = row else {
            continue;
        };
        if receipt.at < since {
            break;
        }
        if receipt.actor_class == "agent"
            && EntityId::from_hex(&receipt.actor_ref).ok() == Some(actor)
        {
            calls.insert(actor, vec![(id, receipt)]);
            break;
        }
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, read);
    Ok(calls)
}

/// Queues one review on the maintenance lane, in the caller's write.
fn enqueue(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &HealthReviewInput,
    parent_attempt: Option<AttemptId>,
    key: String,
    run_id: Option<String>,
    now: u64,
) -> Result<()> {
    let input = serde_json::to_string(input).map_err(|_| invalid())?;
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        MAINTENANCE_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_AGENT_HEALTH_FACET.into(),
            input: Value::from(input),
            parent_attempt,
        },
        Some(key),
        run_id,
        now,
    )?;
    Ok(())
}

/// Runs one review's enqueue in a savepoint of the caller's write, so a
/// health enqueue never fails that write: an agent's terminal write and a
/// wake's commit are working capabilities. On any error, the Coach authority
/// seed included, only the savepoint rolls back and the review is skipped
/// with a warning; the nightly review still reads the attempt.
fn soft(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    queue: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) {
    let queued = vault
        .store
        .env
        .nested_write_txn(txn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            queue(&mut savepoint)?;
            savepoint.commit().map_err(Error::from)
        });
    match queued {
        // The savepoint's own post-commit marks were keyed to it: the
        // caller's write re-arms the deadline watch for the queued job.
        Ok(()) => crate::batch::queue_proactivity_change(vault, txn),
        Err(error) => skipped(attempt, &error),
    }
}

fn skipped(attempt: AttemptId, error: &Error) {
    tracing::warn!(
        attempt = %bytes_to_hex_lower(attempt.as_bytes()),
        kind = ?error.kind(),
        "agent-health review not queued"
    );
}

impl Vault {
    /// Queues the agent-health review of the attempt this write settles
    /// (OF-568 L1), in a savepoint of that write: it never fails the write
    /// ([`soft`]). Only an agent dispatch is agent work: a maintenance job,
    /// this review among them, is never reviewed, so a review never queues
    /// another. Keyed by the attempt and the lease generation it settled
    /// under.
    pub(crate) fn enqueue_health_review_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        if record.kind == MAINTENANCE_QUEUE_KIND || !agent_work(record) {
            return Ok(());
        }
        let key = format!(
            "{TERMINAL_KEY}:{}:{}",
            bytes_to_hex_lower(record.id.as_bytes()),
            record.attempt_count
        );
        soft(self, txn, record.id, |savepoint| {
            let receipt_id = crate::receipt::attempt_pack_receipt_id(&record.id);
            let receipt =
                crate::receipt::attempt_pack_receipt_in_txn(&self.store, savepoint, &receipt_id)?
                    .map(|_| receipt_id);
            let input = HealthReviewInput::Terminal {
                attempt: record.id,
                generation: record.attempt_count,
                receipt,
            };
            enqueue(self, savepoint, &input, None, key, None, record.updated_at)
        });
        Ok(())
    }

    /// Queues a review of each live agent attempt (leased or landing) over
    /// what it has streamed so far (OF-568 L2), in the commit of the
    /// continuous recipe wake `wake`, each in its own savepoint: it never
    /// fails that commit ([`soft`]). One wake queues at most one review per
    /// attempt, each its own job under that wake: many live attempts are
    /// many parts, never one long pass.
    pub(crate) fn enqueue_live_health_review_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        wake: &AttemptRecord,
        now: u64,
    ) -> Result<()> {
        let live: Vec<AttemptId> = match AttemptQueue::new(self).list_in_txn(txn) {
            Ok(rows) => rows
                .into_iter()
                .filter(|record| {
                    matches!(record.state, AttemptState::Leased | AttemptState::Landing)
                })
                .filter(agent_work)
                .map(|record| record.id)
                .collect(),
            Err(error) => {
                skipped(wake.id, &error);
                return Ok(());
            }
        };
        let wake_hex = bytes_to_hex_lower(wake.id.as_bytes());
        for attempt in live {
            let key = format!(
                "{LIVE_KEY}:{}:{wake_hex}",
                bytes_to_hex_lower(attempt.as_bytes())
            );
            let input = HealthReviewInput::Live {
                attempt,
                wake: wake.id,
            };
            soft(self, txn, attempt, |savepoint| {
                enqueue(
                    self,
                    savepoint,
                    &input,
                    Some(wake.id),
                    key,
                    wake.run_id.clone(),
                    now,
                )
            });
        }
        Ok(())
    }
}
