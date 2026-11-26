//! The nightly answer-schema check (HOUSE-SCHEMA-CHECK): one Macro child of the night's
//! recipe attempt, drawn from that night's captured TURN calls.
//!
//! The nightly recipe enqueues the check while the switch reads in force; the run gates on the
//! night's other descendants, draws up to eight captures whose sources still read, re-sends
//! each as a schema/shadow pair on the house rung, and lands one receipt per night. Grammar
//! faults suspend at once; the seven-night window suspends on a below-zero difference. A
//! shadow reply is scored only, never decoded into memory, never filed as a claim.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::nightly_merge::merge_read;
use super::super::request_sources::SourcedBackend;
use super::capture::{bind_check_call, capture_may_go};
use super::draw::{draw_pool_in_txn, pair_seed, rank_key, select};
use super::overrun::overrun_in_txn;
use super::pair::{
    build_arms, candidates_of, f1_against_gold, fault_scores, first_list_is_schema,
    parse_judge_answer, source_text, supported_flags,
};
use super::receipt::{
    FinishedReceipt, LandFinished, PairRow, ReceiptOutcome, SkipReason, all_pairs_in_txn,
    land_receipt_in_txn, receipt_in_txn, receipt_line, write_selection_in_txn,
};
use super::rule::{
    date_in_window, evaluate_window, grammar_faults, grammar_suspends, window_suspends,
};
use super::send::{SchemaArm, judge_request, response_text, send_house, send_schema_arm};
use super::spend::Spend;
use super::{AnswerSchemaSuspension, answer_schema_in_force_in_txn};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope, DreamerRunnerStore,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::inference_context::HostInferenceContext;
use crate::model_step_context::DurableStepContext;
use crate::settings::ReadDestination;
use oneiron_model::llm::{BudgetGuard, LlmBackend, ModelId};

/// The check's attempt type: one Macro child per night.
pub const ATTEMPT: &str = "dreamer.nightly.answer_schema";

/// One check's work: the night it checks, and how long a gated check waits.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckInput {
    night: String,
    retry_secs: u64,
}

/// Enqueues the night's check under the recipe receipt, at most one per night: the dedupe is
/// stable on the night id. Called from the nightly recipe only while the switch reads in
/// force at enqueue.
///
/// # Errors
///
/// The recipe policy does not read; the input does not encode; storage faults.
pub(crate) fn enqueue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAttemptStatus,
    now: u64,
) -> Result<()> {
    let policy = crate::dreamer_wake::recipes::policy_in_txn(vault, txn)?;
    let night = bytes_to_hex_lower(parent.attempt.id.as_bytes());
    let input = serde_json::to_string(&CheckInput {
        night: night.clone(),
        retry_secs: policy.rung_retry_secs,
    })
    .map_err(|_| invalid())?;
    let dedupe = format!("{ATTEMPT}:{night}");
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Macro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: ATTEMPT.into(),
            input: input.into(),
            parent_attempt: Some(parent.attempt.id),
        },
        Some(dedupe),
        parent.attempt.run_id.clone(),
        now,
    )?;
    Ok(())
}

/// What the host lends one check: the house model on its own-server rung alone, with the
/// meter and admission its calls send under.
pub struct AnswerSchemaHouse<'a> {
    /// The house rung, which sends without fallback.
    pub backend: &'a dyn LlmBackend,
    /// The same rung bound per call to the rows that call was read from, when lent.
    pub sourced: Option<&'a dyn SourcedBackend>,
    /// The meter the check's calls spend on.
    pub guard: &'a BudgetGuard,
    /// The house model the calls name.
    pub model: ModelId,
    /// The host's statement of the house route, for the judge calls' admission.
    pub inference: HostInferenceContext<'a>,
    /// Where the house rung's offer sends its calls now: each capture's rows and world are
    /// judged for it before its pair and after a failed schema arm, and the host's backend
    /// judges them again at each physical send (REVIEW-10538 round 2).
    pub destination: ReadDestination,
}

/// Runs one admitted check: receipt first, then the gate, the skips, the draw, the pairs,
/// the rules and the landing. `house` is `None` where no host lends the house rung, and
/// the night skips with its reason.
///
/// # Errors
///
/// The check input does not read; an engine error a step hit; storage faults.
pub async fn run_answer_schema_check(
    status: &DreamerAttemptStatus,
    ctx: &WakeAttemptContext<'_>,
    house: Option<AnswerSchemaHouse<'_>>,
) -> Result<DreamerAttemptExecution> {
    let vault = ctx.vault;
    let check_id = status.attempt.id;
    let input: CheckInput =
        serde_json::from_str(status.payload.input.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    let night_bytes = oneiron_hex::decode::<16>(&input.night).ok_or_else(invalid)?;
    let night = AttemptId::from_bytes(&night_bytes).map_err(|_| invalid())?;
    let now = ctx.now_ms / 1_000;
    // A finished receipt returns its outcome: no second receipt, no second call. A started
    // receipt resumes its selection.
    let stored = {
        let txn = vault.store.env.read_txn()?;
        receipt_in_txn(vault, &txn, night)?
    };
    if let Some(finished) = stored
        .as_ref()
        .and_then(|receipt| receipt.finished.as_ref())
    {
        return landed_execution(vault, finished);
    }
    let stored_selection = stored.map(|receipt| receipt.selection);
    // A skip keeps the selection a started receipt ledgered.
    let kept = stored_selection.as_deref().unwrap_or(&[]);
    let date = night_date(vault, night, now)?;
    // The over-budget latch before the gate: a night that ran past its budget skips with its
    // reason even while a budget-parked extraction stays open, which would hold the gate
    // shut on every try and land no receipt (REVIEW-10538 P1-4). The skip sends nothing.
    let (descendants, overrun) = {
        let txn = vault.store.env.read_txn()?;
        (
            descendants_in_txn(vault, &txn, night, false)?,
            overrun_in_txn(vault, &txn, night)?,
        )
    };
    // The skips, in order: over budget, then (past the gate) out of force, no calls, no
    // house rung.
    if overrun.is_some() {
        return write_skip(
            vault,
            night,
            &date,
            SkipReason::OverBudget,
            kept,
            &descendants,
            now,
        );
    }
    // The gate: never take GPU time from the night. Deferred like the nightly merge and the
    // links wait out unfinished children.
    let open = {
        let txn = vault.store.env.read_txn()?;
        let gated = descendants_in_txn(vault, &txn, night, true)?;
        gate_open_in_txn(vault, &txn, check_id, &gated)?
    };
    if !open {
        return Ok(DreamerAttemptExecution::Deferred {
            completed_units: 0,
            retry_at: now.saturating_add(input.retry_secs),
            step_bindings: Vec::new(),
        });
    }
    let in_force = {
        let txn = vault.store.env.read_txn()?;
        answer_schema_in_force_in_txn(vault, &txn)?
    };
    if !in_force {
        return write_skip(
            vault,
            night,
            &date,
            SkipReason::NotInForce,
            kept,
            &descendants,
            now,
        );
    }
    let actor = vault.dreamer_actor_for_attempt(check_id)?;
    let pool = {
        let read = merge_read(vault, actor)?;
        let txn = vault.store.env.read_txn()?;
        draw_pool_in_txn(vault, &txn, &read, &descendants)?
    };
    if pool.is_empty() {
        return write_skip(
            vault,
            night,
            &date,
            SkipReason::NoCalls,
            kept,
            &descendants,
            now,
        );
    }
    let Some(house) = house else {
        let selection = select(night, &pool);
        let keys = selection.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        return write_skip(
            vault,
            night,
            &date,
            SkipReason::NoHouseRung,
            &keys,
            &descendants,
            now,
        );
    };
    // The selection: the stored one on a retry, else the draw, ledgered before the first
    // call so a retry names the same work.
    let selection = match stored_selection {
        Some(selection) => selection,
        None => {
            let keys = select(night, &pool)
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>();
            vault.with_write_txn_grouped(|txn| {
                write_selection_in_txn(vault, txn, night, &date, &keys)
            })?;
            keys
        }
    };
    // The selected captures; one erased after the draw drops its pair.
    let mut work = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for key in &selection {
            if let Some(capture) = super::capture::capture_in_txn(&vault.store, &txn, key)? {
                work.push((*key, rank_key(night, key), capture));
            }
        }
    }
    if work.is_empty() {
        return write_skip(
            vault,
            night,
            &date,
            SkipReason::NoCalls,
            &selection,
            &descendants,
            now,
        );
    }
    let mut spend = Spend::default();
    let mut rows = Vec::new();
    for (key, rank, capture) in &work {
        // A source erased or withdrawn since the draw, or one a world now keeps from the house
        // rung's destination, drops its pair before any send; the house backend asks again at
        // each physical send (REVIEW-10538 P1-1 and round 2). Each call is listed on its
        // capture before it goes, so an erase of any of the capture's rows takes its reply.
        if !capture_may_go(vault, key, &house.destination)? {
            continue;
        }
        let seed = pair_seed(rank);
        let step_ctx = DurableStepContext {
            vault,
            attempt_id: check_id,
            run_id: status.attempt.run_id.clone(),
            envelope_actor: actor,
            subject: step_subject(&capture.sources, night),
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
            spend_scope: None,
            wake_pass_bound: true,
        };
        let (schema_request, shadow_request) = build_arms(&capture.request, &house.model, seed);
        if !bind_check_call(vault, key, check_id, &schema_request)? {
            continue;
        }
        // A schema arm the provider refused or failed is a failed arm: its shadow still
        // goes out, so a grammar fault reaches the two-fault rule (REVIEW-10538 P1-5). One the
        // rows' admission or fence refused is no answer of the arm: its pair drops.
        let schema_response =
            match send_schema_arm(&step_ctx, &house, &capture.sources, schema_request, spend)
                .await?
            {
                SchemaArm::Answered(response, next) => {
                    spend = next;
                    Some(response)
                }
                SchemaArm::Failed(next) => {
                    spend = next;
                    if !capture_may_go(vault, key, &house.destination)? {
                        continue;
                    }
                    None
                }
                SchemaArm::Parked(parked) => return Ok(parked),
            };
        if !bind_check_call(vault, key, check_id, &shadow_request)? {
            continue;
        }
        let (shadow_response, next) =
            match send_house(&step_ctx, &house, &capture.sources, shadow_request, spend).await? {
                Ok(done) => done,
                Err(parked) => return Ok(parked),
            };
        spend = next;
        let (schema_whole, schema_candidates) =
            schema_response.as_ref().map_or((false, 0), fault_scores);
        let (shadow_whole, shadow_candidates) = fault_scores(&shadow_response);
        let schema_cands = schema_response
            .as_ref()
            .map(candidates_of)
            .unwrap_or_default();
        let shadow_cands = candidates_of(&shadow_response);
        // No candidates on either arm is no gold whatever the judge says: judge nothing.
        let (schema_f1, shadow_f1) =
            if schema_cands.is_empty() && shadow_cands.is_empty() {
                (None, None)
            } else {
                let schema_first = first_list_is_schema(seed);
                let (list1, list2) = if schema_first {
                    (&schema_cands, &shadow_cands)
                } else {
                    (&shadow_cands, &schema_cands)
                };
                let source = source_text(&capture.request);
                let world = capture.request.envelope.scope.world;
                let first_request = judge_request(vault, &house, world, &source, list1, list2)?;
                if !bind_check_call(vault, key, check_id, &first_request)? {
                    continue;
                }
                let (first_response, next) =
                    match send_house(&step_ctx, &house, &capture.sources, first_request, spend)
                        .await?
                    {
                        Ok(done) => done,
                        Err(parked) => return Ok(parked),
                    };
                spend = next;
                let second_request = judge_request(vault, &house, world, &source, list2, list1)?;
                if !bind_check_call(vault, key, check_id, &second_request)? {
                    continue;
                }
                let (second_response, next) =
                    match send_house(&step_ctx, &house, &capture.sources, second_request, spend)
                        .await?
                    {
                        Ok(done) => done,
                        Err(parked) => return Ok(parked),
                    };
                spend = next;
                let first =
                    parse_judge_answer(&response_text(&first_response), list1.len(), list2.len());
                let second =
                    parse_judge_answer(&response_text(&second_response), list2.len(), list1.len());
                match (first, second) {
                    (Some(first), Some(second)) => {
                        let (schema_flags, shadow_flags) = supported_flags(
                            seed,
                            schema_cands.len(),
                            shadow_cands.len(),
                            first,
                            second,
                        );
                        f1_against_gold(&schema_cands, &schema_flags, &shadow_cands, &shadow_flags)
                    }
                    // A judge answer off the contract is no quality for the pair, never a
                    // verdict: the memoized step would answer it again.
                    _ => (None, None),
                }
            };
        rows.push(PairRow {
            night: date.clone(),
            schema_whole,
            shadow_whole,
            schema_candidates,
            shadow_candidates,
            schema_f1,
            shadow_f1,
        });
    }
    // The rules, grammar first.
    let faults = grammar_faults(
        &rows
            .iter()
            .map(|row| (row.schema_whole, row.shadow_whole))
            .collect::<Vec<_>>(),
    );
    let window = {
        let txn = vault.store.env.read_txn()?;
        let mut diffs = Vec::new();
        let mut nights = BTreeSet::new();
        for (pair_night, _, pair) in all_pairs_in_txn(vault, &txn)? {
            if !date_in_window(&pair.night, &date) {
                continue;
            }
            let (Some(schema), Some(shadow)) = (pair.schema_f1, pair.shadow_f1) else {
                continue;
            };
            diffs.push(schema - shadow);
            nights.insert(pair_night);
        }
        for row in &rows {
            let (Some(schema), Some(shadow)) = (row.schema_f1, row.shadow_f1) else {
                continue;
            };
            diffs.push(schema - shadow);
            nights.insert(night);
        }
        evaluate_window(&diffs, night.as_bytes(), nights.len() as u32)
    };
    let suspension = if grammar_suspends(faults) {
        Some(AnswerSchemaSuspension::GrammarFaults {
            night: date.clone(),
            faults,
        })
    } else {
        match window {
            Some(stats) if window_suspends(&stats) => Some(AnswerSchemaSuspension::Window {
                d: stats.d,
                lower: stats.lower,
                upper: stats.upper,
                pairs: stats.n,
                nights: stats.nights,
            }),
            _ => None,
        }
    };
    let quality: Vec<(f64, f64)> = rows
        .iter()
        .filter_map(|row| Some((row.schema_f1?, row.shadow_f1?)))
        .collect();
    tracing::debug!(
        target: "oneiron::dreamer",
        pairs = rows.len(),
        schema_candidates = rows.iter().map(|row| row.schema_candidates).sum::<u32>(),
        shadow_candidates = rows.iter().map(|row| row.shadow_candidates).sum::<u32>(),
        "answer-schema check scored its pairs"
    );
    let land = LandFinished {
        pairs: rows.len() as u32,
        schema_whole: rows.iter().filter(|row| row.schema_whole).count() as u32,
        shadow_whole: rows.iter().filter(|row| row.shadow_whole).count() as u32,
        schema_f1_mean: mean(
            &quality
                .iter()
                .map(|(schema, _)| *schema)
                .collect::<Vec<_>>(),
        ),
        shadow_f1_mean: mean(
            &quality
                .iter()
                .map(|(_, shadow)| *shadow)
                .collect::<Vec<_>>(),
        ),
        window,
        completed_units: spend.units,
        step_bindings: spend.step_bindings.clone(),
    };
    let outcome = match suspension.as_ref() {
        Some(suspension) => ReceiptOutcome::Suspend(suspension),
        None => ReceiptOutcome::Keep,
    };
    vault.with_write_txn_grouped(|txn| {
        land_receipt_in_txn(
            vault,
            txn,
            night,
            &date,
            &selection,
            &rows,
            land,
            outcome,
            &descendants,
            now,
        )
    })?;
    landed_with_log(vault, night, spend)
}

/// Writes a skip receipt for the night with its reason, retiring the night's captures.
///
/// # Errors
///
/// Storage faults.
fn write_skip(
    vault: &Vault,
    night: AttemptId,
    date: &str,
    reason: SkipReason,
    selection: &[(AttemptId, [u8; 32])],
    descendants: &[AttemptId],
    now: u64,
) -> Result<DreamerAttemptExecution> {
    vault.with_write_txn_grouped(|txn| {
        land_receipt_in_txn(
            vault,
            txn,
            night,
            date,
            selection,
            &[],
            LandFinished::empty(),
            ReceiptOutcome::Skip(reason),
            descendants,
            now,
        )
    })?;
    landed_with_log(vault, night, Spend::default())
}

/// Completes a landed night, writing its receipt line to the log: the plan's line, not a
/// digest line.
///
/// # Errors
///
/// Storage faults.
fn landed_with_log(
    vault: &Vault,
    night: AttemptId,
    spend: Spend,
) -> Result<DreamerAttemptExecution> {
    let txn = vault.store.env.read_txn()?;
    if let Some(receipt) = receipt_in_txn(vault, &txn, night)? {
        tracing::info!(target: "oneiron::dreamer", "{}", receipt_line(&receipt));
    }
    Ok(spend.completed())
}

/// What a night that already landed completes with: its own units with the steps they paid
/// for, or nothing once every step it paid for is charged. None when it has not landed is
/// decided by the caller.
///
/// # Errors
///
/// Storage faults.
fn landed_execution(vault: &Vault, finished: &FinishedReceipt) -> Result<DreamerAttemptExecution> {
    let store = DreamerRunnerStore::new(vault);
    let mut paid = !finished.step_bindings.is_empty();
    for binding in &finished.step_bindings {
        paid &= store.checkpoint_step_charged(binding.attempt_id, &binding.step_hash)?;
    }
    Ok(if paid {
        DreamerAttemptExecution::Completed {
            completed_units: 0,
            step_bindings: Vec::new(),
        }
    } else {
        DreamerAttemptExecution::Completed {
            completed_units: finished.completed_units,
            step_bindings: finished.step_bindings.clone(),
        }
    })
}

/// Every descendant of the night, breadth first. With `prune_continue`, remainder queued
/// for a later cadence is skipped with its whole subtree: the gate never waits on it.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn descendants_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    night: AttemptId,
    prune_continue: bool,
) -> Result<Vec<AttemptId>> {
    let store = DreamerRunnerStore::new(vault);
    let queue = AttemptQueue::new(vault);
    let mut seen = BTreeSet::from([night]);
    let mut parents = vec![night];
    let mut out = Vec::new();
    while let Some(parent) = parents.pop() {
        for child in store.child_attempts_in_txn(txn, parent)? {
            if !seen.insert(child) {
                continue;
            }
            if prune_continue && is_continue_in_txn(&queue, txn, child)? {
                continue;
            }
            parents.push(child);
            out.push(child);
        }
    }
    Ok(out)
}

/// Whether `id` is remainder queued for a later cadence. A row or payload that does not
/// read is no remainder.
///
/// # Errors
///
/// Storage faults.
fn is_continue_in_txn(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<bool> {
    let Some(record) = queue.get_in_txn(txn, id)? else {
        return Ok(false);
    };
    let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload) else {
        return Ok(false);
    };
    Ok(payload.attempt_type == crate::dreamer_wake::nightly::CONTINUE_ATTEMPT)
}

/// Whether the gate stands open: every other descendant of the night is terminal. A queue
/// row already cleaned up was terminal.
///
/// # Errors
///
/// Storage faults.
fn gate_open_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    check_id: AttemptId,
    descendants: &[AttemptId],
) -> Result<bool> {
    let queue = AttemptQueue::new(vault);
    for descendant in descendants {
        if *descendant == check_id {
            continue;
        }
        let terminal = queue
            .get_in_txn(txn, *descendant)?
            .is_none_or(|record| record.state.is_terminal());
        if !terminal {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The night's `YYYY-MM-DD`, UTC, of the night attempt's start. The vault names no local
/// date of its own, so UTC stands.
///
/// # Errors
///
/// Storage faults.
fn night_date(vault: &Vault, night: AttemptId, now: u64) -> Result<String> {
    let txn = vault.store.env.read_txn()?;
    let start = AttemptQueue::new(vault)
        .get_in_txn(&txn, night)?
        .map_or(now, |record| record.created_at);
    Ok(utc_date(start)
        .or_else(|| utc_date(now))
        .unwrap_or_else(|| "1970-01-01".to_owned()))
}

/// The UTC `YYYY-MM-DD` of Unix `when`, if it reads as a date.
fn utc_date(when: u64) -> Option<String> {
    let when = i64::try_from(when).ok()?;
    let date = chrono::DateTime::from_timestamp(when, 0)?;
    Some(date.format("%Y-%m-%d").to_string())
}

/// The step subject of a pair's calls: the capture's first source row, else the night.
fn step_subject(sources: &[EntityId], night: AttemptId) -> EntityId {
    sources.first().copied().unwrap_or_else(|| {
        EntityId::from_bytes(*night.as_bytes()).unwrap_or_else(|_| EntityId::now())
    })
}

/// The mean of `values`, if any.
fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid answer-schema check input".into())
}
