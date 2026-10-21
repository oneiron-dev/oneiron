//! A code fix's work rows (OF-380): each failure's row and its key, the
//! `coach.code_fix` run a filed heal wakes, the verdicts a run keeps in the
//! write that queues its records, and what a run reads of the failure.

use rmpv::Value;
use serde_json::json;

use super::super::coach::COACH_CODE_FIX_FACET;
use super::super::coach_heal::{HealRoute, case_reports};
use super::{
    BLOCKED_WORK_DOMAIN, CandidateRun, CodeFixSettled, CodeFixWork, PublisherCandidate,
    PublisherCandidateKind, SealedRun, WORK,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{COACH_HEAL_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore};
use crate::failure_ladder::{BlockedReportRef, HealerCase, healer_case_in_txn};
use crate::failure_signals::{
    CodeFixSource, CodeFixVerdict, CodeFixWithheld, FailureSource, Sealing, failed_case_in,
    queue_sealed_in_txn,
};
use crate::limit_ask::EngineLimit;
use crate::skill_optimize::union_source_rows;
use crate::{EntityId, Result, Vault};

/// The work row's key: a case's own key, or one derived from a blocked
/// report's receipt, so a case and a report never share a row.
fn work_key(source: &CodeFixSource) -> Result<EntityId> {
    match source {
        CodeFixSource::Case { case_ref } => Ok(EntityId::from_hex(case_ref)?),
        CodeFixSource::Blocked { receipt, .. } => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(BLOCKED_WORK_DOMAIN);
            hasher.update(receipt.as_bytes());
            let mut key = [0; 16];
            key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
            Ok(EntityId::from_bytes(key)?)
        }
    }
}

/// Queues the Coach's code-fix run for a failure it just filed a heal for,
/// when this deployment exports. The failure's work row makes it one run per
/// case or report; the attempt's input is that row's key.
pub(in crate::dreamer_runner::maintenance) fn wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: CodeFixSource,
    proposal: EntityId,
    route: HealRoute,
    parent: AttemptId,
    now: u64,
) -> Result<()> {
    if !vault.config.failure_signals.exports() {
        return Ok(());
    }
    let key = work_key(&source)?;
    if WORK.get(&vault.store, &*txn, &key)?.is_some() {
        return Ok(());
    }
    if let CodeFixSource::Case { case_ref } = &source
        && run_report_has_work_in(vault, txn, case_ref)?
    {
        return Ok(());
    }
    WORK.put(
        &vault.store,
        txn,
        &key,
        &CodeFixWork {
            source,
            proposal,
            route: route.as_str().to_owned(),
            queued_at: now,
            settled: None,
        },
    )?;
    enqueue_run_in_txn(vault, txn, key, Some(parent), now)
}

/// Whether a blocked report the case's failing run filed has its own work
/// row: that run replays the same failure and, unless it already settled,
/// classes it with this case's ladder class and evidence joined onto the
/// report (`code_fix_subject_in`), so the case queues none.
fn run_report_has_work_in(vault: &Vault, txn: &heed::RoTxn<'_>, case_ref: &str) -> Result<bool> {
    let Some(case) = healer_case_in_txn(vault, txn, case_ref)? else {
        return Ok(false);
    };
    let run = EntityId::from_bytes(*case.failing_attempt_id.as_bytes())?;
    for receipt in crate::self_heal::blocked_reports::receipts_of_run_in(vault, txn, run)? {
        let key = work_key(&CodeFixSource::Blocked {
            receipt,
            run: Some(run),
        })?;
        if WORK.contains(&vault.store, txn, &key)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The verdict a sealed record keeps: queued in `txn`, the write that keeps
/// its run, unless its source no longer stands there.
pub(super) fn keep_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &CodeFixSource,
    (verdict, sealed): Sealing,
) -> Result<CodeFixVerdict> {
    match sealed {
        Some(sealed) => queue_sealed_in_txn(vault, txn, source, sealed),
        None => Ok(verdict),
    }
}

pub(super) fn keep_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &CodeFixSource,
    (mut run, sealed): SealedRun,
) -> Result<CandidateRun> {
    run.export = keep_in_txn(vault, txn, source, (run.export, sealed))?;
    Ok(run)
}

/// Queues the `coach.code_fix` attempt for the work row `key`. One waiting
/// attempt per row: a second enqueue finds the first.
pub(super) fn enqueue_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: EntityId,
    parent: Option<AttemptId>,
    now: u64,
) -> Result<()> {
    let input = key.to_hex();
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HEAL_ATTEMPT_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_CODE_FIX_FACET.into(),
            input: Value::from(input.as_str()),
            parent_attempt: parent,
        },
        Some(format!("{COACH_CODE_FIX_FACET}:{input}")),
        None,
        now,
    )?;
    Ok(())
}

/// The candidates of `pinned` that `settled` holds no run of that stands,
/// each as its id and kind: one it never ran, an engine pair it kept not
/// run at another shadow protocol (FIX 1661/2144), and with `read_granted`
/// one kept for want of the Coach's Grant (FIX 7031).
pub(super) fn untried(
    settled: &CodeFixSettled,
    pinned: &[PublisherCandidate],
    read_granted: bool,
) -> Vec<(String, PublisherCandidateKind)> {
    pinned
        .iter()
        .filter(|candidate| {
            !settled
                .candidates
                .iter()
                .any(|run| run.candidate_id == candidate.id && run.tried(read_granted))
        })
        .map(|candidate| (candidate.id.clone(), candidate.kind.clone()))
        .collect()
}

/// Each of `candidates` kept as not run, for `reason`: it is not tried again.
pub(super) fn not_run(
    candidates: &[(String, PublisherCandidateKind)],
    reason: CodeFixWithheld,
) -> Vec<SealedRun> {
    candidates
        .iter()
        .map(|(candidate_id, _)| {
            let run = CandidateRun {
                candidate_id: candidate_id.clone(),
                outcome: None,
                export: CodeFixVerdict::Withheld { reason },
                replay: None,
                engine: None,
            };
            (run, None)
        })
        .collect()
}

/// The failure's evidence for its questions (the case's own and each report
/// it still reads), and its reports as those questions read them: every one,
/// each whole, measured.
pub(super) fn failure_context(
    vault: &Vault,
    case: Option<&HealerCase>,
    reports: &[BlockedReportRef],
) -> Result<(Vec<EntityId>, Vec<serde_json::Value>)> {
    let reports = case_reports(vault, reports)?;
    let mut evidence: Vec<EntityId> = case
        .and_then(|case| EntityId::from_hex(&case.evidence_ref).ok())
        .into_iter()
        .chain(reports.iter().map(|(receipt, _)| *receipt))
        .collect();
    evidence.sort();
    evidence.dedup();
    let longest = reports
        .iter()
        .map(|(_, report)| report.untrusted_detail.len())
        .max()
        .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, reports.len() as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    let reports = reports
        .iter()
        .map(|(_, report)| {
            json!({
                "category": report.category.as_str(),
                "untrusted_detail": report.untrusted_detail,
            })
        })
        .collect();
    Ok((evidence, reports))
}

/// The rows a job's draft is assembled from (FIX 6997): the failure's texts,
/// each report the questions read (`evidence`, which a case would join), and
/// the heal its route came from. A failure-ladder case is a row under a
/// correlation key that names no rows its class came from, so a job with one
/// is unknown, `None`.
pub(super) fn draft_rows(
    case: Option<&HealerCase>,
    failure: &FailureSource,
    evidence: &[EntityId],
    proposal: EntityId,
) -> Option<Vec<EntityId>> {
    if case.is_some() {
        return None;
    }
    union_source_rows([
        failure.source_rows.as_deref(),
        Some(evidence),
        Some(std::slice::from_ref(&proposal)),
    ])
}

/// Queues the Coach's code-fix run for a blocked report it just filed a heal
/// for (OF-380). A report with no durable run, or whose run is no agent
/// dispatch's attempt, gets its run too: it replays from the source its
/// run's host kept (FIX 2343). A report whose run's attempt has a failed
/// case gets none of its own: that case's heal queues the run for the same
/// failure.
#[allow(clippy::too_many_arguments)]
pub(in crate::dreamer_runner::maintenance) fn wake_blocked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: EntityId,
    run: Option<EntityId>,
    proposal: EntityId,
    route: HealRoute,
    parent: AttemptId,
    now: u64,
) -> Result<()> {
    if let Some(run) = run {
        let case_ref =
            crate::failure_ladder::failure_case_ref(AttemptId::from_bytes(run.as_bytes())?);
        if failed_case_in(vault, txn, &case_ref)?.is_some() {
            return Ok(());
        }
    }
    wake_in_txn(
        vault,
        txn,
        CodeFixSource::Blocked { receipt, run },
        proposal,
        route,
        parent,
        now,
    )
}
