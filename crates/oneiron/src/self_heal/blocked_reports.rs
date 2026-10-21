//! Blocked reports into the Coach's Issues job (ARCH-0066 #report_blocked,
//! OF-418). A `self.report_blocked` receipt witnessed on the canonical vault
//! lands as a proposed DIAGNOSTIC (class `agent_blocked`, source
//! `self_report`) and one pending Issues row, and wakes the Coach. The report
//! is the agent's own word: it never arms the failure ladder or a tripwire,
//! and its detail stays in the fenced receipt. A report on a session overlay
//! stays off the record and files nothing. A filed report keeps the source a
//! code fix replays (`source`, FIX 2343).
use std::ops::Bound;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::code_run::blocked::BlockedCategory;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::failure_ladder::{BlockedReportRef, ingest_report_blocked};
use crate::limit_ask::EngineLimit;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Result, Vault};

mod source;
pub(crate) use source::{
    BlockedRunHost, BlockedRunRequest, RunWorlds, SentRequest, bind_step_claim_in_txn,
    blocked_source_in, capture_durable_step, erase_blocked_source_actor_in_txn,
    remove_step_sources_in_txn, step_sources_in,
};

/// Reports waiting for the Coach. Key: the receipt.
const PENDING: SideTable<EntityId, BlockedIssue, Named> =
    SideTable::new(&side_table::COACH_BLOCKED_ISSUE);
/// What the Coach filed for a report or a case. Key: the receipt, or the case.
const SETTLED: SideTable<EntityId, IssueSettled, Named> =
    SideTable::new(&side_table::COACH_ISSUE_SETTLED);
/// Every report a durable run filed, and when, kept after the Coach settles
/// it. Key: [`by_run_key`].
const BY_RUN: SideTable<[u8; 32], u64, Raw> = SideTable::new(&side_table::COACH_BLOCKED_RUN);

/// The run's id, then the receipt's.
fn by_run_key(run: EntityId, receipt: EntityId) -> [u8; 32] {
    let mut key = [0; 32];
    key[..16].copy_from_slice(run.as_bytes());
    key[16..].copy_from_slice(receipt.as_bytes());
    key
}

/// One blocked report waiting for the Coach's Issues job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BlockedIssue {
    pub(crate) category: BlockedCategory,
    /// The actor the report was witnessed for.
    pub(crate) reporter: EntityId,
    /// The durable run that reported, when it had one.
    pub(crate) run: Option<EntityId>,
    /// The report's DIAGNOSTIC.
    pub(crate) diagnostic: EntityId,
    pub(crate) reported_at: u64,
    /// Issues runs whose decision failed on this report.
    pub(crate) retries: u8,
}

/// The proposed heal the Coach filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IssueSettled {
    pub(crate) proposal: EntityId,
    pub(crate) at: u64,
}

impl Vault {
    /// Files one witnessed report for the Coach and wakes its Issues job.
    /// Idempotent per receipt: a step re-run that witnesses the same report
    /// again files nothing new. The stored detail is measured against
    /// `limits.blocked_detail_bytes` and kept whole. The report keeps what
    /// its run's `host` knows of the run, the source its code fix replays
    /// (FIX 2343), whole and measured, in the same commit, with the worlds of
    /// the rows the run was served as its complete ledger stands there (FIX
    /// 6130).
    pub(crate) fn file_blocked_report(
        &self,
        receipt: EntityId,
        reporter: EntityId,
        run: Option<EntityId>,
        reported_at: u64,
        host: BlockedRunHost,
    ) -> Result<()> {
        {
            let txn = self.store.env.read_txn()?;
            if PENDING.contains(&self.store, &txn, &receipt)?
                || SETTLED.contains(&self.store, &txn, &receipt)?
            {
                return Ok(());
            }
        }
        let entry = ingest_report_blocked(
            self,
            BlockedReportRef {
                receipt_ref: receipt.to_hex(),
            },
        )?;
        let _ = self.measure_limit(
            EngineLimit::BlockedDetailBytes,
            entry.receipt.untrusted_detail.len() as u64,
        );
        let category = entry.receipt.category;
        let event = DiagnosticEvent {
            detector_id: format!("self_report.blocked.{}", category.as_str()),
            event_class: DiagnosticEventClass::AgentBlocked,
            signal: None,
            actor_class: "agent".into(),
            actor_ref: Some(reporter),
            source: DiagnosticSourceKind::SelfReport,
            criticality: DiagnosticCriticality::Normal,
            expected: Value::from(false),
            actual: Value::from(true),
            delta: Value::from(1),
            replay: DiagnosticReplayCoordinate {
                content_hash: *blake3::hash(entry.receipt.content()?.as_bytes()).as_bytes(),
                run_ref: run.map(|run| run.to_hex()),
                checkpoint_ref: None,
            },
            evidence_refs: vec![receipt],
            valid_from: reported_at,
            valid_to: None,
        };
        let body = encode_diagnostic_event_body(&event)?;
        let diagnostic = diagnostic_event_id(&event.detector_id, &body);
        self.emit_diagnostic_event(&diagnostic, &event)?;
        let read_worlds = host.read_worlds;
        let mut source = source::BlockedReplaySource {
            worlds: run_worlds(self, host.attempt)?,
            request: host.request,
            run_ref: host.run_ref,
            code_run: run,
            reporter,
            reported_at,
            read_worlds: None,
        };
        let _ = self.measure_limit(
            EngineLimit::MaintenanceTextBytes,
            source.longest_text() as u64,
        );
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            if PENDING.contains(&self.store, &*txn, &receipt)?
                || SETTLED.contains(&self.store, &*txn, &receipt)?
            {
                return Ok(());
            }
            PENDING.put(
                &self.store,
                txn,
                &receipt,
                &BlockedIssue {
                    category,
                    reporter,
                    run,
                    diagnostic,
                    reported_at,
                    retries: 0,
                },
            )?;
            if let Some(run) = run {
                BY_RUN.put(&self.store, txn, &by_run_key(run, receipt), &reported_at)?;
            }
            // The worlds the run was served, frozen as its read-world ledger
            // stands in this commit, when it is complete here (FIX 6130).
            source.read_worlds = run.zip(read_worlds).and_then(|(run, seal)| {
                crate::code_run::read_world_snapshot_in_txn(self, &*txn, run, seal)
            });
            source::put_in_txn(self, txn, &receipt, &source)?;
            DreamerRunnerStore::new(self).enqueue_coach_issues_in_txn(txn, None, None, now)
        })?;
        self.store.notify_attempt_observers();
        Ok(())
    }

    /// The blocked reports a durable run filed, oldest receipt first, every
    /// one. A pumped agent's run id is its attempt's id, so these are a
    /// failing attempt's own reports for the failure ladder, which re-verifies
    /// each receipt and drops what no longer reads.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn blocked_reports_of_run(&self, run: EntityId) -> Result<Vec<BlockedReportRef>> {
        let txn = self.store.env.read_txn()?;
        Ok(receipts_of_run_in(self, &txn, run)?
            .into_iter()
            .map(|receipt| BlockedReportRef {
                receipt_ref: receipt.to_hex(),
            })
            .collect())
    }
}

/// The receipts of the blocked reports the durable run `run` filed, oldest
/// first, every one: past its threshold row the read raises one check and
/// reads on.
pub(crate) fn receipts_of_run_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
) -> Result<Vec<EntityId>> {
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::BlockedRunReports,
        run.as_bytes(),
    )?;
    let mut receipts = Vec::new();
    for row in BY_RUN.iter_from(&vault.store, txn, run.as_bytes())? {
        count.row();
        let (key, _) = row?;
        let mut receipt = [0; 16];
        receipt.copy_from_slice(&key[16..]);
        receipts.push(EntityId::from_bytes(receipt)?);
    }
    count.finish(vault);
    Ok(receipts)
}

/// Whether the durable run `run` filed the report `receipt`. The record
/// outlives the Coach's settling of it.
pub(crate) fn filed_by_run_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    receipt: EntityId,
) -> Result<bool> {
    BY_RUN.contains(&vault.store, txn, &by_run_key(run, receipt))
}

/// The waiting issue filed under `receipt`, if the Coach has not settled
/// it yet. The read-side companion of [`pending_blocked_issues`] for a
/// caller's scoped inspection of one report.
pub(crate) fn blocked_issue(vault: &Vault, receipt: &EntityId) -> Result<Option<BlockedIssue>> {
    let txn = vault.store.env.read_txn()?;
    PENDING.get(&vault.store, &txn, receipt)
}

/// What the Coach already filed under `key`, if anything, in one snapshot.
pub(crate) fn settled_issue(vault: &Vault, key: &EntityId) -> Result<Option<IssueSettled>> {
    let txn = vault.store.env.read_txn()?;
    settled_in_txn(vault, &txn, key)
}

/// Up to `limit` reports waiting for the Coach after the receipt `after`
/// (from the first, with none), oldest receipt id first: one page of a read
/// its caller takes on to the end (FIX 1554).
pub(crate) fn pending_blocked_issues(
    vault: &Vault,
    after: Option<EntityId>,
    limit: usize,
) -> Result<Vec<(EntityId, BlockedIssue)>> {
    let txn = vault.store.env.read_txn()?;
    let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    PENDING
        .iter_range(&vault.store, &txn, start, Bound::Unbounded)?
        .take(limit)
        .collect()
}

/// The worlds a run's host scoped it to (FIX 2343): those of the agent
/// dispatch `attempt` it served, its scope's and its task's, or none for a
/// run its host bound to no attempt.
fn run_worlds(vault: &Vault, attempt: Option<AttemptId>) -> Result<RunWorlds> {
    let Some(attempt) = attempt else {
        return Ok(RunWorlds::Unscoped);
    };
    let txn = vault.store.env.read_txn()?;
    let Some(record) = AttemptQueue::new(vault).get_in_txn(&txn, attempt)? else {
        return Ok(RunWorlds::Unproved);
    };
    Ok(
        match crate::failure_signals::dispatch_worlds_in(vault, &txn, &record)? {
            Some(worlds) => RunWorlds::Scoped { worlds },
            None => RunWorlds::Unproved,
        },
    )
}

/// Whether any report waits for the Coach.
pub(crate) fn any_pending_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(!PENDING.scan(&vault.store, txn)?.is_empty())
}

/// Drops a waiting report whose receipt no longer reads.
pub(crate) fn drop_blocked_issue(vault: &Vault, receipt: &EntityId) -> Result<()> {
    vault.with_write_txn_grouped(|txn| PENDING.delete(&vault.store, txn, receipt).map(|_| ()))
}

/// One more failed decision on a waiting report; returns the new count.
pub(crate) fn defer_blocked_issue(vault: &Vault, receipt: &EntityId) -> Result<u8> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut issue) = PENDING.get(&vault.store, &*txn, receipt)? else {
            return Ok(0);
        };
        issue.retries = issue.retries.saturating_add(1);
        PENDING.put(&vault.store, txn, receipt, &issue)?;
        Ok(issue.retries)
    })
}

/// What the Coach already filed under `key`, if anything.
pub(crate) fn settled_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &EntityId,
) -> Result<Option<IssueSettled>> {
    SETTLED.get(&vault.store, txn, key)
}

/// Records the Coach's proposed heal under `key`, in the proposal's commit,
/// and drops the waiting report, if there was one.
pub(crate) fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &EntityId,
    proposal: EntityId,
    now: u64,
) -> Result<()> {
    PENDING.delete(&vault.store, txn, key)?;
    SETTLED.put(&vault.store, txn, key, &IssueSettled { proposal, at: now })
}

/// Records the Coach's proposal for a model finding's issue under the issue's id (OF-418 L3),
/// in the proposal's commit: the settled marker, and nothing else. The issue's row is its
/// source and stays as it was filed; this marker is what ends its wait.
pub(crate) fn record_issue_settled_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    issue: &EntityId,
    proposal: EntityId,
    now: u64,
) -> Result<()> {
    SETTLED.put(
        &vault.store,
        txn,
        issue,
        &IssueSettled { proposal, at: now },
    )
}
