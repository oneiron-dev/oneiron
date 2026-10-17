//! Blocked reports into the Coach's Issues job (ARCH-0066 #report_blocked,
//! OF-418). A `self.report_blocked` receipt witnessed on the canonical vault
//! lands as a proposed DIAGNOSTIC (class `agent_blocked`, source
//! `self_report`) and one pending Issues row, and wakes the Coach. The report
//! is the agent's own word: it never arms the failure ladder or a tripwire,
//! and its detail stays in the fenced receipt. A report on a session overlay
//! stays off the record and files nothing.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::code_run::blocked::BlockedCategory;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::failure_ladder::{BlockedReportRef, ingest_report_blocked};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Reports waiting for the Coach. Key: the receipt.
const PENDING: SideTable<EntityId, BlockedIssue, Named> =
    SideTable::new(&side_table::COACH_BLOCKED_ISSUE);
/// What the Coach filed for a report or a case. Key: the receipt, or the case.
const SETTLED: SideTable<EntityId, IssueSettled, Named> =
    SideTable::new(&side_table::COACH_ISSUE_SETTLED);

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
    /// again files nothing new.
    pub(crate) fn file_blocked_report(
        &self,
        receipt: EntityId,
        reporter: EntityId,
        run: Option<EntityId>,
        reported_at: u64,
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
        let category = entry.receipt.category;
        let event = DiagnosticEvent {
            detector_id: format!("self_report.blocked.{}", category.as_str()),
            event_class: DiagnosticEventClass::AgentBlocked,
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
            DreamerRunnerStore::new(self).enqueue_coach_issues_in_txn(txn, None, None, now)
        })?;
        self.store.notify_attempt_observers();
        Ok(())
    }
}

/// Up to `limit` reports waiting for the Coach, oldest receipt id first.
pub(crate) fn pending_blocked_issues(
    vault: &Vault,
    limit: usize,
) -> Result<Vec<(EntityId, BlockedIssue)>> {
    let txn = vault.store.env.read_txn()?;
    Ok(PENDING
        .scan(&vault.store, &txn)?
        .into_iter()
        .take(limit)
        .collect())
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
