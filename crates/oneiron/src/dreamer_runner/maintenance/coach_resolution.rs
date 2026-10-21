//! The Coach's resolution of its model issues (OF-418 L3; ARCH-0066 §6). After an Issues run
//! files the waiting issues, it reads each filed one again: the revision of its producer in
//! force now, by `issue_effective_revision`, and the judgments its evidence holds. A proved
//! repair is appended once; when the resolution policy finds the complete clean windows of
//! fresh runs it needs, the Coach files a proposed `coach.issue.resolution` through the same
//! run tray as the repair, citing the repair, its review and every window, and appends what it
//! cited. The owner confirms it or not: no count, silence or approval alone closes an issue,
//! and nothing here applies anything. The repair's review count stands for the resolution too.
use serde_json::json;

use super::coach_diagnostic::COACH_ISSUE_RESOLUTION_PREDICATE;
use super::coach_heal::IssuesPass;
use super::proposals;
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::self_heal::issue_evidence::{self, IssueResolutionPolicy, Reconcile};
use crate::self_heal::issue_work::{self, DiagnosticIssue, IssueFact};
use crate::{EntityId, Result, Vault};

/// Issue rows one page of the pass reads. A page, never a cap: the pass reads on to the last.
const RECONCILE_PAGE: usize = 32;

impl Vault {
    /// Reconciles every filed model issue's evidence in the Issues run under `pass` (OF-418
    /// L3), a page at a time to the last: a newly proved repair is appended, and an issue the
    /// resolution policy finds clean files a proposed resolution for the owner.
    pub(super) fn reconcile_issue_evidence(&self, pass: &IssuesPass<'_, '_>) -> Result<()> {
        let mut after = None;
        let mut read = 0usize;
        loop {
            let page = issue_evidence::issue_rows(self, after, RECONCILE_PAGE)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            after = Some(*last);
            read += page.len();
            for (issue_id, issue) in &page {
                self.reconcile_issue(pass, *issue_id, issue)?;
            }
        }
        let _ = self.measure_limit(EngineLimit::MaintenanceScanRows, read as u64);
        Ok(())
    }

    /// One issue's reconciliation: read first, since most issues have nothing to write, then
    /// decided again and written in one commit.
    fn reconcile_issue(
        &self,
        pass: &IssuesPass<'_, '_>,
        issue_id: EntityId,
        issue: &DiagnosticIssue,
    ) -> Result<()> {
        {
            let txn = self.store.env.read_txn()?;
            if issue_evidence::reconcile_in_txn(self, &txn, issue_id, issue, pass.now)?.is_none() {
                return Ok(());
            }
        }
        self.with_write_txn_grouped(|txn| {
            let Some(plan) =
                issue_evidence::reconcile_in_txn(self, &*txn, issue_id, issue, pass.now)?
            else {
                return Ok(());
            };
            if plan.record_repair {
                let fact = IssueFact::RepairEffective {
                    revision: plan.repair.revision.clone(),
                    from: plan.repair.from,
                    proof: plan.repair.proof.clone(),
                    at: pass.now,
                };
                issue_work::append_fact_in_txn(self, txn, issue_id, &fact)?;
            }
            if plan.windows.is_empty() {
                return Ok(());
            }
            // Every cited window goes whole: past its threshold row the write asks.
            let _ = self.measure_limit(EngineLimit::MaintenanceRowItems, plan.windows.len() as u64);
            let value = resolution_value(issue_id, issue, &plan);
            let proposal = proposals::emit_in_txn(
                self,
                txn,
                pass.subject,
                COACH_ISSUE_RESOLUTION_PREDICATE,
                &value,
                &[issue.diagnostic, plan.repair_proposal],
                pass.envelope,
                pass.now,
            )?;
            let fact = IssueFact::ResolutionProposed {
                proposal,
                revision: plan.repair.revision.clone(),
                counts_from: plan.counts_from,
                windows: plan.windows.iter().map(|(digest, _)| *digest).collect(),
                at: pass.now,
            };
            issue_work::append_fact_in_txn(self, txn, issue_id, &fact)
        })
    }
}

/// The resolution as the owner reads it, engine-authored: the issue and its finding, the
/// repair proposal and the owner's answer to it, the producer's base and the revision proved
/// in force with its proof, the policy, and every cited window whole, its runs and the
/// receipts of its decisions.
fn resolution_value(
    issue_id: EntityId,
    issue: &DiagnosticIssue,
    plan: &Reconcile,
) -> serde_json::Value {
    let policy = IssueResolutionPolicy::FreshCompleteWindow;
    let windows: Vec<_> = plan
        .windows
        .iter()
        .map(|(digest, judgment)| {
            let runs: Vec<_> = judgment
                .runs
                .iter()
                .map(|run| {
                    json!({
                        "run": bytes_to_hex_lower(&run.run),
                        "replay": bytes_to_hex_lower(&run.replay),
                        "started_at": run.started_at,
                    })
                })
                .collect();
            json!({
                "fact": bytes_to_hex_lower(digest),
                "tier": judgment.tier,
                "runs": runs,
                "decisions": serde_json::to_value(&judgment.decisions).unwrap_or_default(),
                "judged_at": judgment.at,
            })
        })
        .collect();
    let mut value = json!({
        "issue": issue_id.to_hex(),
        "diagnostic": issue.diagnostic.to_hex(),
        "family": issue.family,
        "recipe_revision": bytes_to_hex_lower(&issue.recipe_revision),
        "recurrence_key": bytes_to_hex_lower(&issue.recurrence_key),
        "producer": issue.producer.value(),
        "repair_proposal": plan.repair_proposal.to_hex(),
    });
    value["repair_review"] = json!(plan.repair_review.map(|(approved, decision)| {
        json!({ "approved": approved, "decision": bytes_to_hex_lower(&decision) })
    }));
    value["effective"] = json!({
        "revision": plan.repair.revision,
        "from": plan.repair.from,
        "proof": plan.repair.proof.value(),
    });
    value["policy"] = json!({
        "name": "fresh_complete_window",
        "min_clean_windows": policy.min_clean_windows(),
        "counts_from": plan.counts_from,
    });
    value["windows"] = json!(windows);
    value
}
