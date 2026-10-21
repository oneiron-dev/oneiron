//! The Coach's heal and Issues jobs (ARCH-0066 #coach, OF-418). A host Coach
//! leases both from the `coach.heal` queue: a `coach.heal` attempt names one
//! failure-ladder case, and a `coach.issues` attempt reads the blocked
//! reports agents filed. Each case or report is asked one typed question on
//! the host's decision ladder, which fix the agent needs, and the answer
//! lands as a proposed heal in the owner's run tray, counted by the oversight
//! receipts. The Coach is propose-only: nothing here edits a skill, injects a
//! prompt, resumes a run or touches an environment, and a case the ladder
//! does not answer goes to a person. A case or report routed to `skill_edit`
//! carries a drafted revision of its skill for the owner to review
//! (`coach_repair`), a gated candidate nothing here admits. A filed heal wakes
//! the Coach's code-fix run for its case, or for its report when the report's
//! run has no failed case (OF-380), on a deployment that exports. Each
//! case's and report's route question, and the draft of its skill repair,
//! also read what the engine recorded about its cause (OF-418 L10): the
//! failing attempt's whole ancestry with its events, receipts, requests and
//! the text they read, as untrusted data beside the case or report.
use std::time::{Duration, Instant};

use rmpv::Value;
use serde_json::json;

use super::coach::COACH_ISSUES_FACET;
use super::coach_repair::{SkillRepairDraft, land_skill_repair_in_txn};
use super::proposals;
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::code_run::blocked::{BlockedReceipt, read_blocked_receipt};
use crate::dreamer_runner::{
    COACH_HEAL_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::failure_ladder::{FailureClass, HealerCase, verified_blocked_reports};
use crate::failure_signals::CodeFixSource;
use crate::limit_ask::EngineLimit;
use crate::llm::decision::catalogue::COACH_HEAL_ROUTE;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::self_heal::blocked_reports::{self, BlockedIssue};
use crate::self_heal::{DiagnosticEventClass, HealContextSeed, HealEvidenceContext};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{
    SkillEditDraft, SkillFailureContext, SkillFailureReport, SkillOptimizeBrief,
};
use crate::{EntityId, Result, Vault};

/// Predicate of a proposed heal for a failure-ladder case.
pub const COACH_HEAL_PROPOSAL_PREDICATE: &str = "coach.heal.proposal";
/// Predicate of a proposed heal for a blocked report.
pub const COACH_ISSUE_PROPOSAL_PREDICATE: &str = "coach.issue.proposal";
/// Reports one page of an Issues run reads. A page, never a cap: the run
/// reads on to the last waiting report (FIX 1554).
const ISSUES_BATCH: usize = 32;
/// A report that landed while an Issues run held its lease (FIX 1554): the
/// lease generation it landed under. Key: the run's attempt.
const REDRIVE: SideTable<AttemptId, u32, Named> = SideTable::new(&side_table::COACH_ISSUES_REDRIVE);
/// Failed decisions on one report before it goes to a person.
const ISSUE_RETRIES: u8 = 3;

/// What the Coach proposes the agent needs (ARCH-0066 #healer). The Coach
/// fixes the agent, never the task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealRoute {
    /// Edit the skill the agent ran.
    SkillEdit,
    /// Inject a prompt and fork-resume from the pre-fail checkpoint.
    PromptInject,
    /// Fix what the agent runs in: a tool, a grant, a connector.
    Environment,
    /// A person looks at it.
    Person,
}

impl HealRoute {
    const ALL: [Self; 4] = [
        Self::SkillEdit,
        Self::PromptInject,
        Self::Environment,
        Self::Person,
    ];

    /// The route's Choice option and proposal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillEdit => "skill_edit",
            Self::PromptInject => "prompt_inject",
            Self::Environment => "environment",
            Self::Person => "person",
        }
    }

    pub(super) fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|route| route.as_str() == raw)
    }
}

/// The host's decision ladder for the route question: the principal the
/// answers are for, the dial and bands they run under, the host's wording,
/// and each question's own budget.
pub struct HealDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub budget: Duration,
}

impl HealDecisions<'_> {
    /// `Ok(None)`: the ladder answered off the contract.
    fn route(
        &self,
        about: &[u8],
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> Result<Option<HealRoute>> {
        let question = COACH_HEAL_ROUTE.question(
            &[about],
            self.wording.clone(),
            AnswerContract::Choice {
                options: HealRoute::ALL
                    .iter()
                    .map(|route| route.as_str().to_owned())
                    .collect(),
            },
        )?;
        let decision = self.ladder.run(
            &question,
            self.principal,
            evidence,
            state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        Ok(match &decision.answer {
            DecisionAnswer::Choice(choice) => HealRoute::parse(choice),
            _ => None,
        })
    }

    /// The route and how it was reached. A failed or off-contract answer
    /// goes to a person.
    fn route_or_person(
        &self,
        about: &[u8],
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> (HealRoute, &'static str) {
        match self.route(about, evidence, state) {
            Ok(Some(route)) => (route, "ladder"),
            Ok(None) => (HealRoute::Person, "abstained"),
            Err(_) => (HealRoute::Person, "unanswered"),
        }
    }
}

/// The author a heal's `skill_edit` repair drafts on (OF-418 L10): the
/// optimizer's DEV-only brief of the skill, aimed at the failure, with what
/// the engine recorded about that failure's cause beside it. The cause is
/// data for the author, never an instruction, and never picks the skill:
/// the engine chose it before the author is asked.
pub trait CoachHealAuthor {
    /// Drafts the revision `brief` supports, reading `cause` as data.
    ///
    /// # Errors
    ///
    /// Implementation-defined: an author that cannot answer errors rather
    /// than invents, and the heal stays route-only.
    fn draft_skill(
        &self,
        brief: &SkillOptimizeBrief,
        cause: &HealEvidenceContext,
    ) -> Result<SkillEditDraft>;
}

/// What one Issues run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IssuesRun {
    /// Reports filed as proposed heals.
    pub proposed: usize,
    /// Reports whose decision failed; they wait for the next run.
    pub deferred: usize,
}

impl DreamerRunnerStore<'_> {
    /// Wakes the Coach's Issues job on the `coach.heal` queue. One fixed
    /// dedupe key: a queued run absorbs every report that lands before the
    /// host leases it. A report that lands while a run holds its lease marks
    /// that run's lease generation, once however many land, and the commit
    /// that settles the run queues its successor (FIX 1554).
    pub(crate) fn enqueue_coach_issues_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<AttemptId>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        let outcome = self.enqueue_kind_in_txn(
            txn,
            COACH_HEAL_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_ISSUES_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            Some(COACH_ISSUES_FACET.into()),
            run_id,
            now,
        )?;
        if let EnqueueDreamerAttemptOutcome::Existing(status) = outcome
            && matches!(
                status.attempt.state,
                AttemptState::Leased | AttemptState::Landing
            )
        {
            REDRIVE.put(
                &self.vault().store,
                txn,
                &status.attempt.id,
                &status.attempt.attempt_count,
            )?;
        }
        Ok(())
    }

    /// The successor of a settled `coach.issues` attempt, queued ready in the
    /// commit that settles it, so no crash between the two strands a report
    /// (FIX 1554): when a report landed while the attempt held its lease and
    /// reports still wait, one Issues run is queued, the settled attempt its
    /// parent (FIX 6937), lineage only. The mark goes either way. An attempt
    /// with no mark, as every other attempt is, queues nothing.
    pub(crate) fn redrive_coach_issues_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        settled: &AttemptRecord,
        now: u64,
    ) -> Result<()> {
        if settled.kind != COACH_HEAL_ATTEMPT_KIND {
            return Ok(());
        }
        let vault = self.vault();
        let Some(generation) = REDRIVE.get(&vault.store, &*txn, &settled.id)? else {
            return Ok(());
        };
        // A mark a later lease of the attempt left is that lease's to settle.
        if generation > settled.attempt_count {
            return Ok(());
        }
        REDRIVE.delete(&vault.store, txn, &settled.id)?;
        if !blocked_reports::any_pending_in_txn(vault, &*txn)? {
            return Ok(());
        }
        // No run: a run's skill-edit cycle cap would bind the successor's
        // drafts together with the settled run's (`proven_cycle`), so it keeps
        // its own cycle, as before.
        self.enqueue_coach_issues_in_txn(txn, Some(settled.id), None, now)
    }
}

impl Vault {
    /// The Coach's diagnosis of one failure-ladder case, under the leased
    /// `coach.heal` attempt the escalation woke: the route question over the
    /// case and its verified blocked reports, with what the engine recorded
    /// of its cause beside them (OF-418 L10), filed as a proposed heal. A
    /// `skill_edit` heal carries the revision `author` drafts of the case's
    /// skill, aimed at that cause too, landed as a gated candidate with the
    /// heal; a draft that went stale before the heal's write files the heal
    /// route-only, saying why (FIX 2497). A replay returns the heal already
    /// filed. Returns the proposal.
    pub fn run_coach_heal(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &HealDecisions<'_>,
        author: &dyn CoachHealAuthor,
        now: u64,
    ) -> Result<EntityId> {
        self.require_coach_attempt(attempt, COACH_HEAL_ATTEMPT_KIND)?;
        let case_ref = attempt
            .status
            .payload
            .input
            .as_str()
            .ok_or_else(super::invalid)?
            .to_owned();
        let key = EntityId::from_hex(&case_ref)?;
        let case = {
            let txn = self.store.env.read_txn()?;
            if let Some(settled) = blocked_reports::settled_in_txn(self, &txn, &key)? {
                return Ok(settled.proposal);
            }
            crate::failure_ladder::healer_case_in_txn(self, &txn, &case_ref)?
                .ok_or_else(super::invalid)?
        };
        let reports = case_reports(self, &case.blocked_reports)?;
        let mut evidence: Vec<EntityId> = EntityId::from_hex(&case.evidence_ref)
            .ok()
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
        measure_reports(self, reports.len(), longest);
        // OF-418 L10: what was recorded of the cause, beside the case.
        let cause =
            self.heal_evidence_context(decisions.principal, HealContextSeed::FailureCase(&case));
        let state = json!({
            "about": "failure_case",
            "failure_class": case.failure_class,
            "consecutive_transients": case.consecutive_transients,
            "names_skill": case.scope.skill_ref.is_some(),
            "reports": reports
                .iter()
                .map(|(_, report)| report_state(report))
                .collect::<Vec<_>>(),
            "untrusted_cause_context": cause.value(),
        });
        let (route, decided) = decisions.route_or_person(b"case", &evidence, &state);
        let repair = match route {
            HealRoute::SkillEdit => Some(self.draft_coach_skill_repair(
                &case,
                case_failure(&case, &reports),
                cause,
                author,
                attempt.status.attempt.id,
                now,
            )?),
            HealRoute::PromptInject | HealRoute::Environment | HealRoute::Person => None,
        };
        let mut value = json!({
            "case": case_ref,
            "agent": case.scope.agent_ref,
            "skill": case.scope.skill_ref,
            "failure_class": case.failure_class,
            "failing_attempt": crate::entity_id::bytes_to_hex_lower(
                case.failing_attempt_id.as_bytes()
            ),
            "route": route.as_str(),
            "decided": decided,
            "repair": repair.as_ref().map(SkillRepairDraft::value),
            "evidence": case.evidence_ref,
            "checkpoint": case.pre_fail_checkpoint_ref,
            "qa_thread": case.qa_thread_ref,
            "reports": reports
                .iter()
                .map(|(receipt, _)| receipt.to_hex())
                .collect::<Vec<_>>(),
        });
        let envelope =
            proposals::run_tray_envelope(self, COACH_HEAL_ATTEMPT_KIND, attempt.status.attempt.id)?;
        let subject = envelope.actor().entity_ref();
        self.with_write_txn_grouped(|txn| {
            if let Some(settled) = blocked_reports::settled_in_txn(self, &*txn, &key)? {
                return Ok(settled.proposal);
            }
            if let Some(repair) = &repair
                && let Some(stale) = land_skill_repair_in_txn(
                    self,
                    txn,
                    repair,
                    COACH_HEAL_ATTEMPT_KIND,
                    attempt.status.attempt.id,
                    now,
                )?
            {
                value["repair"] = stale;
            }
            let proposal = proposals::emit_in_txn(
                self,
                txn,
                subject,
                COACH_HEAL_PROPOSAL_PREDICATE,
                &value,
                &evidence,
                &envelope,
                now,
            )?;
            crate::failure_ladder::oversight::proposed_in_txn(self, txn, &case_ref, now)?;
            blocked_reports::settle_in_txn(self, txn, &key, proposal, now)?;
            super::code_fix::wake_in_txn(
                self,
                txn,
                CodeFixSource::Case {
                    case_ref: case_ref.clone(),
                },
                proposal,
                route,
                attempt.status.attempt.id,
                now,
            )?;
            Ok(proposal)
        })
    }

    /// The Coach's Issues run, under a leased `coach.issues` attempt: each
    /// waiting blocked report, oldest first, a page at a time to the last,
    /// is asked which fix its agent needs, with what was recorded of its
    /// cause beside it (OF-418 L10), and filed as a proposed heal. A
    /// `skill_edit` heal carries the revision `author` drafts of the one
    /// skill the report's run loaded, landed as a gated candidate with the
    /// heal (FIX 2496), or route-only, saying why, when the draft went stale
    /// before the heal's write (FIX 2497). A report whose decision failed
    /// waits for the next run, and its third failure goes to a person. A
    /// report whose receipt is gone leaves nothing to diagnose and drops.
    pub fn run_coach_issues(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &HealDecisions<'_>,
        author: &dyn CoachHealAuthor,
        now: u64,
    ) -> Result<IssuesRun> {
        self.require_coach_attempt(attempt, COACH_ISSUES_FACET)?;
        let envelope =
            proposals::run_tray_envelope(self, COACH_ISSUES_FACET, attempt.status.attempt.id)?;
        let pass = IssuesPass {
            attempt: attempt.status.attempt.id,
            decisions,
            author,
            subject: envelope.actor().entity_ref(),
            envelope: &envelope,
            now,
        };
        let mut run = IssuesRun::default();
        // FIX 1554: the batch is a page, and the run reads on to the end.
        let mut after = None;
        let mut read = 0usize;
        loop {
            let page = blocked_reports::pending_blocked_issues(self, after, ISSUES_BATCH)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            after = Some(*last);
            read += page.len();
            for (receipt, issue) in page {
                match self.coach_issue(&pass, receipt, &issue)? {
                    IssueOutcome::Filed => run.proposed += 1,
                    IssueOutcome::Deferred => run.deferred += 1,
                    IssueOutcome::Nothing => {}
                }
            }
        }
        let _ = self.measure_limit(EngineLimit::MaintenanceRowItems, read as u64);
        Ok(run)
    }

    /// One waiting report of an Issues run, asked and filed under `pass`.
    fn coach_issue(
        &self,
        pass: &IssuesPass<'_, '_>,
        receipt: EntityId,
        issue: &BlockedIssue,
    ) -> Result<IssueOutcome> {
        let Some(report) = read_blocked_receipt(self, &receipt)? else {
            blocked_reports::drop_blocked_issue(self, &receipt)?;
            return Ok(IssueOutcome::Nothing);
        };
        let evidence = [receipt, issue.diagnostic];
        measure_reports(self, 1, report.untrusted_detail.len());
        // OF-418 L10: what was recorded of the cause, beside the report.
        let cause = self.heal_evidence_context(
            pass.decisions.principal,
            HealContextSeed::BlockedReport {
                receipt,
                run: issue.run,
            },
        );
        let state = json!({
            "about": "blocked_report",
            "in_run": issue.run.is_some(),
            "reports": [report_state(&report)],
            "untrusted_cause_context": cause.value(),
        });
        let (route, decided) = match pass.decisions.route(b"report", &evidence, &state) {
            Ok(Some(route)) => (route, "ladder"),
            Ok(None) => (HealRoute::Person, "abstained"),
            Err(_) if issue.retries.saturating_add(1) < ISSUE_RETRIES => {
                blocked_reports::defer_blocked_issue(self, &receipt)?;
                return Ok(IssueOutcome::Deferred);
            }
            Err(_) => (HealRoute::Person, "unanswered"),
        };
        let repair = match route {
            HealRoute::SkillEdit => Some(self.draft_coach_issue_repair(
                issue,
                issue_failure(self, receipt, issue, &report)?,
                cause,
                pass.author,
                pass.attempt,
                pass.now,
            )?),
            HealRoute::PromptInject | HealRoute::Environment | HealRoute::Person => None,
        };
        let mut value = json!({
            "receipt": receipt.to_hex(),
            "diagnostic": issue.diagnostic.to_hex(),
            "category": issue.category.as_str(),
            "reporter": issue.reporter.to_hex(),
            "run": issue.run.map(|run| run.to_hex()),
            "reported_at": issue.reported_at,
            "route": route.as_str(),
            "decided": decided,
            "repair": repair.as_ref().map(SkillRepairDraft::value),
        });
        let now = pass.now;
        let filed = self.with_write_txn_grouped(|txn| {
            if blocked_reports::settled_in_txn(self, &*txn, &receipt)?.is_some() {
                return Ok(false);
            }
            if let Some(repair) = &repair
                && let Some(stale) = land_skill_repair_in_txn(
                    self,
                    txn,
                    repair,
                    COACH_ISSUES_FACET,
                    pass.attempt,
                    now,
                )?
            {
                value["repair"] = stale;
            }
            let proposal = proposals::emit_in_txn(
                self,
                txn,
                pass.subject,
                COACH_ISSUE_PROPOSAL_PREDICATE,
                &value,
                &evidence,
                pass.envelope,
                now,
            )?;
            crate::failure_ladder::oversight::proposed_in_txn(self, txn, &receipt.to_hex(), now)?;
            blocked_reports::settle_in_txn(self, txn, &receipt, proposal, now)?;
            super::code_fix::wake_blocked_in_txn(
                self,
                txn,
                receipt,
                issue.run,
                proposal,
                route,
                pass.attempt,
                now,
            )?;
            Ok(true)
        })?;
        Ok(if filed {
            IssueOutcome::Filed
        } else {
            IssueOutcome::Nothing
        })
    }
}

/// One Issues run's own inputs, which each report it reads is filed under.
struct IssuesPass<'a, 'd> {
    /// The leased `coach.issues` attempt.
    attempt: AttemptId,
    decisions: &'a HealDecisions<'d>,
    author: &'a dyn CoachHealAuthor,
    subject: EntityId,
    envelope: &'a crate::WriteEnvelope,
    now: u64,
}

/// What an Issues run did with one report.
enum IssueOutcome {
    /// Filed as a proposed heal.
    Filed,
    /// Its decision failed; it waits for the next run.
    Deferred,
    /// Dropped, its receipt gone, or already filed.
    Nothing,
}

/// The case's blocked reports that still decode, by receipt.
pub(super) fn case_reports(
    vault: &Vault,
    reports: &[crate::failure_ladder::BlockedReportRef],
) -> Result<Vec<(EntityId, BlockedReceipt)>> {
    let mut decoded = Vec::new();
    for report in reports {
        let Ok(receipt) = EntityId::from_hex(&report.receipt_ref) else {
            continue;
        };
        if let Some(body) = read_blocked_receipt(vault, &receipt)? {
            decoded.push((receipt, body));
        }
    }
    Ok(decoded)
}

/// What a case's skill repair is aimed at (FIX 2495): the case's stored
/// ladder class and every report of it that still reads, each whole.
fn case_failure(case: &HealerCase, reports: &[(EntityId, BlockedReceipt)]) -> SkillFailureContext {
    SkillFailureContext {
        failure_class: ladder_class_name(case.failure_class).to_owned(),
        category: None,
        reports: reports
            .iter()
            .map(|(receipt, report)| failure_report(*receipt, report))
            .collect(),
    }
}

/// What a blocked report's skill repair is aimed at (FIX 2495): its class,
/// `agent_blocked`, with its category, and the report, then every other
/// verified report its run filed that still reads, each whole.
fn issue_failure(
    vault: &Vault,
    receipt: EntityId,
    issue: &BlockedIssue,
    report: &BlockedReceipt,
) -> Result<SkillFailureContext> {
    let mut reports = vec![failure_report(receipt, report)];
    if let Some(run) = issue.run {
        let filed = verified_blocked_reports(vault, &vault.blocked_reports_of_run(run)?)?;
        for (other, body) in case_reports(vault, &filed)? {
            if other != receipt {
                reports.push(failure_report(other, &body));
            }
        }
    }
    Ok(SkillFailureContext {
        failure_class: DiagnosticEventClass::AgentBlocked.as_str().to_owned(),
        category: Some(issue.category.as_str().to_owned()),
        reports,
    })
}

fn failure_report(receipt: EntityId, report: &BlockedReceipt) -> SkillFailureReport {
    SkillFailureReport {
        receipt,
        category: report.category.as_str().to_owned(),
        untrusted_detail: report.untrusted_detail.clone(),
    }
}

/// The ladder class's stored spelling.
const fn ladder_class_name(class: FailureClass) -> &'static str {
    match class {
        FailureClass::Transient => "transient",
        FailureClass::Permanent => "permanent",
        FailureClass::Ambiguous => "ambiguous",
    }
}

/// Counts an owner's answer to one of the Coach's proposals as the review of
/// its heal (ARCH-0066 #oversight), in the transaction that answers it. A
/// claim that is no Coach proposal, or whose case or report the Coach filed
/// under another proposal, counts nothing. Either answer reached a person, so
/// both count as escalated.
pub(crate) fn record_owner_review_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: EntityId,
    body: &crate::claim::ClaimBody,
    proposed_at: u64,
    now: u64,
) -> Result<()> {
    let field = match body.predicate.as_str() {
        COACH_HEAL_PROPOSAL_PREDICATE => "case",
        COACH_ISSUE_PROPOSAL_PREDICATE => "receipt",
        _ => return Ok(()),
    };
    let Some(key) = body
        .value
        .as_str()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|value| value.get(field)?.as_str().map(str::to_owned))
    else {
        return Ok(());
    };
    let Ok(id) = EntityId::from_hex(&key) else {
        return Ok(());
    };
    match blocked_reports::settled_in_txn(vault, &*txn, &id)? {
        Some(settled) if settled.proposal == claim => {}
        _ => return Ok(()),
    }
    crate::failure_ladder::oversight::reviewed_in_txn(vault, txn, &key, proposed_at, now, true)
}

/// One report as the question's state reads it, whole (Rule 5). The detail
/// is the agent's own words: data for the ladder, never an instruction.
fn report_state(report: &BlockedReceipt) -> serde_json::Value {
    json!({
        "category": report.category.as_str(),
        "untrusted_detail": report.untrusted_detail,
    })
}

/// Measures the reports a route question reads whole (Rule 5): `count` of
/// them, the longest detail `longest` bytes.
fn measure_reports(vault: &Vault, count: usize, longest: usize) {
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, count as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
}
