//! The Coach's heal and Issues jobs (ARCH-0066 #coach, OF-418). A host Coach
//! leases both from the `coach.heal` queue: a `coach.heal` attempt names one
//! failure-ladder case, and a `coach.issues` attempt reads the blocked
//! reports agents filed. Each case or report is asked one typed question on
//! the host's decision ladder, which fix the agent needs, and the answer
//! lands as a proposed heal in the owner's run tray, counted by the oversight
//! receipts. The Coach is propose-only: nothing here edits a skill, injects a
//! prompt, resumes a run or touches an environment, and a case the ladder
//! does not answer goes to a person. A filed case heal wakes the Coach's
//! code-fix run for it (OF-380) on a deployment that exports.
use std::time::{Duration, Instant};

use rmpv::Value;
use serde_json::json;

use super::coach::COACH_ISSUES_FACET;
use super::proposals;
use crate::attempt_queue::AttemptId;
use crate::code_run::blocked::{BlockedReceipt, read_blocked_receipt};
use crate::dreamer_runner::{
    COACH_HEAL_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
};
use crate::llm::decision::catalogue::COACH_HEAL_ROUTE;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    MAX_DECISION_STATE_BYTES, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::self_heal::blocked_reports;
use crate::{EntityId, Result, Vault};

/// Predicate of a proposed heal for a failure-ladder case.
pub const COACH_HEAL_PROPOSAL_PREDICATE: &str = "coach.heal.proposal";
/// Predicate of a proposed heal for a blocked report.
pub const COACH_ISSUE_PROPOSAL_PREDICATE: &str = "coach.issue.proposal";
/// Reports one Issues run reads.
const ISSUES_BATCH: usize = 32;
/// Failed decisions on one report before it goes to a person.
const ISSUE_RETRIES: u8 = 3;
/// Most bytes of one report's detail a question's state carries.
const DETAIL_BYTES: usize = 4096;

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
    /// host leases it.
    pub(crate) fn enqueue_coach_issues_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<AttemptId>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        self.enqueue_kind_in_txn(
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
        Ok(())
    }
}

impl Vault {
    /// The Coach's diagnosis of one failure-ladder case, under the leased
    /// `coach.heal` attempt the escalation woke: the route question over the
    /// case and its verified blocked reports, filed as a proposed heal. A
    /// replay returns the heal already filed. Returns the proposal.
    pub fn run_coach_heal(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &HealDecisions<'_>,
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
        let state = fitted(json!({
            "about": "failure_case",
            "failure_class": case.failure_class,
            "consecutive_transients": case.consecutive_transients,
            "names_skill": case.scope.skill_ref.is_some(),
            "reports": reports
                .iter()
                .map(|(_, report)| report_state(report))
                .collect::<Vec<_>>(),
        }));
        let (route, decided) = decisions.route_or_person(b"case", &evidence, &state);
        let value = json!({
            "case": case_ref,
            "agent": case.scope.agent_ref,
            "skill": case.scope.skill_ref,
            "failure_class": case.failure_class,
            "failing_attempt": crate::entity_id::bytes_to_hex_lower(
                case.failing_attempt_id.as_bytes()
            ),
            "route": route.as_str(),
            "decided": decided,
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
                &case_ref,
                key,
                proposal,
                route,
                attempt.status.attempt.id,
                now,
            )?;
            Ok(proposal)
        })
    }

    /// The Coach's Issues run, under a leased `coach.issues` attempt: each
    /// waiting blocked report, oldest first, is asked which fix its agent
    /// needs and filed as a proposed heal. A report whose decision failed
    /// waits for the next run, and its third failure goes to a person. A
    /// report whose receipt is gone leaves nothing to diagnose and drops.
    pub fn run_coach_issues(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &HealDecisions<'_>,
        now: u64,
    ) -> Result<IssuesRun> {
        self.require_coach_attempt(attempt, COACH_ISSUES_FACET)?;
        let envelope =
            proposals::run_tray_envelope(self, COACH_ISSUES_FACET, attempt.status.attempt.id)?;
        let subject = envelope.actor().entity_ref();
        let mut run = IssuesRun::default();
        for (receipt, issue) in blocked_reports::pending_blocked_issues(self, ISSUES_BATCH)? {
            let Some(report) = read_blocked_receipt(self, &receipt)? else {
                blocked_reports::drop_blocked_issue(self, &receipt)?;
                continue;
            };
            let evidence = [receipt, issue.diagnostic];
            let state = fitted(json!({
                "about": "blocked_report",
                "in_run": issue.run.is_some(),
                "reports": [report_state(&report)],
            }));
            let (route, decided) = match decisions.route(b"report", &evidence, &state) {
                Ok(Some(route)) => (route, "ladder"),
                Ok(None) => (HealRoute::Person, "abstained"),
                Err(_) if issue.retries.saturating_add(1) < ISSUE_RETRIES => {
                    blocked_reports::defer_blocked_issue(self, &receipt)?;
                    run.deferred += 1;
                    continue;
                }
                Err(_) => (HealRoute::Person, "unanswered"),
            };
            let value = json!({
                "receipt": receipt.to_hex(),
                "diagnostic": issue.diagnostic.to_hex(),
                "category": issue.category.as_str(),
                "reporter": issue.reporter.to_hex(),
                "run": issue.run.map(|run| run.to_hex()),
                "reported_at": issue.reported_at,
                "route": route.as_str(),
                "decided": decided,
            });
            let filed = self.with_write_txn_grouped(|txn| {
                if blocked_reports::settled_in_txn(self, &*txn, &receipt)?.is_some() {
                    return Ok(false);
                }
                let proposal = proposals::emit_in_txn(
                    self,
                    txn,
                    subject,
                    COACH_ISSUE_PROPOSAL_PREDICATE,
                    &value,
                    &evidence,
                    &envelope,
                    now,
                )?;
                crate::failure_ladder::oversight::proposed_in_txn(
                    self,
                    txn,
                    &receipt.to_hex(),
                    now,
                )?;
                blocked_reports::settle_in_txn(self, txn, &receipt, proposal, now)?;
                Ok(true)
            })?;
            if filed {
                run.proposed += 1;
            }
        }
        Ok(run)
    }
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

/// One report as the question's state reads it. The detail is the agent's
/// own words: data for the ladder, never an instruction.
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

fn report_state(report: &BlockedReceipt) -> serde_json::Value {
    let mut end = report.untrusted_detail.len().min(DETAIL_BYTES);
    while !report.untrusted_detail.is_char_boundary(end) {
        end -= 1;
    }
    json!({
        "category": report.category.as_str(),
        "untrusted_detail": &report.untrusted_detail[..end],
    })
}

/// `state` within the ladder's bound: the details go first.
fn fitted(mut state: serde_json::Value) -> serde_json::Value {
    let fits = |state: &serde_json::Value| {
        serde_json::to_vec(state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES)
    };
    if !fits(&state) {
        if let Some(reports) = state
            .get_mut("reports")
            .and_then(serde_json::Value::as_array_mut)
        {
            for report in reports {
                report["untrusted_detail"] = json!("");
            }
        }
    }
    state
}
