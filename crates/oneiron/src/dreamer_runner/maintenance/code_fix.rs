//! The Coach's code fixes (DEC-0005 FIX6, OF-380). Once the Coach files a
//! heal for a failure case, or for a blocked report whose run has no failed
//! case, on a deployment that exports, a `coach.code_fix`
//! attempt on the `coach.heal` queue asks it for two things, both made and
//! checked inside the vault: an invented example of the failure (a short
//! general note and a made-up conversation that fails the same way), and,
//! for a skill or prompt heal, the shadow result of the instruction it would
//! add, replayed against the real failure. Each candidate the deployment's
//! publisher supplied, pinned by the operator, is replayed against the same
//! failure beside it; one pinned after a failure settled is replayed against
//! it once, in a catch-up over past work after the host starts. The host's
//! model drafts and
//! replays with no tools; every judgment (the failure's class, does a replay
//! fail the same way, did the candidate fix it, may the example leave) is a
//! typed question on the host's decision ladder. The export doors in
//! `failure_signals` decide what leaves, and the failure's work row keeps
//! each verdict here after the export queue drains.
use std::cell::OnceCell;
use std::ops::Bound;
use std::time::{Duration, Instant};

use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::coach::COACH_CODE_FIX_FACET;
use super::coach_heal::{HealRoute, case_reports};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    COACH_HEAL_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
};
use crate::failure_ladder::{BlockedReportRef, HealerCase};
use crate::failure_signals::{
    CandidateFix, CodeFixReplay, CodeFixSource, CodeFixVerdict, CodeFixWithheld, ExportScrubber,
    FailureClassV1, FailureSource, FixOutcome, InventedExampleDraft, InventedMessage, InventedRole,
    ReplayRun, ScrubRun, ShadowRun, code_fix_subject_in, failed_case_in,
};
use crate::llm::decision::catalogue::CODE_FIX_JUDGMENT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    MAX_DECISION_STATE_BYTES, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Key: [`work_key`].
const WORK: SideTable<EntityId, CodeFixWork, Named> =
    SideTable::new(&side_table::FAILURE_SIGNALS_CODE_FIX_WORK);
/// Domain separator for a blocked report's work key.
const BLOCKED_WORK_DOMAIN: &[u8] = b"oneiron.code-fix.blocked.v1\0";
/// Blocked reports one job carries.
const JOB_REPORTS: usize = 8;
/// Most work rows one owner read returns.
pub const MAX_CODE_FIX_WORK: usize = 256;
/// Work rows one catch-up step reads, and top-up runs it queues: a newly
/// pinned candidate reaches past failures a few at a time.
const TOP_UP_SCAN: usize = 256;
const TOP_UP_QUEUE: usize = 2;
/// Most bytes of one report's detail, one message, or one other text a
/// question's state carries.
const DETAIL_BYTES: usize = 1024;
const MESSAGE_BYTES: usize = 768;
const TEXT_BYTES: usize = 4096;

const CLASSES: [FailureClassV1; 9] = [
    FailureClassV1::RefusalOverreach,
    FailureClassV1::TaskFailure,
    FailureClassV1::UserFrustration,
    FailureClassV1::MemoryMiss,
    FailureClassV1::MemoryIntrusion,
    FailureClassV1::PersonaBreak,
    FailureClassV1::LatencyAbandon,
    FailureClassV1::SilentDegradation,
    FailureClassV1::Other,
];
const CLASS_WORDING: &str = "Which kind of failure is this? refusal_overreach: the agent \
    refused what it should have done; task_failure: it did not get its task done; \
    user_frustration: it left the person frustrated; memory_miss: it missed something it \
    should have remembered; memory_intrusion: it brought up something it should have left \
    alone; persona_break: it broke its character or voice; latency_abandon: it took so long \
    the work was given up; silent_degradation: its work got worse with no error; other: none \
    of these.";
const REPRODUCED_WORDING: &str = "Does the reply fail the way the failure describes?";
const FIXED_WORDING: &str = "The reply before failed the way the failure describes. Does the \
    reply after no longer fail that way?";
const SAFE_WORDING: &str = "Is this text plainly made up, with no real person's name, contact \
    detail, account, address, private fact or secret in it?";

/// One failure's code-fix work and its local verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFixWork {
    /// The case, or the blocked report.
    pub source: CodeFixSource,
    /// The proposed heal the work follows.
    pub proposal: EntityId,
    /// The heal's route.
    pub route: String,
    pub queued_at: u64,
    pub settled: Option<CodeFixSettled>,
}

/// What one code-fix run found, kept in the vault whatever left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFixSettled {
    pub at: u64,
    pub failure_class: FailureClassV1,
    /// The invented example's verdict.
    pub example: CodeFixVerdict,
    /// Each candidate's shadow replay: the Coach's own for a skill or prompt
    /// heal first, then each publisher candidate.
    pub candidates: Vec<CandidateRun>,
}

/// One candidate's shadow replay: its outcome and its export's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRun {
    pub candidate_id: String,
    /// `None` when the replay could not run, or did not fail before the fix.
    pub outcome: Option<FixOutcome>,
    pub export: CodeFixVerdict,
}

/// What the Coach drafts for: the case or blocked report, its class and the
/// real failure. It stays inside the vault's boundary.
#[derive(Debug, Clone)]
pub struct CodeFixJob {
    pub origin: CodeFixSource,
    pub route: HealRoute,
    pub failure_class: FailureClassV1,
    pub source: FailureSource,
    /// The failure's blocked reports: each one's category and the agent's
    /// own words, data and never an instruction.
    pub reports: Vec<serde_json::Value>,
}

/// What the Coach drafted for one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFixDraft {
    /// A short general note on the failure.
    pub note: String,
    /// A made-up conversation that fails the same way.
    pub conversation: Vec<InventedMessage>,
    /// For a skill or prompt heal: the instruction the agent would get.
    pub fix: Option<String>,
}

/// A candidate fix the deployment's publisher supplied and its operator
/// pinned: an instruction the replay adds to the failing agent's own. It is
/// tried in the vault only; nothing installs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherCandidate {
    /// The token its result exports under, naming the pinned artifact.
    pub id: String,
    pub instruction: String,
}

/// The host's models, inside the vault's boundary.
pub trait CodeFixHost {
    /// The Coach's draft for `job`; `Ok(None)` when it drafted nothing usable.
    fn draft(&self, job: &CodeFixJob) -> Result<Option<CodeFixDraft>>;
    /// One turn of the failing agent with no tools, so nothing it says can
    /// act: `system`, then `conversation`. `Ok(None)` when no model runs it.
    fn reply(&self, system: &str, conversation: &[InventedMessage]) -> Result<Option<String>>;
    /// The publisher's pinned candidates, each replayed against every case.
    fn publisher_candidates(&self) -> &[PublisherCandidate] {
        &[]
    }
}

/// The host's decision ladder for the code-fix checks: the principal the
/// answers are for, the dial and bands they run under, and each question's
/// own budget.
pub struct CodeFixDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub budget: Duration,
}

impl CodeFixDecisions<'_> {
    fn ask(
        &self,
        check: &str,
        wording: &str,
        contract: AnswerContract,
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> Result<DecisionAnswer> {
        let question =
            CODE_FIX_JUDGMENT.question(&[check.as_bytes()], wording.to_owned(), contract)?;
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
        Ok(decision.answer)
    }

    /// A yes or no; `None` when the state does not fit, or the ladder failed,
    /// abstained or answered off the contract.
    fn yes(
        &self,
        check: &str,
        wording: &str,
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> Option<bool> {
        if !fits(state) {
            return None;
        }
        match self.ask(check, wording, AnswerContract::Noul, evidence, state) {
            Ok(DecisionAnswer::Noul(yes)) => Some(yes),
            _ => None,
        }
    }

    /// The failure's class. An abstention or an off-contract answer is
    /// `Other`; a failed ladder waits for the next lease.
    fn class(&self, evidence: &[EntityId], state: &serde_json::Value) -> Result<FailureClassV1> {
        let options = CLASSES
            .iter()
            .map(|class| class_name(*class).to_owned())
            .collect();
        Ok(
            match self.ask(
                "class",
                CLASS_WORDING,
                AnswerContract::Choice { options },
                evidence,
                state,
            )? {
                DecisionAnswer::Choice(choice) => CLASSES
                    .into_iter()
                    .find(|class| class_name(*class) == choice)
                    .unwrap_or(FailureClassV1::Other),
                _ => FailureClassV1::Other,
            },
        )
    }
}

/// The Coach's in-vault replay of one job: the failing agent's call rebuilt
/// from the real failure, run with no tools, judged on the ladder.
struct CoachReplay<'a> {
    job: &'a CodeFixJob,
    host: &'a dyn CodeFixHost,
    decisions: &'a CodeFixDecisions<'a>,
    evidence: &'a [EntityId],
    /// Each candidate's id and the instruction it adds.
    candidates: Vec<(String, String)>,
    /// The real failing call and the agent's reply to it, once a replay
    /// reproduced the failure; `None` when it did not, or could not run.
    baseline: OnceCell<Option<(Vec<InventedMessage>, String)>>,
}

impl CoachReplay<'_> {
    fn failure_state(&self, note: Option<&str>) -> serde_json::Value {
        json!({
            "failure_class": class_name(self.job.failure_class),
            "reports": self.job.reports,
            "note": note,
        })
    }

    /// Does `reply` to `conversation` fail the way the case did?
    fn fails(
        &self,
        note: Option<&str>,
        conversation: &[InventedMessage],
        reply: &str,
    ) -> Option<bool> {
        let state = json!({
            "failure": self.failure_state(note),
            "conversation": conversation_state(conversation),
            "reply": clip(reply, TEXT_BYTES),
        });
        self.decisions
            .yes("reproduced", REPRODUCED_WORDING, self.evidence, &state)
    }

    /// The real failing call: what the agent was briefed on and asked.
    fn real_conversation(&self) -> Option<Vec<InventedMessage>> {
        let source = &self.job.source;
        let text = [source.briefing.as_deref(), source.task.as_deref()]
            .into_iter()
            .flatten()
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        (!text.is_empty()).then(|| {
            vec![InventedMessage {
                role: InventedRole::User,
                text,
            }]
        })
    }

    /// The real failing call replayed once for every candidate. A failure the
    /// replay does not reproduce cannot say whether a candidate fixed it.
    fn baseline(&self) -> Result<Option<&(Vec<InventedMessage>, String)>> {
        if let Some(baseline) = self.baseline.get() {
            return Ok(baseline.as_ref());
        }
        let ran = match self.real_conversation() {
            None => None,
            Some(conversation) => self
                .host
                .reply(&self.job.source.instructions, &conversation)?
                .filter(|before| self.fails(None, &conversation, before) == Some(true))
                .map(|before| (conversation, before)),
        };
        Ok(self.baseline.get_or_init(|| ran).as_ref())
    }
}

impl CodeFixReplay for CoachReplay<'_> {
    fn reproduces(
        &self,
        _failure: &FailureSource,
        example: &InventedExampleDraft,
    ) -> Result<ReplayRun> {
        // The live agent answers in place of the invented failing turn.
        let Some(last) = example
            .conversation
            .iter()
            .rposition(|message| message.role == InventedRole::User)
        else {
            return Ok(ReplayRun::Unavailable);
        };
        let conversation = &example.conversation[..=last];
        let Some(reply) = self
            .host
            .reply(&self.job.source.instructions, conversation)?
        else {
            return Ok(ReplayRun::Unavailable);
        };
        Ok(
            match self.fails(Some(&example.note), conversation, &reply) {
                Some(true) => ReplayRun::Reproduced,
                Some(false) => ReplayRun::NotReproduced,
                None => ReplayRun::Unavailable,
            },
        )
    }

    fn shadow_replay(&self, _failure: &FailureSource, candidate_id: &str) -> Result<ShadowRun> {
        let Some((_, fix)) = self.candidates.iter().find(|(id, _)| id == candidate_id) else {
            return Ok(ShadowRun::Unavailable);
        };
        let Some((conversation, before)) = self.baseline()? else {
            return Ok(ShadowRun::Unavailable);
        };
        let instructions = &self.job.source.instructions;
        let system = [instructions.as_str(), fix.as_str()]
            .into_iter()
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        let Some(after) = self.host.reply(&system, conversation)? else {
            return Ok(ShadowRun::Unavailable);
        };
        let state = json!({
            "failure": self.failure_state(None),
            "conversation": conversation_state(conversation),
            "before": clip(before, TEXT_BYTES),
            "after": clip(&after, TEXT_BYTES),
        });
        Ok(
            match self
                .decisions
                .yes("fixed", FIXED_WORDING, self.evidence, &state)
            {
                Some(true) => ShadowRun::Fixed,
                Some(false) => ShadowRun::NotFixed,
                None => ShadowRun::Unavailable,
            },
        )
    }
}

/// The in-vault scrubber: one typed question over the whole text. A text
/// too long to ask about whole is not judged.
struct CoachScrubber<'a> {
    decisions: &'a CodeFixDecisions<'a>,
    evidence: &'a [EntityId],
}

impl ExportScrubber for CoachScrubber<'_> {
    fn scrub(&self, text: &str) -> Result<ScrubRun> {
        let state = json!({ "text": text });
        Ok(
            match self
                .decisions
                .yes("export_safe", SAFE_WORDING, self.evidence, &state)
            {
                Some(true) => ScrubRun::Clean,
                Some(false) => ScrubRun::Flagged,
                None => ScrubRun::Unavailable,
            },
        )
    }
}

/// A shadow replay already run, handed to the export door so the candidate
/// runs once.
struct Ran(ShadowRun);

impl CodeFixReplay for Ran {
    fn reproduces(
        &self,
        _failure: &FailureSource,
        _example: &InventedExampleDraft,
    ) -> Result<ReplayRun> {
        Ok(ReplayRun::Unavailable)
    }

    fn shadow_replay(&self, _failure: &FailureSource, _candidate_id: &str) -> Result<ShadowRun> {
        Ok(self.0)
    }
}

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
pub(super) fn wake_in_txn(
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

/// Queues the `coach.code_fix` attempt for the work row `key`. One waiting
/// attempt per row: a second enqueue finds the first.
fn enqueue_run_in_txn(
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

/// The candidates of `pinned` that `settled` holds no run of, each as its id
/// and instruction.
fn untried(settled: &CodeFixSettled, pinned: &[PublisherCandidate]) -> Vec<(String, String)> {
    pinned
        .iter()
        .filter(|candidate| {
            !settled
                .candidates
                .iter()
                .any(|run| run.candidate_id == candidate.id)
        })
        .map(|candidate| (candidate.id.clone(), candidate.instruction.clone()))
        .collect()
}

/// Each of `candidates` kept as not run, for `reason`: it is not tried again.
fn not_run(candidates: &[(String, String)], reason: CodeFixWithheld) -> Vec<CandidateRun> {
    candidates
        .iter()
        .map(|(candidate_id, _)| CandidateRun {
            candidate_id: candidate_id.clone(),
            outcome: None,
            export: CodeFixVerdict::Withheld { reason },
        })
        .collect()
}

/// The failure's evidence for its questions (the case's own and each report
/// it still reads), and its reports as those questions read them.
fn failure_context(
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
    let reports = reports
        .iter()
        .take(JOB_REPORTS)
        .map(|(_, report)| {
            json!({
                "category": report.category.as_str(),
                "untrusted_detail": clip(&report.untrusted_detail, DETAIL_BYTES),
            })
        })
        .collect();
    Ok((evidence, reports))
}

/// Queues the Coach's code-fix run for a blocked report it just filed a heal
/// for (OF-380). A report with no durable run names no failure to replay. A
/// report whose run's attempt has a failed case gets none of its own: that
/// case's heal queues the run for the same failure.
#[allow(clippy::too_many_arguments)]
pub(super) fn wake_blocked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: EntityId,
    run: Option<EntityId>,
    proposal: EntityId,
    route: HealRoute,
    parent: AttemptId,
    now: u64,
) -> Result<()> {
    let Some(run) = run else {
        return Ok(());
    };
    let case_ref = crate::failure_ladder::failure_case_ref(AttemptId::from_bytes(run.as_bytes())?);
    if failed_case_in(vault, txn, &case_ref)?.is_some() {
        return Ok(());
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

impl Vault {
    /// The Coach's code-fix work for the owner, newest queued first, at most
    /// `limit` (capped at [`MAX_CODE_FIX_WORK`]): each case's or blocked
    /// report's heal and, once
    /// its run settled, the failure's class, the invented example's verdict
    /// and each candidate's shadow result. No text of the failure is in it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn code_fix_work(&self, limit: usize) -> Result<Vec<CodeFixWork>> {
        let txn = self.store.env.read_txn()?;
        let mut rows: Vec<CodeFixWork> = WORK
            .iter_from(&self.store, &txn, &[])?
            .map(|row| row.map(|(_, work)| work))
            .collect::<Result<_>>()?;
        rows.sort_by(|a, b| b.queued_at.cmp(&a.queued_at));
        rows.truncate(limit.min(MAX_CODE_FIX_WORK));
        Ok(rows)
    }

    /// One step of the catch-up that tries publisher candidates pinned after
    /// a failure settled on that failure (OF-380): reads up to 256 work rows
    /// after `after` and queues a top-up run for at most 2 settled ones with
    /// no run of some id in `pinned`. Returns the key the next step goes on
    /// after, or `None` once the last row is read. A deployment that does not
    /// export queues nothing.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn queue_code_fix_top_ups(
        &self,
        after: Option<EntityId>,
        pinned: &[&str],
        now: u64,
    ) -> Result<Option<EntityId>> {
        if pinned.is_empty() || !self.config.failure_signals.exports() {
            return Ok(None);
        }
        self.with_write_txn_grouped(|txn| {
            let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
            let rows: Vec<(EntityId, CodeFixWork)> = WORK
                .iter_range(&self.store, &*txn, start, Bound::Unbounded)?
                .take(TOP_UP_SCAN)
                .collect::<Result<_>>()?;
            let mut next = (rows.len() == TOP_UP_SCAN)
                .then(|| rows.last().map(|(key, _)| *key))
                .flatten();
            let mut queued = 0;
            for (key, work) in &rows {
                let Some(settled) = &work.settled else {
                    continue;
                };
                let lacks = pinned
                    .iter()
                    .any(|id| !settled.candidates.iter().any(|run| run.candidate_id == *id));
                if !lacks {
                    continue;
                }
                enqueue_run_in_txn(self, txn, *key, None, now)?;
                queued += 1;
                if queued == TOP_UP_QUEUE {
                    next = Some(*key);
                    break;
                }
            }
            Ok(next)
        })
    }

    /// The Coach's code-fix run for one case or blocked report, under its leased
    /// `coach.code_fix` attempt: the failure's class, the Coach's draft, the
    /// invented example through its export door, and the candidate's shadow
    /// replay, kept here and sent through its own door. A replay returns what
    /// the first run kept, with a run of each pinned publisher candidate it
    /// had none of.
    pub fn run_coach_code_fix(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &CodeFixDecisions<'_>,
        host: &dyn CodeFixHost,
        now: u64,
    ) -> Result<CodeFixSettled> {
        self.require_coach_attempt(attempt, COACH_CODE_FIX_FACET)?;
        let key = EntityId::from_hex(
            attempt
                .status
                .payload
                .input
                .as_str()
                .ok_or_else(super::invalid)?,
        )?;
        let work = {
            let txn = self.store.env.read_txn()?;
            WORK.get(&self.store, &txn, &key)?
                .ok_or_else(super::invalid)?
        };
        let route = HealRoute::parse(&work.route).ok_or_else(super::invalid)?;
        if let Some(settled) = work.settled {
            let missing = untried(&settled, host.publisher_candidates());
            if missing.is_empty() || !self.config.failure_signals.exports() {
                return Ok(settled);
            }
            let runs =
                self.code_fix_top_up(&work.source, route, &settled, &missing, decisions, host)?;
            return self.with_write_txn_grouped(|txn| {
                let mut work = WORK
                    .get(&self.store, &*txn, &key)?
                    .ok_or_else(super::invalid)?;
                let mut settled = work.settled.take().ok_or_else(super::invalid)?;
                for run in &runs {
                    if !settled
                        .candidates
                        .iter()
                        .any(|kept| kept.candidate_id == run.candidate_id)
                    {
                        settled.candidates.push(run.clone());
                    }
                }
                work.settled = Some(settled.clone());
                WORK.put(&self.store, txn, &key, &work)?;
                Ok(settled)
            });
        }
        let settled = self.code_fix_run(&work.source, route, decisions, host, now)?;
        self.with_write_txn_grouped(|txn| {
            let mut work = WORK
                .get(&self.store, &*txn, &key)?
                .ok_or_else(super::invalid)?;
            if let Some(first) = work.settled {
                return Ok(first);
            }
            work.settled = Some(settled.clone());
            WORK.put(&self.store, txn, &key, &work)?;
            Ok(settled)
        })
    }

    fn code_fix_run(
        &self,
        source: &CodeFixSource,
        route: HealRoute,
        decisions: &CodeFixDecisions<'_>,
        host: &dyn CodeFixHost,
        now: u64,
    ) -> Result<CodeFixSettled> {
        let withheld = |failure_class, reason| CodeFixSettled {
            at: now,
            failure_class,
            example: CodeFixVerdict::Withheld { reason },
            candidates: Vec::new(),
        };
        if !self.config.failure_signals.exports() {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::NotEligible,
            ));
        }
        let found = {
            let txn = self.store.env.read_txn()?;
            code_fix_subject_in(self, &txn, source)?
        };
        let Some(subject) = found else {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::UnknownCase,
            ));
        };
        let Some((failure, _)) = subject.failure else {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::PrivateWorld,
            ));
        };
        let case = subject.case.as_ref();
        let (evidence, reports) = failure_context(self, case, &subject.reports)?;
        // A blocked report with no case has no ladder class and names no
        // skill the ladder saw.
        let about = if case.is_some() {
            "failure_case"
        } else {
            "blocked_report"
        };
        let class_state = json!({
            "about": about,
            "failure_ladder_class": case.map(|case| &case.failure_class),
            "names_skill": case.map(|case| case.scope.skill_ref.is_some()),
            "reports": reports,
            "briefing": failure.briefing.as_deref().map(|text| clip(text, TEXT_BYTES)),
            "task": failure.task.as_deref().map(|text| clip(text, TEXT_BYTES)),
        });
        let failure_class = decisions.class(&evidence, &class_state)?;
        let job = CodeFixJob {
            origin: source.clone(),
            route,
            failure_class,
            source: failure,
            reports,
        };
        let draft = host.draft(&job)?;
        let own = match (route, &draft) {
            (HealRoute::SkillEdit | HealRoute::PromptInject, Some(draft)) => draft
                .fix
                .clone()
                .filter(|fix| !fix.trim().is_empty())
                .map(|fix| (format!("coach.{}", route.as_str()), fix)),
            _ => None,
        };
        // A publisher candidate needs no draft of the Coach's: it is replayed
        // against the real failure whatever the heal's route.
        let candidates: Vec<(String, String)> = own
            .into_iter()
            .chain(
                host.publisher_candidates()
                    .iter()
                    .map(|candidate| (candidate.id.clone(), candidate.instruction.clone())),
            )
            .collect();
        if draft.is_none() && candidates.is_empty() {
            return Ok(withheld(failure_class, CodeFixWithheld::NotDrafted));
        }
        let replay = CoachReplay {
            job: &job,
            host,
            decisions,
            evidence: &evidence,
            candidates,
            baseline: OnceCell::new(),
        };
        let scrubber = CoachScrubber {
            decisions,
            evidence: &evidence,
        };
        let example = match draft {
            Some(draft) => self.prepare_invented_example(
                source,
                InventedExampleDraft {
                    failure_class,
                    note: draft.note,
                    conversation: draft.conversation,
                },
                &replay,
                &scrubber,
            )?,
            None => CodeFixVerdict::Withheld {
                reason: CodeFixWithheld::NotDrafted,
            },
        };
        let candidates = self.replay_candidates(source, &replay, &example)?;
        Ok(CodeFixSettled {
            at: now,
            failure_class,
            example,
            candidates,
        })
    }

    /// The runs of `missing`, publisher candidates a settled run never
    /// tried, each replayed once against the failure and sent through its
    /// door. The first run's class and example stand. A failure that no longer
    /// stands, or whose text cannot be read, keeps each as not run.
    fn code_fix_top_up(
        &self,
        source: &CodeFixSource,
        route: HealRoute,
        settled: &CodeFixSettled,
        missing: &[(String, String)],
        decisions: &CodeFixDecisions<'_>,
        host: &dyn CodeFixHost,
    ) -> Result<Vec<CandidateRun>> {
        let found = {
            let txn = self.store.env.read_txn()?;
            code_fix_subject_in(self, &txn, source)?
        };
        let Some(subject) = found else {
            return Ok(not_run(missing, CodeFixWithheld::UnknownCase));
        };
        let Some((failure, _)) = subject.failure else {
            return Ok(not_run(missing, CodeFixWithheld::PrivateWorld));
        };
        let (evidence, reports) = failure_context(self, subject.case.as_ref(), &subject.reports)?;
        let job = CodeFixJob {
            origin: source.clone(),
            route,
            failure_class: settled.failure_class,
            source: failure,
            reports,
        };
        let replay = CoachReplay {
            job: &job,
            host,
            decisions,
            evidence: &evidence,
            candidates: missing.to_vec(),
            baseline: OnceCell::new(),
        };
        self.replay_candidates(source, &replay, &settled.example)
    }

    /// Each of the replay's candidates shadow-replayed against the real
    /// failure, its result sent through its door beside `example`'s record.
    fn replay_candidates(
        &self,
        source: &CodeFixSource,
        replay: &CoachReplay<'_>,
        example: &CodeFixVerdict,
    ) -> Result<Vec<CandidateRun>> {
        let example_id = match example {
            CodeFixVerdict::Queued { id } => Some(id.clone()),
            CodeFixVerdict::Withheld { .. } => None,
        };
        let failure_class = replay.job.failure_class;
        let mut candidates = Vec::with_capacity(replay.candidates.len());
        for (candidate_id, _) in &replay.candidates {
            let shadow = replay.shadow_replay(&replay.job.source, candidate_id)?;
            let outcome = match shadow {
                ShadowRun::Fixed => Some(FixOutcome::Fixed),
                ShadowRun::NotFixed => Some(FixOutcome::NotFixed),
                ShadowRun::Unavailable => None,
            };
            let export = self.record_candidate_fix_result(
                source,
                CandidateFix {
                    candidate_id: candidate_id.clone(),
                    example_id: example_id.clone(),
                    failure_class,
                },
                &Ran(shadow),
            )?;
            candidates.push(CandidateRun {
                candidate_id: candidate_id.clone(),
                outcome,
                export,
            });
        }
        Ok(candidates)
    }
}

/// The class's export spelling, which is also its Choice option.
const fn class_name(class: FailureClassV1) -> &'static str {
    match class {
        FailureClassV1::RefusalOverreach => "refusal_overreach",
        FailureClassV1::TaskFailure => "task_failure",
        FailureClassV1::UserFrustration => "user_frustration",
        FailureClassV1::MemoryMiss => "memory_miss",
        FailureClassV1::MemoryIntrusion => "memory_intrusion",
        FailureClassV1::PersonaBreak => "persona_break",
        FailureClassV1::LatencyAbandon => "latency_abandon",
        FailureClassV1::SilentDegradation => "silent_degradation",
        FailureClassV1::Other => "other",
    }
}

fn conversation_state(conversation: &[InventedMessage]) -> Vec<serde_json::Value> {
    conversation
        .iter()
        .map(|message| json!({ "role": message.role, "text": clip(&message.text, MESSAGE_BYTES) }))
        .collect()
}

/// At most `bytes` of `text`, cut on a character boundary.
fn clip(text: &str, bytes: usize) -> &str {
    let mut end = text.len().min(bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn fits(state: &serde_json::Value) -> bool {
    serde_json::to_vec(state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES)
}
