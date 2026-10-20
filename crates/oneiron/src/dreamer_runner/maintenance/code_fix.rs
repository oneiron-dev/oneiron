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
//! model drafts and replays with no tool run. A replay sends the request the
//! failing call sent when the vault kept it (FIX 1662), its tool
//! declarations kept, and rebuilds the call from the failure's text only
//! when it did not or the host cannot send it; each candidate's run says
//! which. Every judgment (the failure's class, does a replay
//! fail the same way, did the candidate fix it, may the example leave) is a
//! typed question on the host's decision ladder. The export doors in
//! `failure_signals` decide what leaves, and the failure's work row keeps
//! each verdict here after the export queue drains. Each record is queued in
//! the write that keeps its verdict in the row, and a failure gets one run:
//! a case whose run's blocked report already has a run gets none of its own.
//! A blocked report whose run is no agent dispatch's attempt, or that has no
//! durable run, replays from the source its run's host kept (FIX 2343); one
//! whose caller never gave this engine a model request keeps its work, its
//! replay unavailable. Every text a question reads goes whole, measured.
use std::cell::RefCell;
use std::ops::Bound;
use std::rc::Rc;
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
use crate::failure_ladder::{BlockedReportRef, HealerCase, healer_case_in_txn};
use crate::failure_signals::{
    CandidateFix, CodeFixReplay, CodeFixSource, CodeFixVerdict, CodeFixWithheld,
    ExactReplayRequest, ExportScrubber, FailureClassV1, FailureSource, FixOutcome,
    InventedExampleDraft, InventedMessage, InventedRole, ReplayFidelity, ReplayRun, ScrubRun,
    SealedCodeFix, Sealing, ShadowRun, code_fix_subject_in, exact_replay_request, failed_case_in,
    queue_sealed_in_txn,
};
use crate::limit_ask::EngineLimit;
use crate::llm::decision::catalogue::CODE_FIX_JUDGMENT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
use crate::{ContentPart, EntityId, LlmMessage, LlmMessageRole, LlmRequest, Result, Vault};

/// Key: [`work_key`].
const WORK: SideTable<EntityId, CodeFixWork, Named> =
    SideTable::new(&side_table::FAILURE_SIGNALS_CODE_FIX_WORK);
/// Domain separator for a blocked report's work key.
const BLOCKED_WORK_DOMAIN: &[u8] = b"oneiron.code-fix.blocked.v1\0";
/// Work rows one owner read returns when its caller names no limit.
pub const MAX_CODE_FIX_WORK: usize = 256;
/// Work rows one catch-up step reads, and top-up runs it queues: a newly
/// pinned candidate reaches past failures a few at a time.
const TOP_UP_SCAN: usize = 256;
const TOP_UP_QUEUE: usize = 2;

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
    /// How the replay ran the real failure (FIX 1662): the request the
    /// failing call sent, or a call rebuilt from its text. `None` when it
    /// could not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayFidelity>,
}

/// A candidate's run and the record it sealed, queued in the write that
/// keeps the run.
type SealedRun = (CandidateRun, Option<SealedCodeFix>);

/// A first run's result, its records sealed and not yet queued.
struct Unkept {
    at: u64,
    failure_class: FailureClassV1,
    example: Sealing,
    candidates: Vec<SealedRun>,
}

/// What the Coach drafts for: the case or blocked report, its class and the
/// real failure. It stays inside the vault's boundary.
#[derive(Debug, Clone)]
pub struct CodeFixJob {
    pub origin: CodeFixSource,
    pub route: HealRoute,
    pub failure_class: FailureClassV1,
    pub source: FailureSource,
    /// The failure's blocked reports, every one: each one's category and
    /// the agent's own words, whole, data and never an instruction.
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
    /// The failing agent's call sent again as the vault kept it (FIX 1662):
    /// `request` whole, its tool declarations kept and no tool its answer
    /// names run, so nothing it says can act. `Ok(None)` when no model sends
    /// it as kept; the replay then rebuilds the call from the failure's text.
    fn reply_exact(&self, _request: &ExactReplayRequest) -> Result<Option<String>> {
        Ok(None)
    }
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

    /// A yes or no; `None` when the ladder failed, abstained or answered off
    /// the contract.
    fn yes(
        &self,
        check: &str,
        wording: &str,
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> Option<bool> {
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

/// The Coach's in-vault replay of one job: the failing agent's call as the
/// vault kept it, or rebuilt from the real failure, run with no tool run,
/// judged on the ladder.
struct CoachReplay<'a> {
    /// Where the texts its questions read whole are measured.
    vault: &'a Vault,
    job: &'a CodeFixJob,
    host: &'a dyn CodeFixHost,
    decisions: &'a CodeFixDecisions<'a>,
    evidence: &'a [EntityId],
    /// Each candidate's id and the instruction it adds.
    candidates: Vec<(String, String)>,
    /// The request the failing call sent, as the vault kept it (FIX 1662),
    /// dropped once its copy is gone (FIX 6659): it is never sent again.
    exact: RefCell<Option<ExactReplayRequest>>,
    /// The real failing call and the agent's reply to it, once a replay
    /// reproduced the failure; `None` when it did not, or could not run.
    /// One the kept request ran is dropped with it (FIX 6659).
    baseline: RefCell<Option<Option<Rc<Baseline>>>>,
}

/// The real failing call replayed: the conversation its questions read, the
/// agent's reply, and how the call was sent.
struct Baseline {
    conversation: Vec<InventedMessage>,
    before: String,
    fidelity: ReplayFidelity,
}

impl CoachReplay<'_> {
    /// Measures the longest text a question's state carries whole: each
    /// message of `conversation` and a reply of `reply` bytes.
    fn measure(&self, conversation: &[InventedMessage], reply: usize) {
        let longest = conversation
            .iter()
            .map(|message| message.text.len())
            .fold(reply, usize::max);
        let _ = self
            .vault
            .measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    }

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
        self.measure(conversation, reply.len());
        let state = json!({
            "failure": self.failure_state(note),
            "conversation": conversation_state(conversation),
            "reply": reply,
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

    /// The kept request, read again from the vault just before it is sent
    /// (FIX 6659): when an erase took its copy since the job read it, or the
    /// copy no longer reads as it did, it is dropped and never sent again.
    /// `None` once dropped, and when the vault kept none.
    fn live_exact(&self) -> Result<Option<ExactReplayRequest>> {
        if self.exact.borrow().is_none() {
            return Ok(None);
        }
        let live = exact_replay_request(self.vault, &self.job.origin)?;
        let mut kept = self.exact.borrow_mut();
        if *kept == live {
            return Ok(live);
        }
        *kept = None;
        Ok(None)
    }

    /// The real failing call replayed once for every candidate: the request
    /// it sent, when the vault kept it and the host sends it as kept, else
    /// the call rebuilt from the failure's text (FIX 1662). A failure the
    /// replay does not reproduce cannot say whether a candidate fixed it.
    /// Beside a baseline the kept request ran, that request as read again
    /// just now; one whose copy is gone is dropped with it, and the call is
    /// rebuilt (FIX 6659).
    fn baseline(&self) -> Result<Option<(Rc<Baseline>, Option<ExactReplayRequest>)>> {
        let ran = self.baseline.borrow().clone();
        let ran = match ran {
            Some(ran) => ran,
            None => {
                let ran = match self.exact_baseline()? {
                    Some(ran) => Some(ran),
                    None => self.rebuilt_baseline()?,
                }
                .map(Rc::new);
                *self.baseline.borrow_mut() = Some(ran.clone());
                ran
            }
        };
        let Some(baseline) = ran else {
            return Ok(None);
        };
        if baseline.fidelity == ReplayFidelity::Rebuilt {
            return Ok(Some((baseline, None)));
        }
        if let Some(exact) = self.live_exact()? {
            return Ok(Some((baseline, Some(exact))));
        }
        *self.baseline.borrow_mut() = None;
        drop(baseline);
        self.baseline()
    }

    /// The kept request sent again, when it reproduces the failure: read
    /// again just before it is sent (FIX 6659).
    fn exact_baseline(&self) -> Result<Option<Baseline>> {
        let Some(exact) = self.live_exact()? else {
            return Ok(None);
        };
        let Some(before) = self.host.reply_exact(&exact)? else {
            return Ok(None);
        };
        let conversation = request_conversation(&exact.request);
        if self.fails(None, &conversation, &before) != Some(true) {
            return Ok(None);
        }
        Ok(Some(Baseline {
            conversation,
            before,
            fidelity: exact.fidelity(),
        }))
    }

    /// The call rebuilt from the failure's text, when it reproduces the
    /// failure.
    fn rebuilt_baseline(&self) -> Result<Option<Baseline>> {
        let Some(conversation) = self.real_conversation() else {
            return Ok(None);
        };
        Ok(self
            .host
            .reply(&self.job.source.instructions, &conversation)?
            .filter(|before| self.fails(None, &conversation, before) == Some(true))
            .map(|before| Baseline {
                conversation,
                before,
                fidelity: ReplayFidelity::Rebuilt,
            }))
    }

    /// How the baseline ran, once one reproduced the failure.
    fn fidelity(&self) -> Option<ReplayFidelity> {
        self.baseline
            .borrow()
            .as_ref()
            .and_then(Option::as_ref)
            .map(|baseline| baseline.fidelity)
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
        let Some((baseline, exact)) = self.baseline()? else {
            return Ok(ShadowRun::Unavailable);
        };
        let (conversation, before) = (&baseline.conversation, &baseline.before);
        // The fix runs the way the failure was replayed: on the kept request
        // when that reproduced it (FIX 1662) and its copy is still kept
        // (FIX 6659), else on the rebuilt call.
        let after = match exact {
            Some(exact) => self.host.reply_exact(&with_fix(&exact, fix))?,
            None => {
                let instructions = &self.job.source.instructions;
                let system = [instructions.as_str(), fix.as_str()]
                    .into_iter()
                    .filter(|text| !text.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n\n");
                self.host.reply(&system, conversation)?
            }
        };
        let Some(after) = after else {
            return Ok(ShadowRun::Unavailable);
        };
        self.measure(conversation, before.len().max(after.len()));
        let state = json!({
            "failure": self.failure_state(None),
            "conversation": conversation_state(conversation),
            "before": before,
            "after": after,
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

/// The in-vault scrubber: one typed question over the whole text, measured.
struct CoachScrubber<'a> {
    vault: &'a Vault,
    decisions: &'a CodeFixDecisions<'a>,
    evidence: &'a [EntityId],
}

impl ExportScrubber for CoachScrubber<'_> {
    fn scrub(&self, text: &str) -> Result<ScrubRun> {
        let _ = self
            .vault
            .measure_limit(EngineLimit::MaintenanceTextBytes, text.len() as u64);
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
fn keep_in_txn(
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

fn keep_run_in_txn(
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
fn not_run(candidates: &[(String, String)], reason: CodeFixWithheld) -> Vec<SealedRun> {
    candidates
        .iter()
        .map(|(candidate_id, _)| {
            let run = CandidateRun {
                candidate_id: candidate_id.clone(),
                outcome: None,
                export: CodeFixVerdict::Withheld { reason },
                replay: None,
            };
            (run, None)
        })
        .collect()
}

/// The failure's evidence for its questions (the case's own and each report
/// it still reads), and its reports as those questions read them: every one,
/// each whole, measured.
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

/// Queues the Coach's code-fix run for a blocked report it just filed a heal
/// for (OF-380). A report with no durable run, or whose run is no agent
/// dispatch's attempt, gets its run too: it replays from the source its
/// run's host kept (FIX 2343). A report whose run's attempt has a failed
/// case gets none of its own: that case's heal queues the run for the same
/// failure.
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

impl Vault {
    /// The Coach's code-fix work for the owner, newest queued first, at most
    /// the caller's `limit`: each case's or blocked report's heal and, once
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
        rows.truncate(limit);
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
    /// had none of. Every record a run sealed is queued in the write that
    /// keeps the run, and one a run that lost the race to keep sealed is
    /// dropped unsent.
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
                for run in runs {
                    if !settled
                        .candidates
                        .iter()
                        .any(|kept| kept.candidate_id == run.0.candidate_id)
                    {
                        let run = keep_run_in_txn(self, txn, &work.source, run)?;
                        settled.candidates.push(run);
                    }
                }
                work.settled = Some(settled.clone());
                WORK.put(&self.store, txn, &key, &work)?;
                Ok(settled)
            });
        }
        let unkept = self.code_fix_run(&work.source, route, decisions, host, now)?;
        self.with_write_txn_grouped(|txn| {
            let mut work = WORK
                .get(&self.store, &*txn, &key)?
                .ok_or_else(super::invalid)?;
            if let Some(first) = work.settled {
                return Ok(first);
            }
            let example = keep_in_txn(self, txn, &work.source, unkept.example)?;
            let candidates: Vec<CandidateRun> = unkept
                .candidates
                .into_iter()
                .map(|run| keep_run_in_txn(self, txn, &work.source, run))
                .collect::<Result<_>>()?;
            let settled = CodeFixSettled {
                at: unkept.at,
                failure_class: unkept.failure_class,
                example,
                candidates,
            };
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
    ) -> Result<Unkept> {
        let withheld = |failure_class, reason| Unkept {
            at: now,
            failure_class,
            example: (CodeFixVerdict::Withheld { reason }, None),
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
        let (failure, _) = match subject.failure.read() {
            Ok(read) => read,
            Err(reason) => return Ok(withheld(FailureClassV1::Other, reason)),
        };
        let exact = exact_replay_request(self, source)?;
        let case = subject.case.as_ref();
        let (evidence, reports) = failure_context(self, case, &subject.reports)?;
        // A blocked report with no case has no ladder class and names no
        // skill the ladder saw.
        let about = if case.is_some() {
            "failure_case"
        } else {
            "blocked_report"
        };
        let longest = [failure.briefing.as_deref(), failure.task.as_deref()]
            .into_iter()
            .flatten()
            .map(str::len)
            .max()
            .unwrap_or(0);
        let _ = self.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
        let class_state = json!({
            "about": about,
            "failure_ladder_class": case.map(|case| &case.failure_class),
            "names_skill": case.map(|case| case.scope.skill_ref.is_some()),
            "reports": reports,
            "briefing": failure.briefing,
            "task": failure.task,
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
            vault: self,
            job: &job,
            host,
            decisions,
            evidence: &evidence,
            candidates,
            exact: RefCell::new(exact),
            baseline: RefCell::new(None),
        };
        let scrubber = CoachScrubber {
            vault: self,
            decisions,
            evidence: &evidence,
        };
        let example = match draft {
            Some(draft) => self.seal_invented_example(
                source,
                InventedExampleDraft {
                    failure_class,
                    note: draft.note,
                    conversation: draft.conversation,
                },
                &replay,
                &scrubber,
            )?,
            None => (
                CodeFixVerdict::Withheld {
                    reason: CodeFixWithheld::NotDrafted,
                },
                None,
            ),
        };
        let candidates = self.replay_candidates(source, &replay, &example.0)?;
        Ok(Unkept {
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
    ) -> Result<Vec<SealedRun>> {
        let found = {
            let txn = self.store.env.read_txn()?;
            code_fix_subject_in(self, &txn, source)?
        };
        let Some(subject) = found else {
            return Ok(not_run(missing, CodeFixWithheld::UnknownCase));
        };
        let (failure, _) = match subject.failure.read() {
            Ok(read) => read,
            Err(reason) => return Ok(not_run(missing, reason)),
        };
        let exact = exact_replay_request(self, source)?;
        let (evidence, reports) = failure_context(self, subject.case.as_ref(), &subject.reports)?;
        let job = CodeFixJob {
            origin: source.clone(),
            route,
            failure_class: settled.failure_class,
            source: failure,
            reports,
        };
        let replay = CoachReplay {
            vault: self,
            job: &job,
            host,
            decisions,
            evidence: &evidence,
            candidates: missing.to_vec(),
            exact: RefCell::new(exact),
            baseline: RefCell::new(None),
        };
        self.replay_candidates(source, &replay, &settled.example)
    }

    /// Each of the replay's candidates shadow-replayed against the real
    /// failure, its result sealed by its door beside `example`'s record.
    fn replay_candidates(
        &self,
        source: &CodeFixSource,
        replay: &CoachReplay<'_>,
        example: &CodeFixVerdict,
    ) -> Result<Vec<SealedRun>> {
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
            let (export, sealed) = self.seal_candidate_fix_result(
                source,
                CandidateFix {
                    candidate_id: candidate_id.clone(),
                    example_id: example_id.clone(),
                    failure_class,
                },
                &Ran(shadow),
            )?;
            let run = CandidateRun {
                candidate_id: candidate_id.clone(),
                outcome,
                export,
                replay: outcome.and(replay.fidelity()),
            };
            candidates.push((run, sealed));
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

/// The kept request's messages as its questions read them, every part whole:
/// text as written, any other part as its JSON.
fn request_conversation(request: &LlmRequest) -> Vec<InventedMessage> {
    request
        .messages
        .iter()
        .map(|message| InventedMessage {
            role: match message.role {
                LlmMessageRole::System => InventedRole::System,
                LlmMessageRole::User => InventedRole::User,
                LlmMessageRole::Assistant => InventedRole::Assistant,
                LlmMessageRole::Tool => InventedRole::Tool,
            },
            text: message
                .content
                .iter()
                .map(|part| match part {
                    ContentPart::Text { text } => text.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                })
                .collect::<Vec<_>>()
                .join("\n\n"),
        })
        .collect()
}

/// `exact` with a candidate's `fix` added to the agent's instructions: one
/// system message after those the request leads with. A blank fix adds
/// nothing.
fn with_fix(exact: &ExactReplayRequest, fix: &str) -> ExactReplayRequest {
    let mut exact = exact.clone();
    if !fix.trim().is_empty() {
        let at = exact
            .request
            .messages
            .iter()
            .take_while(|message| message.role == LlmMessageRole::System)
            .count();
        exact.request.messages.insert(
            at,
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: fix.to_owned(),
                }],
            },
        );
    }
    exact
}

fn conversation_state(conversation: &[InventedMessage]) -> Vec<serde_json::Value> {
    conversation
        .iter()
        .map(|message| json!({ "role": message.role, "text": message.text }))
        .collect()
}
