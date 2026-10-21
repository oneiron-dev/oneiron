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
//! A publisher's candidate may also be a pinned engine build or patch
//! (FIX 1661, 2144): it never becomes a prompt string, and runs as one
//! matched pair on the host's shadow runner once the Coach's own Grant reads
//! the failing run's scope (FIX 6357, `engine`); until that runner can run a
//! candidate engine, each such pair is kept not run, never a verdict, and
//! tried once more when the engine's shadow protocol moves on; one kept for
//! want of that Grant is tried again once the Grant reads that scope (FIX
//! 7031). An erased capsule's call is replayed by no run (FIX 6251).
use std::cell::RefCell;
use std::ops::Bound;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use self::engine::read_granted_in_txn;
use self::instruction::{CoachReplay, CoachScrubber, Ran};
use self::work::{
    enqueue_run_in_txn, keep_in_txn, keep_run_in_txn, not_run, redraft_invented_example,
    snapshot_job, untried,
};
use super::coach::COACH_CODE_FIX_FACET;
use super::coach_heal::HealRoute;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::failure_signals::{
    CandidateFix, CodeFixReplay, CodeFixSource, CodeFixVerdict, CodeFixWithheld, ExactReplay,
    ExactReplayRequest, FailureClassV1, FailureSource, FixOutcome, InventedExampleDraft,
    InventedMessage, ReplayFidelity, SealedCodeFix, Sealing, ShadowRun, code_fix_source_snapshot,
};
use crate::limit_ask::EngineLimit;
use crate::llm::decision::catalogue::CODE_FIX_JUDGMENT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

mod engine;
mod instruction;
mod publisher;
mod work;
pub use self::publisher::{
    CodeFixShadowHost, EngineAdmission, EngineArm, EngineArmStatus, EngineArmSummary,
    EngineCallUsage, EngineCandidateRun, EngineNotRun, EnginePairState, PublisherCandidateKind,
    artifact_digest_text, parse_artifact_digest_text,
};
pub(super) use self::work::{wake_blocked_in_txn, wake_in_txn};

/// Key: `work::work_key`.
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
    /// An engine candidate's matched pair (FIX 1661, 2144), content-free:
    /// its pin, each arm's summary, and whether it was judged or why not.
    /// `None` for an instruction, and for a candidate whose failure no
    /// longer stood.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineCandidateRun>,
}

impl CandidateRun {
    /// Whether this run stands for its candidate: every run does but an
    /// engine pair kept not run at another shadow protocol, or kept for want
    /// of the Coach's Grant when `read_granted` says that Grant now reads
    /// the run's scope; each is tried once more (FIX 1661, 2144, 7031).
    fn tried(&self, read_granted: bool) -> bool {
        self.engine
            .as_ref()
            .is_none_or(|engine| !engine.retries(read_granted))
    }
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
    /// The rows the draft is assembled from (FIX 6997); `None`, unknown.
    pub source_rows: Option<Vec<EntityId>>,
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
/// pinned: an instruction the replay adds to the failing agent's own, or an
/// engine build or patch the host's shadow runner runs in a sandboxed arm
/// (FIX 1661, 2144). It is tried in the vault only; nothing fetches or
/// installs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherCandidate {
    /// The token its result exports under, naming the pinned artifact by its
    /// whole digest.
    pub id: String,
    /// What it is.
    pub kind: PublisherCandidateKind,
}

/// The host's models, inside the vault's boundary.
pub trait CodeFixHost {
    /// The Coach's draft for `job`; `Ok(None)` when it drafted nothing usable.
    fn draft(&self, job: &CodeFixJob) -> Result<Option<CodeFixDraft>>;
    /// One turn of the failing agent with no tools, so nothing it says can
    /// act: `system`, then `conversation`, assembled from `rows` (FIX 6997;
    /// `None`, unknown). `Ok(None)` when no model runs it.
    fn reply(
        &self,
        system: &str,
        conversation: &[InventedMessage],
        rows: Option<Vec<EntityId>>,
    ) -> Result<Option<String>>;
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
    /// The host's shadow runner, for a publisher's engine candidates (FIX
    /// 1661, 2144). `None` leaves each of them not run.
    fn shadow_runner(&self) -> Option<&dyn CodeFixShadowHost> {
        None
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
    /// no run that stands of some id in `pinned` (an engine pair kept not run
    /// at another shadow protocol stands no longer, nor one kept for want of
    /// a Grant the Coach now holds, FIX 7031). Returns the key the next
    /// step goes on after, or `None` once the last row is read. A deployment
    /// that does not export queues nothing.
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
        // Resolved outside the writer: resolving it opens a writer of its own.
        let coach = self.coach_authority()?.entity_ref();
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
                let granted = read_granted_in_txn(self, &*txn, settled, &work.source, coach)?;
                let lacks = pinned.iter().any(|id| {
                    !settled
                        .candidates
                        .iter()
                        .any(|run| run.candidate_id == *id && run.tried(granted))
                });
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
    /// had none of, and an engine pair it kept not run at another shadow
    /// protocol, or for want of a Grant the Coach now holds (FIX 7031), run
    /// again in its place. Every record a run sealed is queued
    /// in the write that keeps the run, and one a run that lost the race to
    /// keep sealed is dropped unsent.
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
            // The Coach's Grant is read again in the write that keeps a run.
            let coach = self.coach_authority()?.entity_ref();
            let granted = {
                let txn = self.store.env.read_txn()?;
                read_granted_in_txn(self, &txn, &settled, &work.source, coach)?
            };
            let missing = untried(&settled, host.publisher_candidates(), granted);
            if missing.is_empty() || !self.config.failure_signals.exports() {
                return Ok(settled);
            }
            let runs = self.code_fix_top_up(
                &work.source,
                work.proposal,
                route,
                &settled,
                &missing,
                decisions,
                host,
            )?;
            return self.with_write_txn_grouped(|txn| {
                let mut work = WORK
                    .get(&self.store, &*txn, &key)?
                    .ok_or_else(super::invalid)?;
                let mut settled = work.settled.take().ok_or_else(super::invalid)?;
                let granted = read_granted_in_txn(self, &*txn, &settled, &work.source, coach)?;
                for run in runs {
                    let kept = settled
                        .candidates
                        .iter()
                        .position(|kept| kept.candidate_id == run.0.candidate_id);
                    if kept.is_some_and(|at| {
                        settled
                            .candidates
                            .get(at)
                            .is_some_and(|held| held.tried(granted))
                    }) {
                        continue;
                    }
                    let run = keep_run_in_txn(self, txn, &work.source, run)?;
                    // A pair kept not run at another shadow protocol, or for
                    // want of a Grant the Coach now holds, is run again, in
                    // its place.
                    match kept.and_then(|at| settled.candidates.get_mut(at)) {
                        Some(stale) => *stale = run,
                        None => settled.candidates.push(run),
                    }
                }
                work.settled = Some(settled.clone());
                WORK.put(&self.store, txn, &key, &work)?;
                Ok(settled)
            });
        }
        let unkept = self.code_fix_run(&work.source, work.proposal, route, decisions, host, now)?;
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
        proposal: EntityId,
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
        // OF-380 L1: the failure, its reports and its failing call, read once.
        let snapshot = match code_fix_source_snapshot(self, source)? {
            Ok(snapshot) => snapshot,
            Err(reason) => return Ok(withheld(FailureClassV1::Other, reason)),
        };
        // An erased capsule's call is never replayed, rebuilt or not (FIX
        // 6251): nothing is classed or drafted for it.
        if matches!(snapshot.replay.exact, ExactReplay::Erased) {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::ReplayUnavailable,
            ));
        }
        let (case, failure) = (snapshot.case.as_ref(), &snapshot.failure);
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
            "reports": snapshot.reports,
            "briefing": failure.briefing,
            "task": failure.task,
        });
        let failure_class = decisions.class(&snapshot.evidence, &class_state)?;
        let job = snapshot_job(&snapshot, source, route, failure_class, proposal);
        let draft = host.draft(&job)?;
        let own = match (route, &draft) {
            (HealRoute::SkillEdit | HealRoute::PromptInject, Some(draft)) => draft
                .fix
                .clone()
                .filter(|fix| !fix.trim().is_empty())
                .map(|instruction| {
                    (
                        format!("coach.{}", route.as_str()),
                        PublisherCandidateKind::Instruction { instruction },
                    )
                }),
            _ => None,
        };
        let drafted_id = own.as_ref().map(|(id, _)| id.clone());
        // A publisher candidate needs no draft of the Coach's: it is replayed
        // against the real failure whatever the heal's route.
        let candidates: Vec<(String, PublisherCandidateKind)> = own
            .into_iter()
            .chain(
                host.publisher_candidates()
                    .iter()
                    .map(|candidate| (candidate.id.clone(), candidate.kind.clone())),
            )
            .collect();
        measure_candidates(self, &candidates);
        if draft.is_none() && candidates.is_empty() {
            return Ok(withheld(failure_class, CodeFixWithheld::NotDrafted));
        }
        let replay = CoachReplay {
            vault: self,
            job: &job,
            host,
            decisions,
            evidence: &snapshot.evidence,
            snapshot: &snapshot,
            drafted: drafted_id,
            candidates,
            exact: RefCell::new(snapshot.replay.exact.clone()),
            baseline: RefCell::new(None),
        };
        let scrubber = CoachScrubber {
            vault: self,
            decisions,
            evidence: &snapshot.evidence,
        };
        let example = match draft {
            Some(draft) => redraft_invented_example(
                &replay,
                &scrubber,
                InventedExampleDraft {
                    failure_class,
                    note: draft.note,
                    conversation: draft.conversation,
                },
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
    /// tried, or kept an engine pair of not run at another shadow protocol,
    /// each replayed once against the failure and sent through its door. The first run's class and example stand. A failure that no longer
    /// stands, or whose text cannot be read, keeps each as not run, as does
    /// one whose call's capsule was erased (FIX 6251).
    #[expect(clippy::too_many_arguments)]
    fn code_fix_top_up(
        &self,
        source: &CodeFixSource,
        proposal: EntityId,
        route: HealRoute,
        settled: &CodeFixSettled,
        missing: &[(String, PublisherCandidateKind)],
        decisions: &CodeFixDecisions<'_>,
        host: &dyn CodeFixHost,
    ) -> Result<Vec<SealedRun>> {
        // OF-380 L1: read once for this top-up, as for a first run.
        let snapshot = match code_fix_source_snapshot(self, source)? {
            Ok(snapshot) => snapshot,
            Err(reason) => return Ok(not_run(missing, reason)),
        };
        if matches!(snapshot.replay.exact, ExactReplay::Erased) {
            return Ok(not_run(missing, CodeFixWithheld::ReplayUnavailable));
        }
        measure_candidates(self, missing);
        let job = snapshot_job(&snapshot, source, route, settled.failure_class, proposal);
        let replay = CoachReplay {
            vault: self,
            job: &job,
            host,
            decisions,
            evidence: &snapshot.evidence,
            snapshot: &snapshot,
            drafted: None,
            candidates: missing.to_vec(),
            exact: RefCell::new(snapshot.replay.exact.clone()),
            baseline: RefCell::new(None),
        };
        self.replay_candidates(source, &replay, &settled.example)
    }

    /// Each of the replay's candidates shadow-replayed against the real
    /// failure, its result sealed by its door beside `example`'s record: an
    /// instruction on the replay of the failing call, an engine as one
    /// matched pair on the host's shadow runner (FIX 1661, 2144), which is
    /// never a prompt string.
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
        for (candidate_id, kind) in &replay.candidates {
            let (shadow, fidelity, engine) = match kind.engine_pin() {
                None => {
                    let shadow = replay.shadow_replay(&replay.job.source, candidate_id)?;
                    (shadow, replay.fidelity(), None)
                }
                Some(pin) => {
                    let pair = replay.engine_pair(candidate_id, pin)?;
                    (pair.shadow, pair.fidelity, Some(pair.run))
                }
            };
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
                replay: outcome.and(fidelity),
                engine,
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

/// Measures the candidates one run replays (Rule 5): how many, and the
/// longest id or instruction among them, each read whole.
fn measure_candidates(vault: &Vault, candidates: &[(String, PublisherCandidateKind)]) {
    let longest = candidates
        .iter()
        .map(|(id, kind)| match kind {
            PublisherCandidateKind::Instruction { instruction } => id.len().max(instruction.len()),
            PublisherCandidateKind::EngineBuild { .. }
            | PublisherCandidateKind::EnginePatch { .. } => id.len(),
        })
        .max()
        .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, candidates.len() as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
}
