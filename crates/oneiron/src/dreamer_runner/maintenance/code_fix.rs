//! The Coach's code fixes (DEC-0005 FIX6, OF-380). Once the Coach files a
//! heal for a failure case on a deployment that exports, a `coach.code_fix`
//! attempt on the `coach.heal` queue asks it for two things, both made and
//! checked inside the vault: an invented example of the failure (a short
//! general note and a made-up conversation that fails the same way), and,
//! for a skill or prompt heal, the shadow result of the instruction it would
//! add, replayed against the real failure. The host's model drafts and
//! replays with no tools; every judgment (the failure's class, does a replay
//! fail the same way, did the candidate fix it, may the example leave) is a
//! typed question on the host's decision ladder. The export doors in
//! `failure_signals` decide what leaves, and the case's work row keeps each
//! verdict here after the export queue drains.
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
use crate::failure_ladder::HealerCase;
use crate::failure_signals::{
    CandidateFix, CodeFixReplay, CodeFixVerdict, CodeFixWithheld, ExportScrubber, FailureClassV1,
    FailureSource, FixOutcome, InventedExampleDraft, InventedMessage, InventedRole, ReplayRun,
    ScrubRun, ShadowRun, failed_case_in, failure_source_in,
};
use crate::llm::decision::catalogue::CODE_FIX_JUDGMENT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    MAX_DECISION_STATE_BYTES, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Key: id16(case key).
const WORK: SideTable<EntityId, CodeFixWork, Named> =
    SideTable::new(&side_table::FAILURE_SIGNALS_CODE_FIX_WORK);
/// Blocked reports one job carries.
const JOB_REPORTS: usize = 8;
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

/// One case's code-fix work and its local verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFixWork {
    pub case_ref: String,
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
    /// The candidate's shadow replay, for a skill or prompt heal.
    pub candidate: Option<CandidateRun>,
}

/// One candidate's shadow replay: its outcome and its export's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRun {
    pub candidate_id: String,
    /// `None` when the replay could not run, or did not fail before the fix.
    pub outcome: Option<FixOutcome>,
    pub export: CodeFixVerdict,
}

/// What the Coach drafts for: the case, its class and the real failure. It
/// stays inside the vault's boundary.
#[derive(Debug, Clone)]
pub struct CodeFixJob {
    pub case_ref: String,
    pub route: HealRoute,
    pub failure_class: FailureClassV1,
    pub source: FailureSource,
    /// The case's blocked reports: each one's category and the agent's own
    /// words, data and never an instruction.
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

/// The host's models, inside the vault's boundary.
pub trait CodeFixHost {
    /// The Coach's draft for `job`; `Ok(None)` when it drafted nothing usable.
    fn draft(&self, job: &CodeFixJob) -> Result<Option<CodeFixDraft>>;
    /// One turn of the failing agent with no tools, so nothing it says can
    /// act: `system`, then `conversation`. `Ok(None)` when no model runs it.
    fn reply(&self, system: &str, conversation: &[InventedMessage]) -> Result<Option<String>>;
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
    /// The candidate's id and the instruction it adds.
    candidate: Option<(String, String)>,
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
}

impl CodeFixReplay for CoachReplay<'_> {
    fn reproduces(&self, _case: &HealerCase, example: &InventedExampleDraft) -> Result<ReplayRun> {
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

    fn shadow_replay(&self, _case: &HealerCase, candidate_id: &str) -> Result<ShadowRun> {
        let Some((id, fix)) = &self.candidate else {
            return Ok(ShadowRun::Unavailable);
        };
        let Some(conversation) = self.real_conversation() else {
            return Ok(ShadowRun::Unavailable);
        };
        if id != candidate_id {
            return Ok(ShadowRun::Unavailable);
        }
        let instructions = &self.job.source.instructions;
        // The baseline first: a failure the replay does not reproduce cannot
        // say whether the candidate fixed it.
        let Some(before) = self.host.reply(instructions, &conversation)? else {
            return Ok(ShadowRun::Unavailable);
        };
        if self.fails(None, &conversation, &before) != Some(true) {
            return Ok(ShadowRun::Unavailable);
        }
        let system = [instructions.as_str(), fix.as_str()]
            .into_iter()
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        let Some(after) = self.host.reply(&system, &conversation)? else {
            return Ok(ShadowRun::Unavailable);
        };
        let state = json!({
            "failure": self.failure_state(None),
            "conversation": conversation_state(&conversation),
            "before": clip(&before, TEXT_BYTES),
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
    fn reproduces(&self, _case: &HealerCase, _example: &InventedExampleDraft) -> Result<ReplayRun> {
        Ok(ReplayRun::Unavailable)
    }

    fn shadow_replay(&self, _case: &HealerCase, _candidate_id: &str) -> Result<ShadowRun> {
        Ok(self.0)
    }
}

/// Queues the Coach's code-fix run for a case it just filed a heal for,
/// when this deployment exports. The case's work row makes it one run per
/// case.
#[allow(clippy::too_many_arguments)]
pub(super) fn wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case_ref: &str,
    key: EntityId,
    proposal: EntityId,
    route: HealRoute,
    parent: AttemptId,
    now: u64,
) -> Result<()> {
    if !vault.config.failure_signals.exports() || WORK.get(&vault.store, &*txn, &key)?.is_some() {
        return Ok(());
    }
    WORK.put(
        &vault.store,
        txn,
        &key,
        &CodeFixWork {
            case_ref: case_ref.to_owned(),
            proposal,
            route: route.as_str().to_owned(),
            queued_at: now,
            settled: None,
        },
    )?;
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HEAL_ATTEMPT_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_CODE_FIX_FACET.into(),
            input: Value::from(case_ref),
            parent_attempt: Some(parent),
        },
        Some(format!("{COACH_CODE_FIX_FACET}:{case_ref}")),
        None,
        now,
    )?;
    Ok(())
}

impl Vault {
    /// The Coach's code-fix run for one case, under its leased
    /// `coach.code_fix` attempt: the failure's class, the Coach's draft, the
    /// invented example through its export door, and the candidate's shadow
    /// replay, kept here and sent through its own door. A replay returns what
    /// the first run kept.
    pub fn run_coach_code_fix(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &CodeFixDecisions<'_>,
        host: &dyn CodeFixHost,
        now: u64,
    ) -> Result<CodeFixSettled> {
        self.require_coach_attempt(attempt, COACH_CODE_FIX_FACET)?;
        let case_ref = attempt
            .status
            .payload
            .input
            .as_str()
            .ok_or_else(super::invalid)?
            .to_owned();
        let key = EntityId::from_hex(&case_ref)?;
        let work = {
            let txn = self.store.env.read_txn()?;
            WORK.get(&self.store, &txn, &key)?
                .ok_or_else(super::invalid)?
        };
        if let Some(settled) = work.settled {
            return Ok(settled);
        }
        let route = HealRoute::parse(&work.route).ok_or_else(super::invalid)?;
        let settled = self.code_fix_run(&case_ref, route, decisions, host, now)?;
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
        case_ref: &str,
        route: HealRoute,
        decisions: &CodeFixDecisions<'_>,
        host: &dyn CodeFixHost,
        now: u64,
    ) -> Result<CodeFixSettled> {
        let withheld = |failure_class, reason| CodeFixSettled {
            at: now,
            failure_class,
            example: CodeFixVerdict::Withheld { reason },
            candidate: None,
        };
        if !self.config.failure_signals.exports() {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::NotEligible,
            ));
        }
        let found = {
            let txn = self.store.env.read_txn()?;
            match failed_case_in(self, &txn, case_ref)? {
                Some((case, attempt)) => Some((
                    failure_source_in(self, &txn, &case, &attempt)?.map(|(source, _)| source),
                    case,
                )),
                None => None,
            }
        };
        let Some((source, case)) = found else {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::UnknownCase,
            ));
        };
        let Some(source) = source else {
            return Ok(withheld(
                FailureClassV1::Other,
                CodeFixWithheld::PrivateWorld,
            ));
        };
        let reports = case_reports(self, &case.blocked_reports)?;
        let mut evidence: Vec<EntityId> = EntityId::from_hex(&case.evidence_ref)
            .ok()
            .into_iter()
            .chain(reports.iter().map(|(receipt, _)| *receipt))
            .collect();
        evidence.sort();
        evidence.dedup();
        let reports: Vec<serde_json::Value> = reports
            .iter()
            .take(JOB_REPORTS)
            .map(|(_, report)| {
                json!({
                    "category": report.category.as_str(),
                    "untrusted_detail": clip(&report.untrusted_detail, DETAIL_BYTES),
                })
            })
            .collect();
        let class_state = json!({
            "failure_ladder_class": case.failure_class,
            "names_skill": case.scope.skill_ref.is_some(),
            "reports": reports,
            "briefing": source.briefing.as_deref().map(|text| clip(text, TEXT_BYTES)),
            "task": source.task.as_deref().map(|text| clip(text, TEXT_BYTES)),
        });
        let failure_class = decisions.class(&evidence, &class_state)?;
        let job = CodeFixJob {
            case_ref: case_ref.to_owned(),
            route,
            failure_class,
            source,
            reports,
        };
        let Some(draft) = host.draft(&job)? else {
            return Ok(withheld(failure_class, CodeFixWithheld::NotDrafted));
        };
        let candidate = match route {
            HealRoute::SkillEdit | HealRoute::PromptInject => draft
                .fix
                .filter(|fix| !fix.trim().is_empty())
                .map(|fix| (format!("coach.{}", route.as_str()), fix)),
            HealRoute::Environment | HealRoute::Person => None,
        };
        let replay = CoachReplay {
            job: &job,
            host,
            decisions,
            evidence: &evidence,
            candidate,
        };
        let scrubber = CoachScrubber {
            decisions,
            evidence: &evidence,
        };
        let example = self.prepare_invented_example(
            case_ref,
            InventedExampleDraft {
                failure_class,
                note: draft.note,
                conversation: draft.conversation,
            },
            &replay,
            &scrubber,
        )?;
        let candidate = match &replay.candidate {
            None => None,
            Some((candidate_id, _)) => {
                let shadow = replay.shadow_replay(&case, candidate_id)?;
                let outcome = match shadow {
                    ShadowRun::Fixed => Some(FixOutcome::Fixed),
                    ShadowRun::NotFixed => Some(FixOutcome::NotFixed),
                    ShadowRun::Unavailable => None,
                };
                let example_id = match &example {
                    CodeFixVerdict::Queued { id } => Some(id.clone()),
                    CodeFixVerdict::Withheld { .. } => None,
                };
                let export = self.record_candidate_fix_result(
                    case_ref,
                    CandidateFix {
                        candidate_id: candidate_id.clone(),
                        example_id,
                        failure_class,
                    },
                    &Ran(shadow),
                )?;
                Some(CandidateRun {
                    candidate_id: candidate_id.clone(),
                    outcome,
                    export,
                })
            }
        };
        Ok(CodeFixSettled {
            at: now,
            failure_class,
            example,
            candidate,
        })
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
