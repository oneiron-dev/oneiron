//! The host's replay capsule for the Coach's contribution checks (FIX 3028):
//! the concrete [`ContributionReplayHost`] the Coach's recipe borrows for one
//! wake pass. Each pair runs the engine's matched-fork runner
//! ([`run_contribution_forks`]) on three lent seams. The model call is the
//! capsule's own model by its exact route, with no fallback, each fork on
//! its own equal cap the Coach pays under live policy. An engine step's
//! fork's program runs on a fresh runtime of the checked-in component in a
//! scratch store of its own (FIX 3607, [`program`]). The scorer is the
//! registered replay judge on the pass's clock: it resolves the run's anchor
//! to the skill's goal axis as the project's goal states it, and judges each
//! fork by that axis, blind to which fork it reads. It reads each fork's
//! answer's text, as before FIX 3607. In the `Executed` mode, where both
//! forks' programs ran, it reads what each program did after that text
//! (L08-A's 07:42 answer: no frozen rubric is qualified on executed output
//! alone). An `Audit` anchor is scored instead by the completed random
//! audit's frozen checker contract, by its own judge alone, and never
//! through a project goal's axis (FIX 3611, [`audit`]). An `OwnerVerdict`
//! anchor's pair is judged by the owner's own word, never by a model: its
//! route only freezes the criterion (FIX 3609, [`owner`]).

mod audit;
mod owner;
mod program;

use std::sync::Weak;

use oneiron::code_run::{
    ContributionForkModel, ContributionForkScorer, ContributionReplayUnavailable, ReplayAnchor,
    ReplayRung, ScoredFork, run_contribution_forks,
};
use oneiron::dreamer_runner::maintenance::{ContributionForks, ContributionReplayHost};
use oneiron::learning::Anchor;
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::{DecisionQuestion, TypedDecision};
use oneiron::llm::mark_solo;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_attribution::ContributionCandidate;
use oneiron::skill_optimize::{
    GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, SkillOptimizeDecisions,
    SkillReplayResponse, SkillReplayResponses, skill_edit_goal,
};
use oneiron::{
    BudgetExhaustionPolicy, ContentPart, EntityId, Error, LlmMessageRole, LlmRequest, LlmResponse,
    Vault,
};
use serde_json::{Value, json};

use self::audit::AuditScorer;
use self::owner::OwnerScorer;
use self::program::{LentProgram, ProgramLending, executed_evidence};
use crate::replay_judge::ServeReplayJudge;
use crate::server::SyncServer;

/// The most one fork's model call may spend. Each fork is metered on a
/// guard of its own at this cap, or at the pass's allowance when that is
/// less, so the two forks get equal caps and neither can starve the other.
const FORK_BUDGET_UNITS: u64 = 1 << 20;
/// The judgment that scores a fork: the replay judge's live-axis question,
/// whose pass rule is a decided yes at the band's high mark.
const SCORER_JUDGMENT: &str = "live_axis";

/// The Coach's contribution forks for one wake pass, on the server once it
/// is bound.
pub(super) struct HostContributionReplay {
    server: Weak<SyncServer>,
    /// The server's runtime: the Dreamer's own cannot carry a fork's call
    /// while its thread waits on the pair.
    handle: tokio::runtime::Handle,
    judge: &'static ServeReplayJudge,
    /// What one fork's call may spend.
    fork_units: u64,
    /// The runtime and scratch stores an engine step's forks' programs run
    /// on.
    programs: ProgramLending,
}

impl HostContributionReplay {
    pub(super) fn new(
        server: Weak<SyncServer>,
        handle: tokio::runtime::Handle,
        judge: &'static ServeReplayJudge,
        pass_units: u64,
    ) -> Self {
        Self {
            server,
            handle,
            judge,
            fork_units: FORK_BUDGET_UNITS.min(pass_units),
            programs: ProgramLending::default(),
        }
    }
}

impl ContributionReplayHost for HostContributionReplay {
    fn run_pair(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<ContributionForks>> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| Error::InvalidConfig("contribution forks: the server stopped".into()))?;
        let model = ExactFork {
            server: &server,
            vault,
            handle: &self.handle,
            fork_units: self.fork_units,
        };
        let program = LentProgram {
            server: &server,
            vault,
            lending: &self.programs,
        };
        let held_out = JudgeScorer { judge: self.judge };
        let audit = AuditScorer {
            server: &server,
            handle: &self.handle,
            fork_units: self.fork_units,
        };
        let owner = OwnerScorer { judge: self.judge };
        // An audit's pair is scored by its stored checker contract (FIX
        // 3611), an owner verdict's by the owner's word (FIX 3609), and
        // every other anchor's by the replay judge's goal axis.
        let scorer: &dyn ContributionForkScorer = match candidate.anchor {
            Anchor::Audit { .. } => &audit,
            Anchor::OwnerVerdict => &owner,
            _ => &held_out,
        };
        Ok(
            match run_contribution_forks(vault, candidate, &model, &program, scorer, clock)? {
                Ok(forks) => Some(forks),
                Err(reason) => {
                    tracing::debug!(reason = reason.as_str(), "contribution forks unavailable");
                    None
                }
            },
        )
    }
}

/// A fork's call: the capsule's model alone, on the one rung that answered
/// it (the role's rung, else the model's raw rung, FIX 18546), under the
/// route prompt the capsule was answered under, paid by the Coach.
/// The prompt sent is the one the capsule's body holds, each secret in it
/// its custody handle (FIX 6255), once the configured route is the one the
/// capsule's call was sent on, by its prompt digest (FIX 6356).
struct ExactFork<'a> {
    server: &'a SyncServer,
    vault: &'a Vault,
    handle: &'a tokio::runtime::Handle,
    fork_units: u64,
}

impl ContributionForkModel for ExactFork<'_> {
    fn generate(
        &self,
        request: &LlmRequest,
        rung: &ReplayRung,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<LlmResponse>> {
        let runtime = self.server.ai.model_runtime();
        let mut request = request.clone();
        request.model = rung.binding.model.clone();
        request.envelope.locality = rung.binding.locality;
        // The two forks are compared with each other: each runs alone on an
        // own server that batches (INF 1). The fork's request hash is its
        // unmarked request's.
        mark_solo(&mut request);
        // The capsule's model, never swapped for the role's pick. The role's
        // route still clamps it: a model not served here now is no replay,
        // and no other model stands in. The role is the one whose admission
        // sent the capsule's call (FIX 6359).
        let Ok(admission) = runtime.admit_replay(self.vault, rung.role, request) else {
            return Ok(None);
        };
        let (request, routes) = (admission.request, admission.routes);
        // The rung that answered the capsule's call, as it is configured
        // now: on the role's route, else on the model's raw route (FIX
        // 18546). The replay runs only while its configured prompt is the
        // one the call was answered under, by its digest; the stored prompt
        // then takes its place, put first once.
        let Some((_, ladder)) = routes
            .exact_rung(
                &rung.binding.model,
                rung.binding.locality,
                rung.prompt_digest,
            )
            .filter(|(_, ladder)| ladder.exact_prompt_digest() == rung.prompt_digest)
        else {
            return Ok(None);
        };
        let run_id = format!("coach-contribution-fork:{}", EntityId::now().to_hex());
        let guard = self.vault.policy_budget_guard(
            run_id.clone(),
            self.fork_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
            self.vault.coach_authority()?,
        )?;
        let run = runtime.undeclared_run(run_id, guard);
        let may_send = || !clock.decision_time_left().is_zero();
        let response = self
            .handle
            .block_on(ladder.generate_exact_within(
                &run,
                request,
                None,
                rung.binding.prompt.as_deref(),
                &may_send,
                clock.decision_time_left(),
            ))
            .map_err(|error| {
                Error::InvalidConfig(format!("a contribution fork failed: {error}"))
            })?;
        Ok(Some(response))
    }
}

/// The replay judge, scoring a fork's answer by the skill's goal axis.
struct JudgeScorer {
    judge: &'static ServeReplayJudge,
}

impl ContributionForkScorer for JudgeScorer {
    /// The skill's goal axis the outcome was anchored on, with the measure
    /// and bound the joined project's goal states for it. An axis the goal
    /// does not name, or one no project goal measures, is no frozen rubric.
    fn resolve(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
    ) -> oneiron::Result<Result<ReplayAnchor, ContributionReplayUnavailable>> {
        Ok(goal_axis_anchor(vault, candidate, self.judge)?
            .ok_or(ContributionReplayUnavailable::AnchorUnresolved))
    }

    /// The judge's live-axis question on the fork's answer, on the pass's
    /// clock. Both forks are asked on the same state but for the answer, with
    /// no instructions in it, so the judge cannot tell which had the skill.
    /// In the `Executed` mode the answer is read with what its program did
    /// when run (FIX 3607, `fork_answer`). An abstained or failed judgment
    /// decides nothing.
    fn passes(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
        anchor: &ReplayAnchor,
        fork: &ScoredFork<'_>,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<bool>> {
        let Some(mut blind) = vault.get_skill_record(&candidate.skill)? else {
            return Ok(None);
        };
        blind.desc.clear();
        let notes = ForkNotes {
            judge: self.judge,
            clock,
            receipt: fork.receipt,
            task: task_text(vault, fork.task),
            response: fork_answer(vault, fork),
        };
        let notes: &dyn HeldOutReplayNotes = &notes;
        match notes.live_axis_met(candidate.skill, &blind, fork.receipt, &anchor.rubric) {
            Ok(met) => Ok(Some(met)),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "a contribution fork was not judged");
                Ok(None)
            }
        }
    }
}

/// The skill's goal axis the outcome was anchored on, with the measure and
/// bound the joined project's goal states for it, scored by `judge`'s
/// live-axis question; `None` when it resolves to no frozen rubric.
fn goal_axis_anchor(
    vault: &Vault,
    candidate: &ContributionCandidate,
    judge: &ServeReplayJudge,
) -> oneiron::Result<Option<ReplayAnchor>> {
    let Ok(goal) = skill_edit_goal(vault, &candidate.skill) else {
        return Ok(None);
    };
    let Some(axis) = goal.axes.iter().find(|axis| axis.name == candidate.axis) else {
        return Ok(None);
    };
    let Some((project, _)) = goal.project else {
        return Ok(None);
    };
    let Some(record) = vault.project_intake_goal(project)? else {
        return Ok(None);
    };
    let Some(stated) = record
        .primary_axes
        .iter()
        .chain(&record.floor_axes)
        .chain(&record.cost_axes)
        .find(|stated| stated.name == axis.name)
    else {
        return Ok(None);
    };
    Ok(Some(ReplayAnchor {
        rubric: json!({
            "name": axis.name, "kind": axis.kind, "measure": stated.measure,
            "bound": stated.bound, "goal": record.goal, "why": record.why,
        }),
        scorer: format!("{}/{SCORER_JUDGMENT}", judge.judge_revision()),
    }))
}

/// The replay judge lent for one fork: its ladder and journal on the pass's
/// clock, and the fork's task and answer as the one replay it reads.
struct ForkNotes<'a> {
    judge: &'static ServeReplayJudge,
    clock: &'a RetrievalDeadline,
    receipt: &'a str,
    task: String,
    response: String,
}

impl HeldOutReplayNotes for ForkNotes<'_> {
    fn judge_revision(&self) -> &str {
        self.judge.judge_revision()
    }

    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            deadline: self.clock,
            ..self.judge.decisions()
        }
    }

    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> oneiron::Result<Value> {
        Ok(json!({
            "skill_id": case.skill_id,
            "version": case.version,
            "replays": [{
                "receipt": self.receipt,
                "task": self.task,
                "response": self.response,
            }],
        }))
    }

    /// The fork's own task and answer, when the receipts name its run, and
    /// the judge's rubric: the one response this fork holds, never a second
    /// one made up to pair it with.
    fn replay_responses(&self, receipts: &[String]) -> oneiron::Result<SkillReplayResponses> {
        let responses = (receipts.iter().any(|receipt| receipt == self.receipt)
            && !self.response.trim().is_empty())
        .then(|| SkillReplayResponse {
            receipt: self.receipt.to_owned(),
            task: self.task.clone(),
            response: self.response.clone(),
        })
        .into_iter()
        .collect();
        Ok(SkillReplayResponses {
            responses,
            rubric: self.judge.rubric()?,
        })
    }

    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Value,
    ) -> oneiron::Result<()> {
        self.judge.record_decision(question, decision, state)
    }

    fn goal_axes(&self, case: &HeldOutReplayCase<'_>) -> oneiron::Result<Vec<GoalAxisSpec>> {
        self.judge.goal_axes(case)
    }
}

/// What the step asked: its non-system messages' text, in order, whole.
/// The system prompt is the executor's or the agent's standing instruction,
/// the same for every task. Past the
/// `[limits] contribution_judge_task_bytes` row it asks, and the judge
/// reads it all.
fn task_text(vault: &Vault, task: &LlmRequest) -> String {
    let text = task
        .messages
        .iter()
        .filter(|message| message.role != LlmMessageRole::System)
        .flat_map(|message| &message.content)
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    measure(vault, EngineLimit::ContributionJudgeTaskBytes, &text);
    text
}

/// A fork's answer as the judge reads it, whole: its text, and in the
/// `Executed` mode what its program did after it ([`executed_evidence`],
/// FIX 3607). Every input the rubric read before FIX 3607 is still there;
/// the execution is added, never put in the text's place. Past the
/// `[limits] contribution_judge_answer_bytes` row it asks, and the judge
/// reads it all.
fn fork_answer(vault: &Vault, fork: &ScoredFork<'_>) -> String {
    let mut text = answer_text(fork.response);
    if let Some(executed) = fork.executed {
        text.push_str("\n\n");
        text.push_str(&executed_evidence(executed));
    }
    measure(vault, EngineLimit::ContributionJudgeAnswerBytes, &text);
    text
}

/// A fork's answer's text, whole.
fn answer_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// Measures `text`'s bytes against `row`, which asks past its bound and
/// never cuts the text.
fn measure(vault: &Vault, row: EngineLimit, text: &str) {
    vault.measure_limit(row, u64::try_from(text.len()).unwrap_or(u64::MAX));
}
