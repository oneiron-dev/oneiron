//! The host's replay capsule for the Coach's contribution checks (FIX 3028):
//! the concrete [`ContributionReplayHost`] the Coach's recipe borrows for one
//! wake pass. Each pair runs the engine's matched-fork runner
//! ([`run_contribution_forks`]) on two lent seams. The model call is the
//! capsule's own model by its exact route, with no fallback, each fork on
//! its own equal cap the Coach pays under live policy. The scorer is the
//! registered replay judge on the pass's clock: it resolves the run's anchor
//! to the skill's goal axis as the project's goal states it, and judges each
//! fork's answer by that axis, blind to which fork it reads.
use std::sync::Weak;

use oneiron::code_run::{
    CapsuleRungBinding, ContributionForkModel, ContributionForkScorer, ReplayAnchor, ScoredFork,
    run_contribution_forks,
};
use oneiron::dreamer_runner::maintenance::{ContributionForks, ContributionReplayHost};
use oneiron::llm::decision::{DecisionQuestion, TypedDecision};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_attribution::ContributionCandidate;
use oneiron::skill_optimize::{
    GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, SkillOptimizeDecisions, SkillReplayPair,
    skill_edit_goal,
};
use oneiron::{
    BudgetExhaustionPolicy, ContentPart, EntityId, Error, LlmMessageRole, LlmRequest, LlmResponse,
    Vault,
};
use serde_json::{Value, json};

use super::CHAT_ROLE;
use super::code_fix::clip;
use crate::replay_judge::{JUDGE_REVISION, ServeReplayJudge};
use crate::server::SyncServer;

/// The most one fork's model call may spend. Each fork is metered on a
/// guard of its own at this cap, or at the pass's allowance when that is
/// less, so the two forks get equal caps and neither can starve the other.
const FORK_BUDGET_UNITS: u64 = 1 << 20;
/// Most bytes of the task a fork's judgment reads.
const TASK_BYTES: usize = 24 * 1024;
/// Most bytes of a fork's answer its judgment reads.
const RESPONSE_BYTES: usize = 16 * 1024;
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
        let scorer = JudgeScorer { judge: self.judge };
        Ok(
            match run_contribution_forks(vault, candidate, &model, &scorer, clock)? {
                Ok(forks) => Some(forks),
                Err(reason) => {
                    tracing::debug!(reason = reason.as_str(), "contribution forks unavailable");
                    None
                }
            },
        )
    }
}

/// A fork's call: the capsule's model alone, by its own one-model ladder,
/// under the route prompt the capsule was answered under, paid by the Coach.
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
        binding: &CapsuleRungBinding,
        clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<LlmResponse>> {
        let runtime = self.server.ai.model_runtime();
        let mut request = request.clone();
        request.model = binding.model.clone();
        request.envelope.locality = binding.locality;
        // The model a raw call naming it meets, never swapped for the
        // role's route, which still clamps it: a model not served here now
        // is no replay, and no other model stands in.
        let Ok(call) = runtime.admit_seat_bound(self.vault, CHAT_ROLE, request) else {
            return Ok(None);
        };
        // Its rung puts its route prompt first, once: the replay runs only
        // while that is the prompt the capsule's call was answered under.
        if call.ladder.exact_prompt() != Some(binding.prompt.as_deref()) {
            return Ok(None);
        }
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
            .block_on(call.ladder.generate_exact_within(
                &run,
                call.request,
                None,
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
            scorer: format!("{JUDGE_REVISION}/{SCORER_JUDGMENT}"),
        }))
    }

    /// The judge's live-axis question on the fork's answer, on the pass's
    /// clock. Both forks are asked on the same state but for the answer, with
    /// no instructions in it, so the judge cannot tell which had the skill.
    /// An abstained or failed judgment decides nothing.
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
            task: task_text(fork.task),
            response: answer_text(fork.response),
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

    fn blind_pairs(
        &self,
        _task: &str,
        _receipts: &[String],
    ) -> oneiron::Result<Vec<SkillReplayPair>> {
        Ok(Vec::new())
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

/// What the step asked: its non-system messages' text, in order, cut to
/// [`TASK_BYTES`]. The system prompt is the executor's or the agent's
/// standing instruction, the same for every task.
fn task_text(task: &LlmRequest) -> String {
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
    clip(&text, TASK_BYTES).to_owned()
}

/// A fork's answer as text, cut to [`RESPONSE_BYTES`].
fn answer_text(response: &LlmResponse) -> String {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    clip(&text, RESPONSE_BYTES).to_owned()
}
