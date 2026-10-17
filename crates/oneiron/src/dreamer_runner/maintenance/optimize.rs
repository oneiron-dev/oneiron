//! The Coach's skill-maintenance body on the shared wake runner. Drafting and
//! admission remain separate: this job asks the independent held-out gate and
//! never activates or supersedes a skill itself.
use std::time::{Duration, Instant};

use crate::autoreason_campaign::coverage::CoverageFloorComparison;
use crate::claim::ClaimApprovalStatus;
use crate::dreamer_runner::{
    DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::llm::decision::{DecisionQuestion, TypedDecision};
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill::SkillLifecycle;
use crate::skill_optimize::{
    AxisArm, ConfidenceInterval, GoalAxisBandit, GoalAxisBandits, GoalAxisSpec, HeldOutReplayCase,
    HeldOutReplayNotes, HonestyReplay, OnlineAxisSample, PROVENANCE_OPTIMIZE_ATTEMPT_KEY,
    SKILL_OPTIMIZE_BIRTH_PATH, SkillEditDisposition, SkillOptimizeAuthor, SkillOptimizeDecisions,
    SkillReplayPair, measure_skill_edit_goal_axes, run_skill_optimize,
    run_skill_optimize_for_resident, score_gate_skill_edit_in_cycle,
    skill_edit_needs_goal_axis_report, skill_edit_verdict, skill_tradeoff_ask,
};
use crate::{EntityId, Error, Result, TimeRange, Vault};
use rmpv::Value;

/// Hosts reuse the Coach's model route and budgeted author, with a distinct
/// held-out judge. The judge's decision clock must fit inside the wake clock.
pub struct CoachSkillOptimizer<'a> {
    pub author: &'a (dyn SkillOptimizeAuthor + Send + Sync),
    pub scorer: &'a (dyn HeldOutReplayNotes + Send + Sync),
    /// The live slice a project goal's gate waits on. `None`: the Coach takes
    /// none, and such a gate retries until the owner's measure keeps a report.
    pub live: Option<CoachLiveSlice<'a>>,
}

/// The host's live arms and its configured pull budget (ARCH-0053: "Primary
/// axes are measured online."). The engine sets no budget of its own.
#[derive(Clone, Copy)]
pub struct CoachLiveSlice<'a> {
    pub bandits: &'a (dyn GoalAxisBandits + Send + Sync),
    /// Live pulls per online axis, across both arms; also the most live runs
    /// one proposal's exploration trial routes to the proposal.
    pub pulls_per_axis: u32,
}

/// The lent judge on the wake pass's clock: each judgment it asks stops by
/// the time the pass has left, never on the host judge's own longer clock.
struct PassBoundScorer<'a> {
    inner: &'a (dyn HeldOutReplayNotes + Send + Sync),
    clock: &'a RetrievalDeadline,
}

impl HeldOutReplayNotes for PassBoundScorer<'_> {
    fn judge_revision(&self) -> &str {
        self.inner.judge_revision()
    }

    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            deadline: self.clock,
            ..self.inner.decisions()
        }
    }

    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<serde_json::Value> {
        self.inner.replay_state(case)
    }

    fn blind_pairs(&self, task: &str, receipts: &[String]) -> Result<Vec<SkillReplayPair>> {
        self.inner.blind_pairs(task, receipts)
    }

    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &serde_json::Value,
    ) -> Result<()> {
        self.inner.record_decision(question, decision, state)
    }

    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
        self.inner.honesty_replays(case)
    }

    fn human_minutes(&self, case: &HeldOutReplayCase<'_>) -> Result<f64> {
        self.inner.human_minutes(case)
    }

    fn coverage_floor(&self) -> Option<&CoverageFloorComparison> {
        self.inner.coverage_floor()
    }

    fn goal_axes(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        self.inner.goal_axes(case)
    }
}

/// The live slice on the wake pass's clock: each pull asks its axis question
/// of the pass-bound judge, and no pull starts once the pass's judgment time
/// is spent.
struct PassBoundBandit<'a> {
    inner: &'a dyn GoalAxisBandit,
    clock: &'a RetrievalDeadline,
}

impl GoalAxisBandit for PassBoundBandit<'_> {
    fn pull(&self, axis: &str, arm: AxisArm) -> Result<OnlineAxisSample> {
        if !self.clock.decision_may_start() {
            return Err(Error::InvalidConfig(
                "the wake pass's judgment time is spent".into(),
            ));
        }
        self.inner.pull(axis, arm)
    }

    fn confidence_interval(
        &self,
        axis: &str,
        arm: AxisArm,
        wins: u32,
        pulls: u32,
    ) -> Result<ConfidenceInterval> {
        self.inner.confidence_interval(axis, arm, wins, pulls)
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid Coach skill optimization input".into())
}

fn resident(input: &Value) -> Result<Option<EntityId>> {
    match input {
        Value::Nil => Ok(None),
        Value::Map(fields) if fields.len() == 1 && fields[0].0.as_str() == Some("resident") => {
            EntityId::from_hex(fields[0].1.as_str().ok_or_else(invalid)?)
                .map(Some)
                .map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}

/// Called only after normal admission and inside the driver's panic boundary.
pub(crate) fn execute(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    optimizer: Option<&CoachSkillOptimizer<'_>>,
) -> Result<DreamerAttemptExecution> {
    if attempt.status.payload.attempt_type != DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND {
        return Err(invalid());
    }
    let Some(optimizer) = optimizer else {
        return Ok(DreamerAttemptExecution::Park {
            reason: "Coach skill optimizer has no host author and decision route".into(),
            cause: DreamerParkCause::Other,
        });
    };
    if ctx.deadline.in_finalize_window() {
        return Ok(DreamerAttemptExecution::Park {
            reason: "Coach skill optimization deadline".into(),
            cause: DreamerParkCause::Checkpoint,
        });
    }
    // The author's and the judge's model calls block on the host's runtime,
    // which a thread already driving the wake pass cannot enter: the body
    // runs on its own thread, and the pass waits for it. Its judgments run on
    // the time the pass has left.
    let clock = RetrievalDeadline::hard(
        Instant::now(),
        Duration::from_millis(ctx.deadline.remaining_ms()),
    );
    let (vault, now_ms) = (ctx.vault, ctx.now_ms);
    let outcome = std::thread::scope(|scope| {
        scope
            .spawn(|| optimize(attempt, vault, now_ms, optimizer, &clock))
            .join()
    })
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    // A judgment the pass's clock cut parks the attempt; the next pass
    // resumes its unscored proposal.
    match outcome {
        Err(_) if !clock.decision_may_start() => Ok(DreamerAttemptExecution::Park {
            reason: "Coach skill optimization deadline".into(),
            cause: DreamerParkCause::Checkpoint,
        }),
        outcome => outcome,
    }
}

fn optimize(
    attempt: &DreamerAdmittedAttempt,
    vault: &Vault,
    now_ms: u64,
    optimizer: &CoachSkillOptimizer<'_>,
    clock: &RetrievalDeadline,
) -> Result<DreamerAttemptExecution> {
    let scorer = PassBoundScorer {
        inner: optimizer.scorer,
        clock,
    };
    let resident = resident(&attempt.status.payload.input)?;
    let id = attempt.status.attempt.id;
    let at = now_ms / 1000;
    // Resume an unscored proposal before drafting another one. A crash after
    // draft commit must not strand the candidate behind the open-edit filter.
    let pending = pending_proposal(vault, resident, id)?;
    let (proposal, spent) = if let Some(proposal) = pending {
        (Some(proposal), true)
    } else {
        let occurred = TimeRange { start: at, end: at };
        let outcome = match resident {
            Some(resident) => run_skill_optimize_for_resident(
                vault,
                resident,
                id,
                optimizer.author,
                occurred,
                at,
            )?,
            None => run_skill_optimize(vault, id, optimizer.author, occurred, at)?,
        };
        (
            outcome.proposal,
            outcome.skill.is_some() && outcome.affirmed_receipts.is_empty(),
        )
    };
    if let Some(proposal) = proposal {
        // A project goal's gate rules on a live report bound to this exact
        // proposal: take the slice first unless a kept report still binds it.
        // Its offline floors are judged on the held-out set first; only a
        // passed preflight opens a trial on live work, bounded by the host's
        // pull cap and funded by the goal's exploration slice, and the slice
        // is measured once that trial closes. A failed preflight is the
        // gate's evidence instead.
        if let Some(live) = optimizer.live
            && skill_edit_needs_goal_axis_report(vault, &proposal)?
            && crate::skill::drive_exploration_trial(
                vault,
                &proposal,
                &scorer,
                live.pulls_per_axis,
                at,
            )? == crate::skill::ExplorationTrialStatus::Measurable
        {
            let bandit = live.bandits.for_proposal_judged(&proposal, &scorer)?;
            let bandit = PassBoundBandit {
                inner: &*bandit,
                clock,
            };
            measure_skill_edit_goal_axes(vault, &proposal, &scorer, &bandit, live.pulls_per_axis)?;
        }
        // This gate owns its held-out read and revalidates it at commit. The
        // drafting author never receives the scores or reserved receipts.
        score_gate_skill_edit_in_cycle(vault, &proposal, &scorer, id, at)?;
    }
    Ok(DreamerAttemptExecution::Completed {
        // The host meters model calls separately. The wake counter charges
        // its admitted reservation, never reports paid maintenance as free.
        completed_units: if spent {
            attempt.reservation.reserved_units
        } else {
            0
        },
    })
}

fn pending_proposal(
    vault: &Vault,
    resident: Option<EntityId>,
    attempt: crate::attempt_queue::AttemptId,
) -> Result<Option<EntityId>> {
    let mut after = None;
    let attempt_hex = crate::entity_id::bytes_to_hex_lower(attempt.as_bytes());
    let mut first = None;
    loop {
        let page =
            vault.entities_by_type_page(crate::registry::ENTITY_TYPE_SKILL, after.as_ref(), 128)?;
        for id in &page {
            let Some(record) = vault.get_skill_record(id)? else {
                continue;
            };
            if record.lifecycle_status != SkillLifecycle::Candidate
                || record.approval_status != ClaimApprovalStatus::Proposed
                || crate::skill::resident_of(&record)? != resident
            {
                continue;
            }
            let Value::Map(fields) = &record.provenance else {
                continue;
            };
            let field = |name: &str| {
                fields.iter().find_map(|(key, value)| {
                    (key.as_str() == Some(name))
                        .then(|| value.as_str())
                        .flatten()
                })
            };
            if field(crate::skill_convert::PROVENANCE_BIRTH_KEY) != Some(SKILL_OPTIMIZE_BIRTH_PATH)
            {
                continue;
            }
            if field(PROVENANCE_OPTIMIZE_ATTEMPT_KEY) == Some(attempt_hex.as_str()) {
                return Ok(Some(*id));
            }
            if let Some(verdict) = skill_edit_verdict(vault, id)? {
                if verdict.disposition.admits()
                    || (verdict.disposition == SkillEditDisposition::NeedsTradeoffDecision
                        && skill_tradeoff_ask(vault, id)?.is_some())
                {
                    continue;
                }
            }
            first.get_or_insert(*id);
        }
        if page.len() < 128 {
            return Ok(first);
        }
        after = page.last().copied();
    }
}
