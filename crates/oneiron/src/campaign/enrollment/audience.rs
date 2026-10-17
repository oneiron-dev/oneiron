//! The saved-query sweep's enrollment leg (ARCH-0059, decide-host 1193): a
//! query campaign programs name as their audience is swept by detection, and
//! each entry detection records is enqueued as an enrollment attempt at its
//! program's entry step, once per bound program. The campaign owns its program and an edge to the
//! target saved query, never its cohort: membership is derived here, and
//! `campaign.member` is written only by the runner's leader-gated execution.

use super::detection::detect_enrollments;
use super::program::{CampaignProgram, campaign_programs_for_query};
use super::runner::{CampaignEnrollmentAttemptPayload, CampaignEnrollmentRunner};
use super::storage::invalid;
use crate::Vault;
use crate::attempt_queue::EnqueueOutcome;
use crate::campaign::surface::{CampaignLifecycle, read_campaign};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::saved_query::{
    SavedQueryEvaluator, SavedQueryRecord, WakeEvaluationReport, read_saved_query,
};

/// What one audience wake did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceWakeReport {
    /// The wake's counts and resume point, as an unbound query's wake
    /// reports them.
    pub wake: WakeEvaluationReport,
    /// Entries detection recorded, one per bound program a candidate entered.
    pub recorded: u32,
    /// Attempts newly queued; a recorded entry whose consequence is already
    /// queued coalesces onto that row.
    pub enqueued: u32,
}

/// The programs `record`'s query enrolls into now: every program naming it as
/// its audience whose campaign is active and owned by the query's owner, in
/// program-id order. Empty leaves the query to verdict-only evaluation.
///
/// # Errors
///
/// Storage errors propagate; a malformed program row is
/// [`Error::CorruptedIndex`].
pub fn audience_programs(vault: &Vault, record: &SavedQueryRecord) -> Result<Vec<CampaignProgram>> {
    let mut live = Vec::new();
    for program in campaign_programs_for_query(vault, record.query_ref)? {
        if read_campaign(vault, record.definition.owner_actor, program.campaign_ref)?
            .is_some_and(|campaign| campaign.definition.lifecycle == CampaignLifecycle::Active)
        {
            live.push(program);
        }
    }
    Ok(live)
}

/// One bounded wake of `query_ref` over `candidates`, enrolling into each of
/// `programs`.
///
/// Each candidate is evaluated once, BY detection, in this one loop, so the
/// query's own bounds hold exactly as
/// [`SavedQueryEvaluator::evaluate_wake_batch`] counts them: entities visited
/// against `max_entities_per_wake`, judges that actually ran against
/// `max_judges_per_wake`, and the same resume point when a bound stops the
/// wake. Detection then records an entry per program's campaign, against that
/// campaign's own history, and each is enqueued at once at its program's
/// entry step; a candidate that does not match, or already holds its entry in
/// a campaign on this evidence, enqueues nothing there.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when a program does not name `query_ref` as its
/// audience; [`Error::EntityNotFound`] when `owner_actor` does not own the
/// query; detection, queue and storage errors propagate.
pub async fn enroll_audience_wake(
    evaluator: &SavedQueryEvaluator<'_>,
    owner_actor: EntityId,
    query_ref: EntityId,
    programs: &[CampaignProgram],
    candidates: &[EntityId],
    now: u64,
) -> Result<AudienceWakeReport> {
    let mut bound = Vec::with_capacity(programs.len());
    for program in programs {
        let audience = program
            .audience
            .filter(|audience| audience.query_ref == query_ref)
            .ok_or_else(|| invalid("the campaign program does not enroll from this query"))?;
        bound.push((program, audience));
    }
    let mut campaigns: Vec<EntityId> = Vec::with_capacity(bound.len());
    for (program, _) in &bound {
        if !campaigns.contains(&program.campaign_ref) {
            campaigns.push(program.campaign_ref);
        }
    }
    let record =
        read_saved_query(evaluator.vault, owner_actor, query_ref)?.ok_or(Error::EntityNotFound)?;
    let bounds = record.definition.eval;
    let runner = CampaignEnrollmentRunner::new(evaluator.vault);
    let mut report = AudienceWakeReport {
        wake: WakeEvaluationReport {
            evaluated: 0,
            memo_hits: 0,
            judges_run: 0,
            resume_after: None,
        },
        recorded: 0,
        enqueued: 0,
    };
    // The last entity actually visited, as `evaluate_wake_batch` tracks it:
    // `None` means the candidate set was exhausted.
    let mut last_visited = None;
    for entity_ref in candidates {
        if report.wake.evaluated >= bounds.max_entities_per_wake {
            report.wake.resume_after = last_visited;
            return Ok(report);
        }
        let (recorded, visit) = detect_enrollments(
            evaluator,
            owner_actor,
            query_ref,
            &campaigns,
            *entity_ref,
            now,
        )
        .await?;
        report.wake.evaluated = report.wake.evaluated.saturating_add(1);
        last_visited = Some(*entity_ref);
        if visit.memo_hit {
            report.wake.memo_hits = report.wake.memo_hits.saturating_add(1);
        }
        for event in recorded {
            // The program write door holds a campaign to one program per
            // query, so the event's campaign names its program.
            let Some((program, audience)) = bound
                .iter()
                .find(|(program, _)| program.campaign_ref == event.campaign_ref)
            else {
                continue;
            };
            report.recorded = report.recorded.saturating_add(1);
            let queued = runner.enqueue(
                &CampaignEnrollmentAttemptPayload {
                    membership_event_ref: event.event_ref,
                    campaign_program_ref: program.program_ref,
                    program_step_ref: audience.entry_step_ref,
                },
                None,
                now,
            )?;
            if matches!(queued, EnqueueOutcome::Enqueued(_)) {
                report.enqueued = report.enqueued.saturating_add(1);
            }
        }
        if visit.judge_ran {
            report.wake.judges_run = report.wake.judges_run.saturating_add(1);
            if report.wake.judges_run >= bounds.max_judges_per_wake {
                report.wake.resume_after = Some(*entity_ref);
                return Ok(report);
            }
        }
    }
    Ok(report)
}
