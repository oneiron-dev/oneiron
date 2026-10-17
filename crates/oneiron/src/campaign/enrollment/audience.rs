//! The saved-query sweep's enrollment leg (ARCH-0059, decide-host 1193): a
//! query a campaign program names as its audience is swept by detection, and
//! each entry detection records is enqueued as an enrollment attempt at the
//! program's entry step. The campaign owns its program and an edge to the
//! target saved query, never its cohort: membership is derived here, and
//! `campaign.member` is written only by the runner's leader-gated execution.

use super::detection::{DetectEnrollment, EnrollmentDetection, detect_enrollment_visit};
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
    /// Entries detection recorded.
    pub recorded: u32,
    /// Attempts newly queued; a recorded entry whose consequence is already
    /// queued coalesces onto that row.
    pub enqueued: u32,
}

/// The program `record`'s query enrolls into now: the one program naming it
/// as its audience (the program write door holds that to one), while that
/// program's campaign is active and owned by the query's owner. `None` leaves
/// the query to verdict-only evaluation.
///
/// # Errors
///
/// Storage errors propagate; a malformed program row is
/// [`Error::CorruptedIndex`].
pub fn audience_program(
    vault: &Vault,
    record: &SavedQueryRecord,
) -> Result<Option<CampaignProgram>> {
    for program in campaign_programs_for_query(vault, record.query_ref)? {
        let live = read_campaign(vault, record.definition.owner_actor, program.campaign_ref)?
            .is_some_and(|campaign| campaign.definition.lifecycle == CampaignLifecycle::Active);
        if live {
            return Ok(Some(program));
        }
    }
    Ok(None)
}

/// One bounded wake of `program`'s audience query over `candidates`.
///
/// Each candidate is evaluated once, BY detection, in this one loop, so the
/// query's own bounds hold exactly as
/// [`SavedQueryEvaluator::evaluate_wake_batch`] counts them: entities visited
/// against `max_entities_per_wake`, judges that actually ran against
/// `max_judges_per_wake`, and the same resume point when a bound stops the
/// wake. An entry detection records is enqueued at once; a candidate that does
/// not match, or already holds its entry on this evidence, enqueues nothing.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the program names no audience;
/// [`Error::EntityNotFound`] when `owner_actor` does not own the query;
/// detection, queue and storage errors propagate.
pub async fn enroll_audience_wake(
    evaluator: &SavedQueryEvaluator<'_>,
    owner_actor: EntityId,
    program: &CampaignProgram,
    candidates: &[EntityId],
    now: u64,
) -> Result<AudienceWakeReport> {
    let audience = program
        .audience
        .ok_or_else(|| invalid("the campaign program names no audience"))?;
    let record = read_saved_query(evaluator.vault, owner_actor, audience.query_ref)?
        .ok_or(Error::EntityNotFound)?;
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
        let (detection, visit) = detect_enrollment_visit(
            evaluator,
            owner_actor,
            &DetectEnrollment {
                query_ref: audience.query_ref,
                campaign_ref: program.campaign_ref,
                entity_ref: *entity_ref,
                now,
            },
        )
        .await?;
        report.wake.evaluated = report.wake.evaluated.saturating_add(1);
        last_visited = Some(*entity_ref);
        if visit.memo_hit {
            report.wake.memo_hits = report.wake.memo_hits.saturating_add(1);
        }
        if let EnrollmentDetection::Recorded(event) = detection {
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
