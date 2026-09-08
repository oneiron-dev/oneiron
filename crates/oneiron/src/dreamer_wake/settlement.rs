//! What the driver does with an attempt once the executor returns: milestones, landing, complete, park, publish.

use rmpv::Value;

use crate::attempt_queue::{
    AcceptAttemptLanding, AttemptId, AttemptQueue, FinishAttemptLanding, LandingOutcome,
    LandingReserveSpendOutcome, LandingTrigger, RecordAttemptResumePoint,
    SpendAttemptLandingReserve,
};
use crate::dreamer_runner::{
    CompleteDreamerAttempt, DREAMER_MILESTONE_PREDICATE, DREAMER_MILESTONE_VALUE_SCHEMA_VERSION,
    DreamerAdmittedAttempt, DreamerMilestoneClaim, DreamerMilestoneKind, ParkDreamerAttempt,
};
#[cfg(feature = "sync")]
use crate::dreamer_runner::{DreamerAttemptProgressState, DreamerAttemptProgressUpdate};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;

use super::driver::DreamerWakeDriver;
use super::types::{LandingRequest, ProgressKind};

impl DreamerWakeDriver<'_> {
    pub(super) fn milestone_claim(
        &self,
        kind: DreamerMilestoneKind,
        now: u64,
    ) -> Option<DreamerMilestoneClaim> {
        self.milestones
            .as_ref()
            .map(|author| DreamerMilestoneClaim {
                claim_id: EntityId::now(),
                subject: author.subject,
                kind,
                envelope: author.envelope.clone(),
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
            })
    }

    /// Writes a durable milestone claim for `attempt_id` through the gate,
    /// matching the landed `dreamer.job_milestone` value codec exactly
    /// (pinned keys `schema_version`/`job_id`/`milestone`/`at`).
    pub(super) fn write_milestone(
        &self,
        attempt_id: AttemptId,
        kind: DreamerMilestoneKind,
        now: u64,
    ) -> Result<()> {
        let Some(author) = &self.milestones else {
            return Ok(());
        };
        let claim_id = EntityId::now();
        let value = Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DREAMER_MILESTONE_VALUE_SCHEMA_VERSION),
            ),
            (
                Value::from("job_id"),
                Value::Binary(attempt_id.as_bytes().to_vec()),
            ),
            (Value::from("milestone"), Value::from(kind.as_str())),
            (Value::from("at"), Value::from(now)),
        ]);
        let candidate = ClaimCandidate::new(
            DREAMER_MILESTONE_PREDICATE,
            crate::claim::ClaimSubject::Entity(author.subject),
            value,
            1.0,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault.with_write_txn(|wtxn| {
            self.vault
                .batch_in()
                .claim_candidate(&claim_id, candidate, &author.envelope, occurred, now)
                .apply(wtxn)
        })
    }

    /// Runs the durable landing protocol for one admitted attempt and returns
    /// the reserve units it actually spent.
    ///
    /// Order is the invariant: ENTER landing (the row stops being ordinary
    /// running work and keeps its lease), SPEND from the reserve (never from
    /// the ordinary meter, and never more than the reserve holds), RECORD the
    /// exact resume point, then FINISH through the queue's own transaction —
    /// optionally minting the successor that carries the point. Nothing here
    /// can report the attempt completed.
    pub(super) fn land_attempt(
        &self,
        admitted: &DreamerAdmittedAttempt,
        request: LandingRequest,
        now: u64,
    ) -> Result<u64> {
        let queue = AttemptQueue::new(self.vault);
        let attempt_id = admitted.status.attempt.id;
        let lease_owner = admitted
            .status
            .attempt
            .lease_owner
            .clone()
            .unwrap_or_default();
        let attempt_count = admitted.status.attempt.attempt_count;
        // Entering is idempotent (`AlreadyLanding`), so a re-executed attempt
        // that already entered still finishes its landing here.
        let _entered: LandingOutcome = queue.accept_landing(AcceptAttemptLanding {
            id: attempt_id,
            lease_owner: lease_owner.clone(),
            attempt_count,
            // Fallback only: a landing answering a recorded request takes that
            // request's trigger, so a worker cannot relabel why it was asked.
            trigger: LandingTrigger::CancelRequest,
            status: request.status,
            resume_point: None,
            request_sequence: None,
            now,
        })?;

        let mut spent_units = 0;
        if request.reserve_units > 0 {
            match queue.spend_landing_reserve(SpendAttemptLandingReserve {
                id: attempt_id,
                lease_owner: lease_owner.clone(),
                attempt_count,
                units: request.reserve_units,
                now,
            })? {
                LandingReserveSpendOutcome::Spent { .. } => {
                    spent_units = request.reserve_units;
                }
                // Fail closed and keep landing: an over-ask spends NOTHING, and
                // the attempt still gets to record where it stopped rather than
                // losing the landing because its final work was too large.
                LandingReserveSpendOutcome::Exhausted { .. } => {}
            }
        }

        if let Some(resume_point) = request.resume_point {
            queue.record_resume_point(RecordAttemptResumePoint {
                id: attempt_id,
                lease_owner: lease_owner.clone(),
                attempt_count,
                resume_point,
                now,
            })?;
        }

        queue.finish_landing(FinishAttemptLanding {
            id: attempt_id,
            lease_owner,
            attempt_count,
            hand_off: request.hand_off,
            // The successor is NEXT-pass work. A pass runs on one fixed `now`,
            // so scheduling one second out makes the handoff unclaimable by the
            // very pass that just asked this attempt to stop — otherwise a
            // budget- or lease-pressured pass would immediately re-admit the
            // work it landed and spin against the pressure that caused it.
            scheduled_at: Some(now.saturating_add(1)),
            now,
        })?;
        Ok(spent_units)
    }

    pub(super) fn complete_attempt(
        &mut self,
        admitted: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<()> {
        let input = CompleteDreamerAttempt {
            id: admitted.status.attempt.id,
            lease_owner: admitted
                .status
                .attempt
                .lease_owner
                .clone()
                .unwrap_or_default(),
            attempt_count: admitted.status.attempt.attempt_count,
            now,
        };
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            self.store
                .complete_with_progress(input, &mut lane.producer, lane.ephemeral)?;
            return Ok(());
        }
        self.store.complete(input)?;
        Ok(())
    }

    pub(super) fn park_attempt(
        &mut self,
        attempt_id: AttemptId,
        reason: String,
        park_owner: String,
        now: u64,
    ) -> Result<()> {
        let input = ParkDreamerAttempt {
            attempt_id,
            reason,
            park_owner,
            now,
        };
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            self.store
                .park_attempt_with_progress(input, &mut lane.producer, lane.ephemeral)?;
            return Ok(());
        }
        self.store.park_attempt(input)?;
        Ok(())
    }

    // The Result is only fallible on the sync progress lane.
    #[cfg_attr(not(feature = "sync"), allow(clippy::unnecessary_wraps))]
    pub(super) fn publish(
        &mut self,
        attempt_id: AttemptId,
        kind: ProgressKind,
        message: Option<String>,
        now: u64,
    ) -> Result<()> {
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            let state = match kind {
                ProgressKind::Running => DreamerAttemptProgressState::Running,
                ProgressKind::Parked => DreamerAttemptProgressState::Parked,
            };
            self.store.publish_progress(
                &mut lane.producer,
                lane.ephemeral,
                DreamerAttemptProgressUpdate {
                    attempt_id,
                    state,
                    message,
                    completed_units: 0,
                    total_units: None,
                    updated_at_ms: now.saturating_mul(1_000),
                },
            )?;
        }
        #[cfg(not(feature = "sync"))]
        let _ = (attempt_id, kind, message, now);
        Ok(())
    }
}
