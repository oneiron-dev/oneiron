//! What the driver does with an attempt once the executor returns: milestones, landing, complete, park, publish.

use rmpv::Value;

use crate::attempt_queue::{
    AcceptAttemptLanding, AttemptId, AttemptQueue, FinishAttemptLanding, LandingOutcome,
    LandingReserveSpendOutcome, LandingTrigger, RecordAttemptResumePoint,
    SpendAttemptLandingReserve,
};
use crate::dreamer_runner::{
    CompleteDreamerAttempt, DREAMER_MILESTONE_PREDICATE, DREAMER_MILESTONE_VALUE_SCHEMA_VERSION,
    DreamerAdmittedAttempt, DreamerBudgetSettlementOutcome, DreamerMilestoneClaim,
    DreamerMilestoneKind, DreamerParkCause, DreamerTryLease, ParkDreamerAttempt,
    SettleDreamerBudget,
};
#[cfg(feature = "sync")]
use crate::dreamer_runner::{DreamerAttemptProgressState, DreamerAttemptProgressUpdate};

use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;

use super::driver::DreamerWakeDriver;
use super::types::{DreamerAttemptExecutor, LandingRequest, ProgressKind, WakeAttemptMeter};

/// The lease `admitted` ran under (FIX 6057): its admission's owner and
/// lease generation, `pass_owner` when the snapshot names no owner.
pub(super) fn admitted_lease<'a>(
    admitted: &'a DreamerAdmittedAttempt,
    pass_owner: &'a str,
) -> DreamerTryLease<'a> {
    DreamerTryLease {
        owner: admitted
            .status
            .attempt
            .lease_owner
            .as_deref()
            .unwrap_or(pass_owner),
        generation: admitted.status.attempt.attempt_count,
    }
}

impl DreamerWakeDriver<'_> {
    pub(super) fn milestone_claim(
        &self,
        kind: DreamerMilestoneKind,
        now: u64,
    ) -> Result<Option<DreamerMilestoneClaim>> {
        self.milestones
            .as_ref()
            .map(|author| {
                Ok(DreamerMilestoneClaim {
                    claim_id: self.vault.store.clock.entity_id()?,
                    subject: author.subject,
                    kind,
                    envelope: author.envelope.clone(),
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                })
            })
            .transpose()
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
        self.write_milestone_as(attempt_id, kind, now, author.subject, &author.envelope)
    }

    /// [`Self::write_milestone`] for an admitted attempt. A turn program's
    /// milestone is its waking actor's, never the Dreamer author's (DOOR-141
    /// PR2); one it cannot write is logged, never the settlement's failure.
    /// Every other attempt's is [`Self::write_milestone`]'s.
    pub(super) fn write_attempt_milestone(
        &self,
        admitted: &DreamerAdmittedAttempt,
        kind: DreamerMilestoneKind,
        now: u64,
    ) -> Result<()> {
        let attempt_id = admitted.status.attempt.id;
        if admitted.status.attempt.kind != crate::dreamer_runner::DREAMER_TURN_PROGRAM_ATTEMPT_KIND
        {
            return self.write_milestone(attempt_id, kind, now);
        }
        let Some(author) = &self.milestones else {
            return Ok(());
        };
        let written = crate::dreamer_runner::program_milestone_envelope(
            self.vault,
            attempt_id,
            &author.envelope,
        )
        .and_then(|envelope| {
            self.write_milestone_as(attempt_id, kind, now, author.subject, &envelope)
        });
        if let Err(error) = written {
            tracing::warn!(
                kind = ?error.kind(),
                attempt = ?attempt_id,
                "a turn program's milestone was not written; its settlement stands"
            );
        }
        Ok(())
    }

    /// One milestone claim for `attempt_id`, about `subject`, under
    /// `envelope`.
    fn write_milestone_as(
        &self,
        attempt_id: AttemptId,
        kind: DreamerMilestoneKind,
        now: u64,
        subject: crate::EntityId,
        envelope: &crate::write_envelope::WriteEnvelope,
    ) -> Result<()> {
        let claim_id = self.vault.store.clock.entity_id()?;
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
            crate::claim::ClaimSubject::Entity(subject),
            value,
            1.0,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault.with_write_txn_grouped(|wtxn| {
            let mut envelope = envelope.clone();
            self.vault.sign_retained_machine_claim_in_txn(
                &*wtxn,
                &claim_id,
                &candidate,
                &mut envelope,
            )?;
            self.vault
                .batch_in()
                .claim_candidate(&claim_id, candidate, &envelope, occurred, now)
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

    /// Completes a try whose execution finished. A TASK's Done is judged by
    /// `exec`'s host first, as the resident pump judges its runs' (OF-533).
    /// A TASK realization's confession is read before Done settles its TASK
    /// and sealed in the commit that closes the try (OF-544); neither can
    /// fail it.
    pub(super) async fn complete_attempt<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        exec: &E,
        admitted: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<()> {
        let judged =
            match crate::task_verb::runner_done_question(self.vault, admitted.status.attempt.id)? {
                Some(question) => exec.judge_done(question).await,
                None => None,
            };
        let confession = crate::dreamer_consolidation::task_realize_confession(
            self.vault,
            &admitted.status.attempt,
        )
        .unwrap_or_else(|error| {
            tracing::warn!(kind = ?error.kind(), "a TASK realization's confession was not read");
            None
        });
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
            self.store.complete_with_progress(
                input,
                judged,
                confession.as_ref(),
                &mut lane.producer,
                lane.ephemeral,
            )?;
            return Ok(());
        }
        self.store
            .complete_sealed(input, judged, confession.as_ref())?;
        Ok(())
    }

    /// Parks `admitted` under `park_owner`, fenced on the lease it ran under
    /// (FIX 6057): a try a held program's resume queued again, or a later
    /// pass claimed, since then is left as it is, never re-parked.
    pub(super) fn park_attempt(
        &mut self,
        admitted: &DreamerAdmittedAttempt,
        reason: String,
        cause: DreamerParkCause,
        park_owner: &str,
        now: u64,
    ) -> Result<()> {
        let input = ParkDreamerAttempt {
            attempt_id: admitted.status.attempt.id,
            reason,
            cause,
            park_owner: park_owner.to_owned(),
            carried_spend: None,
            now,
        };
        let lease = admitted_lease(admitted, park_owner);
        #[cfg(feature = "sync")]
        if let Some(lane) = &mut self.progress {
            self.store.park_if_current_lease_with_progress(
                input,
                lease,
                &mut lane.producer,
                lane.ephemeral,
            )?;
            return Ok(());
        }
        self.store.park_if_current_lease(input, lease)?;
        Ok(())
    }

    /// Settles a failed or plainly parked attempt's reservation on `line`
    /// with what it charged (SCAN C012): its run line's charge and what its
    /// executor's tally spent before an error (FIX 7432), pinning in that
    /// writer the paid receipts of the terminal steps the charge covers
    /// (FIX 6100). Incurred spend is never refused (FIX 8702). A nonzero
    /// charge whose settlement fails is never refunded at zero: it stays
    /// owed on the reservation, which its next settlement or abort charges
    /// (FIX 8728), and the attempt still parks or fails as before. The
    /// static code says which of those it did, for the attempt's outcome
    /// line (FIX 7271).
    pub(super) fn settle_metered_charge(
        &self,
        line: &str,
        attempt_id: AttemptId,
        meter: &WakeAttemptMeter,
        now: u64,
    ) -> Result<&'static str> {
        let charged = meter.charged_units();
        let settlement = SettleDreamerBudget {
            budget_id: line.to_owned(),
            child_attempt: attempt_id,
            actual_units: charged,
            now,
        };
        let receipts = meter.step_receipts();
        let error = match self
            .store
            .settle_budget_with_step_receipts(settlement.clone(), &receipts)
        {
            Ok(DreamerBudgetSettlementOutcome::NoReservation) => return Ok("no_reservation"),
            Ok(_) if charged == 0 => return Ok("refunded"),
            Ok(_) if receipts.is_empty() => return Ok("charged"),
            Ok(_) => return Ok("charged_with_receipts"),
            // Nothing was spent: that settlement was the zero abort itself.
            Err(error) if charged == 0 => return Err(error),
            Err(error) => error,
        };
        tracing::warn!(
            kind = ?error.kind(),
            attempt_id = %bytes_to_hex_lower(attempt_id.as_bytes()),
            charged,
            "the measured charge did not settle; it stays owed on the reservation"
        );
        self.store.owe_unsettled_charge(&settlement)?;
        Ok("charge_owed")
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
