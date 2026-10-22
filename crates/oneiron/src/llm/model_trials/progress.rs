//! A trial's paid arms, kept one by one inside its own row (FIX 9920).
//!
//! Each arm is marked `Sending` before it goes to the executor, and its billed
//! reading is kept before the next send, so an executor error or a crash
//! loses no completed read. Each claim takes the next run number; an arm an
//! earlier run left in flight then reads unknown. A run sends only the arms
//! never sent: a completed arm is never billed again, and an arm whose
//! provider outcome is unknown stays unknown, is never sent again and never
//! reads as zero usage. Once every arm is read or unknown, the kept readings
//! measure the trial; an unknown arm leaves its case without a decision or a
//! known cost, so the comparison reads unknown and stays an owner-reviewed
//! offer at most (FIX 9901).

use super::evidence::{CaseReads, measure_reads};
use super::*;

/// What a trial's arms come to, as its view reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrialProgressCounts {
    pub state: ModelTrialExecutionState,
    pub completed: usize,
    pub unknown: usize,
    pub total: usize,
}

impl ModelTrial {
    /// Where the trial's paid reads stand: measured evidence counts its
    /// known and unknown costs; otherwise the kept arms do.
    #[must_use]
    pub fn progress_counts(&self) -> TrialProgressCounts {
        let total = self.cases.len() * 2;
        if let Some(evidence) = &self.evidence {
            return TrialProgressCounts {
                state: ModelTrialExecutionState::Measured,
                completed: total.saturating_sub(evidence.unknown_arms),
                unknown: evidence.unknown_arms,
                total,
            };
        }
        let count = |unknown: bool| {
            self.arms
                .iter()
                .filter(|arm| match &arm.outcome {
                    TrialArmOutcome::Completed { .. } => !unknown,
                    TrialArmOutcome::Unknown { .. } => unknown,
                    TrialArmOutcome::Sending => false,
                })
                .count()
        };
        TrialProgressCounts {
            state: self.execution,
            completed: count(false),
            unknown: count(true),
            total,
        }
    }

    fn arm_mut(&mut self, answer: EntityId, arm: TrialArm) -> Option<&mut TrialArmProgress> {
        self.arms
            .iter_mut()
            .find(|kept| kept.answer == answer && kept.arm == arm)
    }

    fn arm_reads(&self, answer: EntityId, arm: TrialArm) -> Option<Option<TrialReading>> {
        let kept = self
            .arms
            .iter()
            .find(|kept| kept.answer == answer && kept.arm == arm)?;
        match &kept.outcome {
            TrialArmOutcome::Completed { reading } => Some(Some(reading.clone())),
            TrialArmOutcome::Unknown { .. } => Some(None),
            TrialArmOutcome::Sending => None,
        }
    }
}

/// The claim's change to the row: the next run, with every arm an earlier
/// run left in flight unknown. An arm with no mark was never sent, so it
/// stays missing and this run sends it.
pub(super) fn claim(trial: &mut ModelTrial) {
    for kept in &mut trial.arms {
        if kept.outcome == TrialArmOutcome::Sending {
            kept.outcome = TrialArmOutcome::Unknown {
                failure: TrialArmFailure::Interrupted,
            };
        }
    }
    trial.run = trial.run.saturating_add(1);
    trial.execution_started = true;
    trial.execution = ModelTrialExecutionState::Running;
}

impl Vault {
    /// Keeps one arm's step in its own committed write: `Sending` before a
    /// send, its outcome after. The row is read as stored, never re-frozen:
    /// a label change since cannot lose a billed read. Returns false when a
    /// later run holds the trial, so this run sends nothing more; a late
    /// outcome for this run's own arm is still kept, which is more truthful
    /// than the unknown the later claim left.
    fn record_trial_arm(
        &self,
        claimed: &ModelTrial,
        answer: EntityId,
        arm: TrialArm,
        outcome: TrialArmOutcome,
    ) -> Result<bool> {
        let key = (claimed.request.question, claimed.id);
        let mut txn = self.store.env.write_txn()?;
        let previous = TRIALS
            .get(&self.store, &txn, &key)?
            .filter(|trial| trial.request.principal == claimed.request.principal)
            .ok_or(Error::EntityNotFound)?;
        let current = previous.run == claimed.run;
        let mut trial = previous.clone();
        if outcome == TrialArmOutcome::Sending {
            if !current || trial.evidence.is_some() || trial.arm_mut(answer, arm).is_some() {
                return Ok(false);
            }
            trial.arms.push(TrialArmProgress {
                answer,
                arm,
                run: claimed.run,
                outcome,
            });
        } else {
            let kept = trial
                .arm_mut(answer, arm)
                .filter(|kept| kept.run == claimed.run)
                .ok_or(Error::ConcurrentWrite("model trial arm changed"))?;
            if matches!(kept.outcome, TrialArmOutcome::Completed { .. }) {
                return Err(Error::ConcurrentWrite("model trial arm changed"));
            }
            let failed = matches!(outcome, TrialArmOutcome::Unknown { .. });
            kept.outcome = outcome;
            if failed && current && trial.evidence.is_none() {
                trial.execution = ModelTrialExecutionState::Interrupted;
            }
        }
        replace(self, &mut txn, &previous, &trial)?;
        txn.commit()?;
        Ok(current)
    }

    /// Sends the claimed trial's arms not yet sent, case by case, the
    /// incumbent before the candidate. `prepare` runs before an arm is
    /// marked: its refusal (an owner's revalidation, an unreadable source)
    /// leaves the arm unsent for a later run. `send` is the paid read; its
    /// error keeps the arm unknown, the trial interrupted, and returns. A
    /// run a later claim superseded stops with `ConcurrentWrite`.
    pub(crate) fn resume_trial_execution<C>(
        &self,
        claimed: &ModelTrial,
        mut prepare: impl FnMut(&TrialCaseInput) -> Result<C>,
        mut send: impl FnMut(
            &QuestionRecord,
            &PricedModelBackend,
            &TrialCaseInput,
            &C,
        ) -> Result<TrialReading>,
    ) -> Result<()> {
        let record = read_question(
            self,
            claimed.request.principal,
            claimed.request.question,
            Some(claimed.request.question_version),
        )?
        .ok_or(Error::EntityNotFound)?;
        let superseded = || Error::ConcurrentWrite("model trial run was superseded");
        for case in &claimed.cases {
            let input = TrialCaseInput {
                answer: case.selection.answer,
                unit: case.unit,
                source_frontier: case.source_frontier,
            };
            for (arm, backend) in [
                (TrialArm::Incumbent, &claimed.incumbent),
                (TrialArm::Candidate, &claimed.candidate),
            ] {
                if claimed
                    .arms
                    .iter()
                    .any(|kept| kept.answer == input.answer && kept.arm == arm)
                {
                    continue;
                }
                let context = prepare(&input)?;
                if !self.record_trial_arm(claimed, input.answer, arm, TrialArmOutcome::Sending)? {
                    return Err(superseded());
                }
                let outcome = send(&record, backend, &input, &context);
                let kept = match &outcome {
                    Ok(reading) => TrialArmOutcome::Completed {
                        reading: reading.clone(),
                    },
                    Err(_) => TrialArmOutcome::Unknown {
                        failure: TrialArmFailure::ExecutorError,
                    },
                };
                let current = self.record_trial_arm(claimed, input.answer, arm, kept)?;
                outcome?;
                if !current {
                    return Err(superseded());
                }
            }
        }
        Ok(())
    }

    /// Records the evidence the kept arms measure once every arm is read
    /// or unknown; `None` while an arm is unsent or in flight. Recorded
    /// evidence answers again unchanged.
    pub(crate) fn record_trial_progress_measurements_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
    ) -> Result<Option<TrialEvidence>> {
        let previous = self
            .model_trial_in_txn(txn, principal, question, id, locality)?
            .ok_or(Error::EntityNotFound)?;
        if let Some(existing) = &previous.evidence {
            return Ok(Some(existing.clone()));
        }
        if !previous.execution_started {
            return Err(invalid("model trial has not been claimed"));
        }
        let mut reads = Vec::with_capacity(previous.cases.len());
        for case in &previous.cases {
            let answer = case.selection.answer;
            let (Some(incumbent), Some(candidate)) = (
                previous.arm_reads(answer, TrialArm::Incumbent),
                previous.arm_reads(answer, TrialArm::Candidate),
            ) else {
                return Ok(None);
            };
            reads.push(CaseReads {
                answer,
                incumbent,
                candidate,
            });
        }
        let measured = measure_reads(&previous, reads)?;
        let mut trial = previous.clone();
        trial.evidence = Some(measured.clone());
        trial.execution = ModelTrialExecutionState::Measured;
        replace(self, txn, &previous, &trial)?;
        Ok(Some(measured))
    }
}
