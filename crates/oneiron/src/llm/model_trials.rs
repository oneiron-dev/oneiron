//! Per-question held-out trials nominated by external benchmark scores.
//!
//! Scraping can only prepare work. A measured, sufficient trial can produce an
//! activation offer, but this module never edits a route or a historical answer.

mod evidence;
mod types;
pub use types::*;

use crate::claim::CallerLocality;
use crate::llm::decision::questions::{QuestionRecord, read_question, read_question_in_txn};
use crate::llm::registry::{ModelBackendPin, ModelCostReceipt, PricedModelBackend, invalid};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

const TRIALS: SideTable<(EntityId, EntityId), ModelTrial, Named> =
    SideTable::new(&side_table::LLM_MODEL_TRIAL);

fn matching_backend(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &ModelBackendPin,
) -> Result<Option<PricedModelBackend>> {
    let Some(row) = vault.model_registry_row_in_txn(txn, &pin.model)? else {
        return Ok(None);
    };
    Ok(row.backends()?.into_iter().find(|row| &row.pin == pin))
}

fn backend(vault: &Vault, txn: &heed::RoTxn<'_>, pin: &ModelBackendPin) -> Result<PricedModelBackend> {
    matching_backend(vault, txn, pin)?
        .ok_or_else(|| invalid("model backend serving pin is not registered"))
}

fn replace(vault: &Vault, txn: &mut heed::RwTxn<'_>, previous: &ModelTrial, next: &ModelTrial) -> Result<()> {
    let key = (previous.request.question, previous.id);
    if TRIALS.get(&vault.store, txn, &key)?.as_ref() != Some(previous) {
        return Err(Error::ConcurrentWrite("model trial changed"));
    }
    TRIALS.put(&vault.store, txn, &key, next)
}

impl Vault {
    /// The host supplies a sealed selection from eval authoring and the goal's
    /// remaining exploration allowance. Preparing work never invokes a model.
    pub fn prepare_model_trial(&self, request: ModelTrialRequest, locality: CallerLocality, now: u64) -> Result<ModelTrial> {
        let mut txn = self.store.env.write_txn()?;
        let result = self.prepare_model_trial_in_txn(&mut txn, request, locality, now)?;
        txn.commit()?;
        Ok(result)
    }

    pub(super) fn prepare_model_trial_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: ModelTrialRequest,
        locality: CallerLocality,
        now: u64,
    ) -> Result<ModelTrial> {
        if request.question_version == 0
            || request.set.version == 0
            || [
                &request.source,
                &request.benchmark,
                &request.set.id,
                &request.set.rubric_version,
            ]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 256)
            || request.held_out.is_empty()
            || request.incumbent == request.candidate
            || !request.policy.exploration_remaining.is_finite()
            || request.policy.exploration_remaining < 0.0
            || [
                request.policy.vault_cost_cap,
                request.policy.project_cost_cap,
            ]
            .into_iter()
            .flatten()
            .any(|cap| !cap.is_finite() || cap < 0.0)
        {
            return Err(invalid("invalid question model trial request"));
        }
        let current = read_question_in_txn(self, txn, request.principal, request.question, None)?
            .ok_or(Error::EntityNotFound)?;
        if current.definition.question.version != request.question_version {
            return Err(Error::ConcurrentWrite("model trial question changed"));
        }
        let row = self
            .model_registry_row_in_txn(txn, &request.candidate.model)?
            .ok_or(Error::EntityNotFound)?;
        let nominated_score = row
            .scores
            .get(&request.source)
            .and_then(|scores| scores.get(&request.benchmark))
            .copied()
            .ok_or_else(|| invalid("model trial needs a scraped score nomination"))?;
        let score_fetched_at = row
            .fetched_at
            .get(&request.source)
            .copied()
            .ok_or_else(|| invalid("model score nomination has no observation time"))?;
        let incumbent = backend(self, txn, &request.incumbent)?;
        let candidate = row.backend(&request.candidate)?;
        let cases = evidence::freeze_cases(self, txn, &request, locality)?;
        let estimated_cost = (incumbent
            .cost_receipt(request.incumbent_usage_bound.clone(), 1)?
            .cost
            + candidate
                .cost_receipt(request.candidate_usage_bound.clone(), 1)?
                .cost)
            * cases.len() as f64;
        if !estimated_cost.is_finite() {
            return Err(invalid("model trial estimate overflow"));
        }
        let admission = if estimated_cost <= request.policy.exploration_remaining {
            TrialAdmission::Ready
        } else {
            TrialAdmission::AskExploration
        };
        let trial = ModelTrial {
            id: EntityId::now(),
            request,
            nominated_score,
            score_fetched_at,
            incumbent,
            candidate,
            cases,
            estimated_cost,
            admission,
            prepared_at: now,
            execution_started: false,
            evidence: None,
            receipt: None,
        };
        for (_, previous) in
            TRIALS.scan_from(&self.store, txn, trial.request.question.as_bytes())?
        {
            if previous.request.principal == trial.request.principal
                && previous.request.question_version == trial.request.question_version
                && previous.request.incumbent == trial.request.incumbent
                && previous.request.candidate == trial.request.candidate
                && previous.request.set == trial.request.set
            {
                if previous.cases != trial.cases {
                    return Err(invalid(
                        "held-out selection changed without a new set version",
                    ));
                }
                return Ok(previous);
            }
        }
        TRIALS.put(
            &self.store,
            txn,
            &(trial.request.question, trial.id),
            &trial,
        )?;
        Ok(trial)
    }

    /// Retained labels are released only while their original, scoped outcome
    /// pairs remain readable. An old question version never becomes a new one.
    pub fn model_trial(&self, principal: EntityId, question: EntityId, id: EntityId, locality: CallerLocality) -> Result<Option<ModelTrial>> {
        let txn = self.store.env.read_txn()?;
        let result = self.model_trial_in_txn(&txn, principal, question, id, locality)?;
        Ok(result)
    }

    pub(super) fn model_trial_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
    ) -> Result<Option<ModelTrial>> {
        let stored = {
            TRIALS.get(&self.store, txn, &(question, id))?
        };
        let Some(trial) = stored.filter(|trial| trial.request.principal == principal) else {
            return Ok(None);
        };
        if evidence::freeze_cases(self, txn, &trial.request, locality)? != trial.cases {
            return Err(Error::ConcurrentWrite("model trial labels changed"));
        }
        Ok(Some(trial))
    }

    /// One durable approval changes only trial admission, never the answerer.
    pub fn approve_model_trial(&self, principal: EntityId, question: EntityId, id: EntityId, locality: CallerLocality) -> Result<ModelTrial> {
        let mut txn = self.store.env.write_txn()?;
        let result = self.approve_model_trial_in_txn(&mut txn, principal, question, id, locality)?;
        txn.commit()?;
        Ok(result)
    }

    pub(super) fn approve_model_trial_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
    ) -> Result<ModelTrial> {
        let previous = self
            .model_trial_in_txn(txn, principal, question, id, locality)?
            .ok_or(Error::EntityNotFound)?;
        let mut trial = previous.clone();
        trial.admission = TrialAdmission::Ready;
        replace(self, txn, &previous, &trial)?;
        Ok(trial)
    }

    /// Claim before any paid work. A crash leaves the claim for explicit host
    /// recovery, rather than silently replaying already billed model calls.
    pub fn claim_model_trial(&self, principal: EntityId, question: EntityId, id: EntityId, locality: CallerLocality) -> Result<ModelTrial> {
        let mut txn = self.store.env.write_txn()?;
        let result = self.claim_model_trial_in_txn(&mut txn, principal, question, id, locality)?;
        txn.commit()?;
        Ok(result)
    }

    pub(super) fn claim_model_trial_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
    ) -> Result<ModelTrial> {
        let previous = self
            .model_trial_in_txn(txn, principal, question, id, locality)?
            .ok_or(Error::EntityNotFound)?;
        if previous.admission != TrialAdmission::Ready || previous.execution_started {
            return Err(invalid("model trial needs approval or was already started"));
        }
        if backend(self, txn, &previous.request.incumbent)? != previous.incumbent
            || backend(self, txn, &previous.request.candidate)? != previous.candidate
            || read_question_in_txn(self, txn, principal, question, None)?.is_none_or(|record| {
                record.definition.question.version != previous.request.question_version
            })
        {
            return Err(Error::ConcurrentWrite(
                "model trial pins changed before execution",
            ));
        }
        let mut trial = previous.clone();
        trial.execution_started = true;
        replace(self, txn, &previous, &trial)?;
        Ok(trial)
    }

    /// The host's executor goes through decide() and its normal budget leases.
    /// It must replay the pinned frontier, not substitute a later live source.
    /// Failed/cut reads return a TrialReading with no decision and real usage.
    /// Over-budget plans remain one recoverable ask without calling the executor.
    pub fn run_model_trial(
        &self,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
        execute: impl FnMut(
            &QuestionRecord,
            &PricedModelBackend,
            &TrialCaseInput,
        ) -> Result<TrialReading>,
    ) -> Result<Option<TrialEvidence>> {
        let plan = self
            .model_trial(principal, question, id, locality)?
            .ok_or(Error::EntityNotFound)?;
        if plan.admission == TrialAdmission::AskExploration {
            return Ok(None);
        }
        if let Some(evidence) = plan.evidence {
            return Ok(Some(evidence));
        }
        let trial = self.claim_model_trial(principal, question, id, locality)?;
        let observations = self.execute_model_trial(&trial, execute)?;
        self.record_model_trial_measurements(principal, question, id, locality, observations)
            .map(Some)
    }

    pub(super) fn execute_model_trial(
        &self,
        trial: &ModelTrial,
        mut execute: impl FnMut(&QuestionRecord, &PricedModelBackend, &TrialCaseInput) -> Result<TrialReading>,
    ) -> Result<Vec<TrialObservation>> {
        let record = read_question(
            self,
            trial.request.principal,
            trial.request.question,
            Some(trial.request.question_version),
        )?
        .ok_or(Error::EntityNotFound)?;
        let mut observations = Vec::new();
        for case in &trial.cases {
            let input = TrialCaseInput {
                answer: case.selection.answer,
                unit: case.unit,
                source_frontier: case.source_frontier,
            };
            observations.push(TrialObservation {
                answer: input.answer,
                incumbent: execute(&record, &trial.incumbent, &input)?,
                candidate: execute(&record, &trial.candidate, &input)?,
            });
        }
        Ok(observations)
    }



    /// Commit the billed reads before asking eval authoring for its sufficiency
    /// card, so an unknown or failed assessment cannot erase measured cost.
    pub fn record_model_trial_measurements(&self, principal: EntityId, question: EntityId, id: EntityId, locality: CallerLocality, observations: Vec<TrialObservation>) -> Result<TrialEvidence> {
        let mut txn = self.store.env.write_txn()?;
        let result = self.record_model_trial_measurements_in_txn(&mut txn, principal, question, id, locality, observations)?;
        txn.commit()?;
        Ok(result)
    }

    pub(super) fn record_model_trial_measurements_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
        observations: Vec<TrialObservation>,
    ) -> Result<TrialEvidence> {
        let previous = self
            .model_trial_in_txn(txn, principal, question, id, locality)?
            .ok_or(Error::EntityNotFound)?;
        if !previous.execution_started {
            return Err(invalid("model trial has not been claimed"));
        }
        let measured = evidence::measure(&previous, observations)?;
        if let Some(existing) = &previous.evidence {
            return if existing == &measured {
                Ok(existing.clone())
            } else {
                Err(invalid("model trial measurements are immutable"))
            };
        }
        let mut trial = previous.clone();
        trial.evidence = Some(measured.clone());
        replace(self, txn, &previous, &trial)?;
        Ok(measured)
    }

    pub fn complete_model_trial(&self, principal: EntityId, question: EntityId, id: EntityId, locality: CallerLocality, assessment: TrialAssessment, now: u64) -> Result<ModelTrialReceipt> {
        let mut txn = self.store.env.write_txn()?;
        let result = self.complete_model_trial_in_txn(&mut txn, principal, question, id, locality, assessment, now)?;
        txn.commit()?;
        Ok(result)
    }

    pub(super) fn complete_model_trial_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        principal: EntityId,
        question: EntityId,
        id: EntityId,
        locality: CallerLocality,
        assessment: TrialAssessment,
        now: u64,
    ) -> Result<ModelTrialReceipt> {
        let previous = self
            .model_trial_in_txn(txn, principal, question, id, locality)?
            .ok_or(Error::EntityNotFound)?;
        if let Some(receipt) = &previous.receipt {
            return if receipt.assessment == assessment {
                Ok(receipt.clone())
            } else {
                Err(invalid("model trial receipt is immutable"))
            };
        }
        let measured = previous
            .evidence
            .as_ref()
            .ok_or_else(|| invalid("model trial has no measured evidence"))?;
        let mut quality = evidence::quality(&previous, measured, &assessment)?;
        if read_question_in_txn(self, txn, principal, question, None)?.is_none_or(|record| {
            record.definition.question.version != previous.request.question_version
        }) || matching_backend(self, txn, &previous.request.incumbent)?.as_ref()
            != Some(&previous.incumbent)
            || matching_backend(self, txn, &previous.request.candidate)?.as_ref()
                != Some(&previous.candidate)
        {
            quality = TrialQuality::Unknown;
        }
        let added_cost_per_thousand =
            (measured.candidate_cost_per_thousand - measured.incumbent_cost_per_thousand).max(0.0);
        let added_future_cost =
            added_cost_per_thousand * previous.request.future_units as f64 / 1_000.0;
        if !added_future_cost.is_finite() {
            return Err(invalid("model switch cost overflow"));
        }
        let receipt = ModelTrialReceipt {
            action: evidence::action(&previous, measured, quality),
            quality,
            assessment,
            candidate_cost_per_unit: measured.candidate_cost_per_thousand / 1_000.0,
            added_cost_per_thousand,
            added_future_cost,
            completed_at: now,
        };
        let mut trial = previous.clone();
        trial.receipt = Some(receipt.clone());
        replace(self, txn, &previous, &trial)?;
        Ok(receipt)
    }

    pub fn model_trials(
        &self,
        principal: EntityId,
        question: EntityId,
        locality: CallerLocality,
    ) -> Result<Vec<ModelTrial>> {
        let ids = {
            let txn = self.store.env.read_txn()?;
            TRIALS.scan_keys(&self.store, &txn, question.as_bytes())?
        };
        let mut trials = Vec::new();
        for (_, id) in ids {
            if let Some(trial) = self.model_trial(principal, question, id, locality)? {
                trials.push(trial);
            }
        }
        Ok(trials)
    }

    pub fn model_backend_quality_pin(
        &self,
        principal: EntityId,
        question: EntityId,
        version: u32,
        set: &TrialSetPin,
        pin: &ModelBackendPin,
        locality: CallerLocality,
    ) -> Result<Option<BackendQualityPin>> {
        if read_question(self, principal, question, None)?
            .is_none_or(|record| record.definition.question.version != version)
        {
            return Ok(None);
        }
        let current = {
            let txn = self.store.env.read_txn()?;
            backend(self, &txn, pin)?
        };
        let latest = self
            .model_trials(principal, question, locality)?
            .into_iter()
            .filter(|trial| {
                trial.request.question_version == version
                    && (&trial.request.incumbent == pin || &trial.request.candidate == pin)
            })
            .filter(|trial| trial.receipt.is_some())
            .max_by_key(|trial| (trial.receipt.as_ref().map(|r| r.completed_at), trial.id));
        let Some(trial) = latest else {
            return Ok(None);
        };
        if trial.request.set != *set
            || trial
                .receipt
                .as_ref()
                .is_none_or(|receipt| receipt.quality == TrialQuality::Unknown)
        {
            return Ok(None);
        }
        let measured = trial
            .evidence
            .as_ref()
            .ok_or(Error::CorruptedIndex("model trial evidence"))?;
        let is_candidate = &trial.request.candidate == pin;
        let brier_loss = if is_candidate {
            measured.candidate_loss
        } else {
            measured.incumbent_loss
        };
        let mut projected_cost = 0.0;
        for measurement in &measured.measurements {
            let cost = if is_candidate {
                &measurement.candidate_cost
            } else {
                &measurement.incumbent_cost
            };
            projected_cost += current.cost_receipt(cost.usage.clone(), cost.units)?.cost;
        }
        let cost_per_thousand = projected_cost * 1_000.0 / measured.measurements.len() as f64;
        if !cost_per_thousand.is_finite() {
            return Err(invalid("backend quality pin cost overflow"));
        }
        Ok(brier_loss.map(|brier_loss| BackendQualityPin {
            backend: current,
            question,
            question_version: version,
            trial: trial.id,
            set: trial.request.set,
            brier_loss,
            cost_per_thousand,
            measured_at: trial
                .receipt
                .as_ref()
                .expect("completed trial")
                .completed_at,
        }))
    }
}
