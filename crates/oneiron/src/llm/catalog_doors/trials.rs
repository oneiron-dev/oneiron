//! Owner model-trial doors.
//! Entry: Vault::run_model_trial_as_owner.
//! Vault is crate::Vault; trial records are owned by llm::model_trials.

use super::*;
use crate::claim::CallerLocality;
use crate::llm::decision::questions::{
    GraphUnitContext, QuestionRecord, answer_records, answer_records_in_txn, trial_unit_context,
    trial_unit_context_in_txn,
};
use crate::llm::model_trials::{ModelTrial, TrialAdmission, TrialReading};
use crate::llm::registry::PricedModelBackend;

fn trial_revision(vault: &Vault, txn: &heed::RoTxn<'_>, trial: EntityId) -> Result<String> {
    TRIAL_CATALOG
        .get(&vault.store, txn, &trial)?
        .ok_or(Error::EntityNotFound)
}

pub(super) fn owned_trial(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
    input: &ModelTrialRef,
    locality: CallerLocality,
) -> Result<(String, ModelTrial)> {
    let principal = owner.revalidate_in_txn(vault, txn)?;
    let trial = vault
        .model_trial_in_txn(txn, principal, input.question, input.trial, locality)?
        .ok_or(Error::EntityNotFound)?;
    let answers = answer_records_in_txn(vault, txn, principal, input.question)?;
    for case in &trial.cases {
        let answer = answers
            .iter()
            .find(|answer| answer.claim == case.selection.answer)
            .ok_or(Error::EntityNotFound)?;
        trial_unit_context_in_txn(vault, txn, principal, locality, answer)?;
    }
    Ok((trial_revision(vault, txn, trial.id)?, trial))
}

impl Vault {
    pub fn nominate_model_trial_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelTrialNominate,
        locality: CallerLocality,
    ) -> Result<ModelTrialView> {
        let mut txn = self.store.env.write_txn()?;
        let principal = owner.revalidate_in_txn(self, &txn)?;
        if input.request.principal != principal {
            return Err(invalid("model trials belong to the caller's own principal"));
        }
        let catalog = current(self, &txn, &input.catalog_revision)?;
        for pin in [&input.request.incumbent, &input.request.candidate] {
            let frozen = catalog
                .rows
                .iter()
                .find(|row| row.catalog.model == pin.model)
                .ok_or(Error::EntityNotFound)?;
            frozen.backend(pin)?;
            if frozen.is_stale()
                || self.model_registry_row_in_txn(&txn, &pin.model)?.as_ref() != Some(frozen)
            {
                return Err(Error::ConcurrentWrite(
                    "model catalog serving evidence changed",
                ));
            }
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let trial = self.prepare_model_trial_in_txn(&mut txn, input.request, locality, now)?;
        if TRIAL_CATALOG
            .get(&self.store, &txn, &trial.id)?
            .is_some_and(|id| id != input.catalog_revision)
        {
            return Err(invalid(
                "a repeated trial needs a new held-out set version for another catalog revision",
            ));
        }
        TRIAL_CATALOG.put(self, &mut txn, &trial.id, &input.catalog_revision)?;
        owned_trial(
            self,
            &txn,
            owner,
            &ModelTrialRef {
                question: trial.request.question,
                trial: trial.id,
            },
            locality,
        )?;
        txn.commit()?;
        Ok(ModelTrialView::of(input.catalog_revision, trial))
    }

    pub fn model_trial_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelTrialRef,
        locality: CallerLocality,
    ) -> Result<ModelTrialView> {
        let txn = self.store.env.read_txn()?;
        let (revision, trial) = owned_trial(self, &txn, owner, &input, locality)?;
        Ok(ModelTrialView::of(revision, trial))
    }

    pub fn approve_model_trial_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelTrialRef,
        locality: CallerLocality,
    ) -> Result<ModelTrialView> {
        let mut txn = self.store.env.write_txn()?;
        let (revision, previous) = owned_trial(self, &txn, owner, &input, locality)?;
        let trial = self.approve_model_trial_in_txn(
            &mut txn,
            previous.request.principal,
            input.question,
            input.trial,
            locality,
        )?;
        txn.commit()?;
        Ok(ModelTrialView::of(revision, trial))
    }

    pub fn run_model_trial_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelTrialRef,
        locality: CallerLocality,
        mut execute: impl FnMut(
            &QuestionRecord,
            &PricedModelBackend,
            &GraphUnitContext,
        ) -> Result<TrialReading>,
    ) -> Result<ModelTrialView> {
        let (revision, trial) = {
            let mut txn = self.store.env.write_txn()?;
            let (revision, plan) = owned_trial(self, &txn, owner, &input, locality)?;
            if plan.admission == TrialAdmission::AskExploration || plan.evidence.is_some() {
                return Ok(ModelTrialView::of(revision, plan));
            }
            current(self, &txn, &revision)?;
            let trial = self.claim_model_trial_in_txn(
                &mut txn,
                plan.request.principal,
                input.question,
                input.trial,
                locality,
            )?;
            txn.commit()?;
            (revision, trial)
        };
        let principal = trial.request.principal;
        let answers = answer_records(self, principal, input.question)?;
        let observations = self.execute_model_trial(&trial, |record, backend, case| {
            owner.revalidate(self)?;
            let answer = answers
                .iter()
                .find(|answer| answer.claim == case.answer)
                .ok_or(Error::EntityNotFound)?;
            let context = trial_unit_context(self, principal, locality, answer)?;
            execute(record, backend, &context)
        })?;
        let mut txn = self.store.env.write_txn()?;
        owned_trial(self, &txn, owner, &input, locality)?;
        self.record_model_trial_measurements_in_txn(
            &mut txn,
            principal,
            input.question,
            input.trial,
            locality,
            observations,
        )?;
        let stored = self
            .model_trial_in_txn(&txn, principal, input.question, input.trial, locality)?
            .ok_or(Error::EntityNotFound)?;
        txn.commit()?;
        Ok(ModelTrialView::of(revision, stored))
    }

    pub fn complete_model_trial_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelTrialComplete,
        locality: CallerLocality,
    ) -> Result<ModelTrialView> {
        let mut txn = self.store.env.write_txn()?;
        let principal = owner.revalidate_in_txn(self, &txn)?;
        let (revision, _) = owned_trial(
            self,
            &txn,
            owner,
            &ModelTrialRef {
                question: input.question,
                trial: input.trial,
            },
            locality,
        )?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        self.complete_model_trial_in_txn(
            &mut txn,
            principal,
            input.question,
            input.trial,
            locality,
            input.assessment,
            now,
        )?;
        let trial = self
            .model_trial_in_txn(&txn, principal, input.question, input.trial, locality)?
            .ok_or(Error::EntityNotFound)?;
        txn.commit()?;
        Ok(ModelTrialView::of(revision, trial))
    }
}
