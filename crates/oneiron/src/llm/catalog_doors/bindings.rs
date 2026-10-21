//! Owner model-binding doors.
//! Entry: Vault::propose_model_binding_as_owner.
//! Vault is crate::Vault; binding records are owned by llm::manifest.

use super::trials::owned_trial;
use super::*;
use crate::claim::CallerLocality;
use crate::llm::manifest::{ModelBinding, read_manifest};
use crate::llm::model_trials::ModelTrialAction;

fn proposal(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    id: EntityId,
) -> Result<ModelBindingProposal> {
    PROPOSALS
        .get(&vault.store, txn, &id)?
        .filter(|row| row.principal == principal)
        .ok_or(Error::EntityNotFound)
}

impl Vault {
    pub fn propose_model_binding_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelBindingPropose,
        locality: CallerLocality,
    ) -> Result<ModelBindingProposal> {
        let mut txn = self.store.env.write_txn()?;
        let principal = owner.revalidate_in_txn(self, &txn)?;
        let (revision, trial) = owned_trial(
            self,
            &txn,
            owner,
            &ModelTrialRef {
                question: input.question,
                trial: input.trial,
            },
            locality,
        )?;
        current(self, &txn, &revision)?;
        if trial.receipt.as_ref().is_none_or(|receipt| {
            !matches!(
                receipt.action,
                ModelTrialAction::Offer
                    | ModelTrialAction::AutoApprove
                    | ModelTrialAction::AskTradeoff
            )
        }) {
            return Err(invalid(
                "model binding proposal needs a sufficient held-out trial offer",
            ));
        }
        let manifest = read_manifest(&self.store, &txn)?.ok_or(Error::EntityNotFound)?;
        let previous = manifest.binding(input.role)?.clone();
        if previous.model != trial.request.incumbent.model
            || input.binding.model != trial.request.candidate.model
        {
            return Err(invalid("model binding does not match both trial arms"));
        }
        let mut measured = previous.clone();
        measured.model = trial.request.candidate.model.clone();
        if input.binding != measured {
            return Err(invalid(
                "a model trial changes only the measured role model, not other binding controls",
            ));
        }
        let mut proposed_manifest = manifest.clone();
        proposed_manifest
            .roles
            .insert(input.role, input.binding.clone());
        proposed_manifest.validate()?;
        for (_, saved) in PROPOSALS.scan(&self.store, &txn)? {
            if saved.principal == principal
                && saved.role == input.role
                && saved.trial.id == trial.id
            {
                return Ok(saved);
            }
        }
        let row = ModelBindingProposal {
            id: EntityId::now(),
            principal,
            role: input.role,
            previous,
            proposed: input.binding,
            trial: ModelTrialView::of(revision, trial),
            status: ModelBindingStatus::Proposed,
            proposed_at: crate::ports::recorded_at_in_txn(&self.store, &mut txn)?,
            settled_at: None,
        };
        PROPOSALS.put(self, &mut txn, &row.id, &row)?;
        txn.commit()?;
        Ok(row)
    }

    pub fn model_binding_proposal_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelBindingProposalRef,
        locality: CallerLocality,
    ) -> Result<ModelBindingProposal> {
        let txn = self.store.env.read_txn()?;
        let principal = owner.revalidate_in_txn(self, &txn)?;
        let row = proposal(self, &txn, principal, input.proposal)?;
        owned_trial(
            self,
            &txn,
            owner,
            &ModelTrialRef {
                question: row.trial.request.question,
                trial: row.trial.id,
            },
            locality,
        )?;
        Ok(row)
    }

    pub fn model_binding_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelBindingRead,
    ) -> Result<ModelBinding> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        read_manifest(&self.store, &txn)?
            .ok_or(Error::EntityNotFound)?
            .binding(input.role)
            .cloned()
    }

    pub fn accept_model_binding_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelBindingAccept,
        locality: CallerLocality,
    ) -> Result<ModelBindingProposal> {
        self.settle_model_binding_as_owner(
            owner,
            ModelBindingProposalRef {
                proposal: input.proposal,
            },
            locality,
            ModelBindingStatus::Accepted,
            input.teacher_approval.as_ref(),
        )
    }

    pub fn deny_model_binding_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelBindingProposalRef,
        locality: CallerLocality,
    ) -> Result<ModelBindingProposal> {
        self.settle_model_binding_as_owner(owner, input, locality, ModelBindingStatus::Denied, None)
    }

    fn settle_model_binding_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelBindingProposalRef,
        locality: CallerLocality,
        status: ModelBindingStatus,
        teacher_approval: Option<&crate::llm::manifest::TeacherProbeApproval>,
    ) -> Result<ModelBindingProposal> {
        let mut txn = self.store.env.write_txn()?;
        let principal = owner.revalidate_in_txn(self, &txn)?;
        let mut row = proposal(self, &txn, principal, input.proposal)?;
        if row.status == status {
            return Ok(row);
        }
        if row.status != ModelBindingStatus::Proposed {
            return Err(invalid("model binding proposal is already settled"));
        }
        let (_, trial) = owned_trial(
            self,
            &txn,
            owner,
            &ModelTrialRef {
                question: row.trial.request.question,
                trial: row.trial.id,
            },
            locality,
        )?;
        if status == ModelBindingStatus::Accepted {
            if crate::llm::decision::questions::read_question_in_txn(
                self,
                &txn,
                principal,
                trial.request.question,
                None,
            )?
            .is_none_or(|record| {
                record.definition.question.version != trial.request.question_version
            }) {
                return Err(Error::ConcurrentWrite("model trial question changed"));
            }
            current(self, &txn, &row.trial.catalog_revision)?;
            let candidate = self
                .model_registry_row_in_txn(&txn, &trial.request.candidate.model)?
                .ok_or(Error::EntityNotFound)?;
            if candidate.is_stale()
                || candidate.backend(&trial.request.candidate)? != trial.candidate
            {
                return Err(Error::ConcurrentWrite(
                    "model trial candidate serving evidence changed",
                ));
            }
            let mut manifest = read_manifest(&self.store, &txn)?.ok_or(Error::EntityNotFound)?;
            if manifest.binding(row.role)? != &row.previous {
                return Err(Error::ConcurrentWrite("incumbent model binding changed"));
            }
            manifest.roles.insert(row.role, row.proposed.clone());
            self.write_model_manifest_in_txn(&mut txn, &manifest, teacher_approval, None)?;
        }
        row.status = status;
        row.settled_at = Some(crate::ports::recorded_at_in_txn(&self.store, &mut txn)?);
        PROPOSALS.put(self, &mut txn, &row.id, &row)?;
        txn.commit()?;
        Ok(row)
    }
}
