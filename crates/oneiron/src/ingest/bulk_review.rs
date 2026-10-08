//! One import-time human act for the exact set of imported claim candidates.

use std::collections::HashSet;

use serde_json::Value;

use super::admission::{imported_candidate, json_to_msgpack_value};
use super::{INGEST_SOURCE_REGISTRY, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution};
use crate::claim::ClaimApprovalStatus;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, ConsentReceipt,
    EffectFacts, GrantBound,
};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};

/// One resolved imported claim. Resolution and ids are fixed before consent is requested.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedClaimBatchEntry {
    pub claim_id: EntityId,
    pub subject: EntityId,
    pub source_record_id: String,
    pub predicate: String,
    pub value: Value,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// Exact import request; a new request id requires a new human consent act.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedClaimBatch {
    pub request_id: EntityId,
    pub source_id: String,
    pub entries: Vec<ImportedClaimBatchEntry>,
}

/// Whole-batch outcome, bound to the same effect digest the owner approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedClaimBatchReceipt {
    pub approval_digest: String,
    pub approval: ClaimApprovalStatus,
    pub claim_ids: Vec<EntityId>,
}

impl Vault {
    /// Describe the exact batch for one authenticated-owner `approve_once` act.
    /// Changing any member, subject, value, time, source or request changes the digest.
    ///
    /// # Errors
    /// Refuses empty batches, unknown sources, duplicate ids and malformed evidence.
    pub fn imported_claim_batch_effect(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedClaimBatch,
    ) -> Result<ComposedEffect> {
        validate_batch(batch)?;
        let hash = content_hash(batch)?.to_hex();
        let bound = GrantBound::action(
            ActorBound::new(owner.actor().to_hex())?,
            ActionClass::new("claims.import.review")?,
            ActionEnvelope::new([
                format!("request:{}", batch.request_id.to_hex()),
                format!("source:{}", batch.source_id),
                format!("claims:{}", batch.entries.len()),
                format!("content:{hash}"),
            ])?,
        )?;
        ComposedEffect::new(EffectFacts::new("claims.import.review")?)
            .with_action_requirement(bound)
    }

    /// Atomically admit the entire batch as Proposed without consent, or Approved
    /// with one exact approve-once act. Never creates a per-claim approval queue.
    /// The consent marker is spent only when all candidates pass their Gate writes.
    ///
    /// # Errors
    /// An invalid owner, bad target, or failed Gate write leaves no imported
    /// claims or consumed consent. A changed valid batch cannot use an earlier
    /// batch's approval: it remains Proposed.
    pub fn admit_imported_claim_batch(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedClaimBatch,
    ) -> Result<ImportedClaimBatchReceipt> {
        let digest = self.imported_claim_batch_effect(owner, batch)?.digest();
        self.with_write_txn(|txn| self.admit_imported_claim_batch_in_txn(txn, owner, batch, digest))
    }

    /// The owner's one act for the whole batch: the approve-once receipt and
    /// the Approved admission of every candidate commit in ONE write
    /// transaction, or neither does.
    ///
    /// # Errors
    /// As [`Vault::admit_imported_claim_batch`], plus
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent)
    /// when any owner already approved or declined this exact batch.
    pub fn approve_imported_claim_batch(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedClaimBatch,
    ) -> Result<ImportedClaimBatchReceipt> {
        let digest = self.imported_claim_batch_effect(owner, batch)?.digest();
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.approve_once_in_txn(txn, owner, digest)?;
            self.admit_imported_claim_batch_in_txn(txn, owner, batch, digest)
        })
    }

    /// The owner's refusal of the whole batch: one denial receipt, nothing
    /// admitted. Like a consented admission it takes the batch's one decision
    /// slot, so it is final whichever owner made it.
    ///
    /// # Errors
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent)
    /// when any owner already approved or declined this exact batch; the
    /// earlier decision stands.
    pub fn decline_imported_claim_batch(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedClaimBatch,
    ) -> Result<ConsentReceipt> {
        let digest = self.imported_claim_batch_effect(owner, batch)?.digest();
        let slot = decision_slot(batch)?;
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let receipt = self.deny_consent_in_txn(txn, owner, digest)?;
            self.take_decision_slot_in_txn(txn, &slot, receipt.decision_id())?;
            Ok(receipt)
        })
    }

    fn admit_imported_claim_batch_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        batch: &ImportedClaimBatch,
        digest: crate::consent::EffectDigest,
    ) -> Result<ImportedClaimBatchReceipt> {
        owner.revalidate_in_txn(self, txn)?;
        let authorization =
            crate::consent::approve_once_authorization_in_txn(&self.store, txn, &digest)?;
        let approval = if authorization.is_some() {
            // The approval is this batch's one decision, whichever owner
            // made it; an earlier approval or decline refuses it first.
            let approving =
                crate::consent::approve_once_decision_in_txn(&self.store, txn, &digest)?
                    .ok_or(Error::CorruptedIndex("consent approve-once marker"))?;
            self.take_decision_slot_in_txn(txn, &decision_slot(batch)?, approving)?;
            ClaimApprovalStatus::Approved
        } else {
            ClaimApprovalStatus::Proposed
        };
        let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
        // A fresh id is required. Consent names one immutable candidate set;
        // it must not authorize replacing an earlier import or another kind.
        for entry in &batch.entries {
            if self.local_hard_delete_marker_exists_in_txn(txn, &entry.claim_id)?
                || self.get_raw_in(txn, &entry.claim_id)?.is_some()
            {
                return Err(Error::InvalidClaimBody("import claim id is not fresh"));
            }
        }
        // Proposed is the ordinary Gate admission path. With owner consent,
        // resolve these same candidates against the attached Gate bindings
        // before committing anything, in this same writer transaction.
        for phase in 0..if authorization.is_some() { 2 } else { 1 } {
            let phase_approval = if phase == 0 {
                ClaimApprovalStatus::Proposed
            } else {
                ClaimApprovalStatus::Approved
            };
            let mut builder = self.batch_in();
            for entry in &batch.entries {
                let admission = ImportedEvidenceAdmission::proposed(
                    &batch.source_id,
                    entry.claim_id,
                    ImportedEvidenceEntityResolution::subject(entry.subject),
                    actor,
                    entry.occurred,
                    entry.learned_at,
                )
                .with_approval(phase_approval);
                let (candidate, envelope) = imported_candidate(
                    &entry.predicate,
                    json_to_msgpack_value(&entry.value),
                    &entry.source_record_id,
                    &admission,
                )?;
                builder = builder.claim_candidate(
                    &entry.claim_id,
                    candidate,
                    &envelope,
                    entry.occurred,
                    entry.learned_at,
                );
            }
            builder.apply(txn)?;
        }
        if let Some(authorization) = &authorization {
            crate::consent::spend_approve_once_in_txn(&self.store, txn, authorization)?;
        } else {
            // No per-claim review tray: an unconsented import stays Proposed
            // until a new exact batch is explicitly consented at import time.
            for entry in &batch.entries {
                self.store
                    .delete_pending_gate_consent_in_txn(txn, &entry.claim_id)?;
            }
        }
        Ok(ImportedClaimBatchReceipt {
            approval_digest: digest.to_hex(),
            approval,
            claim_ids: batch.entries.iter().map(|entry| entry.claim_id).collect(),
        })
    }
}

/// The batch's claims, hashed: every member, subject, value and time.
fn content_hash(batch: &ImportedClaimBatch) -> Result<blake3::Hash> {
    let content = serde_json::to_vec(
        &batch
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.claim_id.to_hex(),
                    entry.subject.to_hex(),
                    &entry.source_record_id,
                    &entry.predicate,
                    &entry.value,
                    entry.occurred.start,
                    entry.occurred.end,
                    entry.learned_at,
                )
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|_| Error::InvalidClaimBody("import batch encoding failed"))?;
    Ok(blake3::hash(&content))
}

/// The batch's one decision slot: the exact batch, whichever owner decides.
/// The consent digest also binds the deciding owner, so it cannot serve.
fn decision_slot(batch: &ImportedClaimBatch) -> Result<[u8; 32]> {
    let named = serde_json::to_vec(&(
        batch.request_id.to_hex(),
        &batch.source_id,
        batch.entries.len(),
        content_hash(batch)?.to_hex().as_str(),
    ))
    .map_err(|_| Error::InvalidClaimBody("import batch encoding failed"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron claims.import.review decision v1");
    hasher.update(&named);
    Ok(*hasher.finalize().as_bytes())
}

fn validate_batch(batch: &ImportedClaimBatch) -> Result<()> {
    if batch.entries.is_empty() {
        return Err(Error::InvalidClaimBody("empty imported claim batch"));
    }
    if !INGEST_SOURCE_REGISTRY
        .get_config(&batch.source_id)
        .is_some_and(|config| {
            config.trust_ceiling.claim_source == crate::claim::ClaimSource::Imported
        })
    {
        return Err(Error::InvalidClaimBody("unknown imported claim source"));
    }
    let mut ids = HashSet::new();
    for entry in &batch.entries {
        if !ids.insert(entry.claim_id) {
            return Err(Error::InvalidClaimBody("duplicate imported claim id"));
        }
        if entry.source_record_id.trim().is_empty() {
            return Err(Error::InvalidClaimBody(
                "imported evidence missing source_record_id",
            ));
        }
        if entry.predicate == crate::claim::KEY_VALUE_PREDICATE {
            return Err(crate::error::ClaimError::KeyValueWriteRequiresOwnedDoor.into());
        }
    }
    Ok(())
}
