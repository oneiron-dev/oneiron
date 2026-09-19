//! Attempt-bound pack reads stamp their actual revision in the same transaction.

use super::{SkillLifecycle, SkillRecord};
use crate::attempt_queue::{AttemptId, AttemptQueue, ManifestEntry, ManifestKind};
use crate::claim::{ClaimApprovalStatus, ClaimBody, claim_surfaceable, encode_claim_body};
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Mid-run tier-2 record load. Merely listing a skill at tier 1 is not evidence of body use.
    pub fn load_attempt_skill(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        at: u64,
    ) -> Result<SkillRecord> {
        self.with_write_txn(|txn| {
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
                return Err(Error::EntityNotFound);
            }
            let record = self.read_skill_record_in_txn(txn, skill)?;
            if record.lifecycle_status != SkillLifecycle::Active
                || !matches!(
                    record.approval_status,
                    ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                )
            {
                return Err(Error::InvalidClaimBody(
                    "pack load requires an active approved skill",
                ));
            }
            AttemptQueue::new(self).append_manifest_entry_in_txn(
                txn,
                attempt,
                ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at),
            )?;
            Ok(record)
        })
    }

    /// Load one surfaceable actor claim; content digest is its revision, never a made-up counter.
    pub fn load_attempt_actor_claim(
        &self,
        attempt: AttemptId,
        claim: &EntityId,
        at: u64,
    ) -> Result<ClaimBody> {
        self.with_write_txn(|txn| {
            let body = self
                .get_claim_in_txn(txn, claim)?
                .ok_or(Error::EntityNotFound)?;
            if !body.predicate.starts_with("actor.")
                || !claim_surfaceable(&body)
                || body.valid_from.is_some_and(|start| start > at)
                || body.valid_to.is_some_and(|end| end <= at)
            {
                return Err(Error::InvalidClaimBody(
                    "pack load requires a current actor claim",
                ));
            }
            let revision = blake3::hash(&encode_claim_body(&body)?);
            AttemptQueue::new(self).append_manifest_entry_in_txn(
                txn,
                attempt,
                ManifestEntry::new(
                    ManifestKind::ActorClaim,
                    claim.to_hex(),
                    revision.to_hex().as_str(),
                    at,
                ),
            )?;
            Ok(body)
        })
    }
}
