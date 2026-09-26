//! Attempt-bound pack reads stamp their actual revision in the same transaction.

use super::{SkillLifecycle, SkillRecord};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ManifestEntry, ManifestKind,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, claim_surfaceable, encode_claim_body};
use crate::{EntityId, Error, Result, Vault};

/// One actual tier-2 load. Native record-only skills have no file tree.
#[derive(Debug, Clone)]
pub struct LoadedSkillPack {
    pub record: SkillRecord,
    pub source_files: Option<Vec<crate::skill_hub::HubFile>>,
}

impl Vault {
    /// Mid-run tier-2 record load. Merely listing a skill at tier 1 is not evidence of body use.
    pub fn load_attempt_skill(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        at: u64,
    ) -> Result<SkillRecord> {
        Ok(self.load_attempt_skill_pack(attempt, skill, at)?.record)
    }

    /// Loads the exact stored SKILL.md/scripts when present and stamps one row
    /// atomically. A failed package check never records a successful load.
    pub fn load_attempt_skill_pack(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.with_write_txn(|txn| self.load_skill_pack_in_txn(txn, attempt, skill, at))
    }

    /// The callable door checks the caller's live lease generation in the
    /// SAME transaction that loads and stamps the source. A stale worker
    /// cannot append a manifest entry on a re-leased or terminal attempt.
    pub(crate) fn load_leased_callable_skill_pack(
        &self,
        leased: &AttemptRecord,
        skill: &EntityId,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.with_write_txn(|txn| {
            let current = AttemptQueue::new(self)
                .get_in_txn(txn, leased.id)?
                .ok_or(Error::EntityNotFound)?;
            if current.state != AttemptState::Leased
                || current.lease_owner.is_none()
                || current.lease_owner != leased.lease_owner
                || current.attempt_count != leased.attempt_count
            {
                return Err(Error::InvalidClaimBody(
                    "callable execution requires the caller's live attempt lease",
                ));
            }
            self.load_skill_pack_in_txn(txn, leased.id, skill, at)
        })
    }

    fn load_skill_pack_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        skill: &EntityId,
        at: u64,
    ) -> Result<LoadedSkillPack> {
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
        let source_files = self
            .runtime_skill_package_in_txn(txn, skill, &record)?
            .map(|package| package.files);
        AttemptQueue::new(self).append_manifest_entry_in_txn(
            txn,
            attempt,
            ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at),
        )?;
        Ok(LoadedSkillPack {
            record,
            source_files,
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
