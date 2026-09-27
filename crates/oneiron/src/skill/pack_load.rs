//! Attempt-bound pack reads stamp their actual revision in the same transaction.

use super::{SkillLifecycle, SkillRecord};
use crate::attempt_queue::{AttemptId, AttemptQueue, ManifestEntry, ManifestKind};
use crate::claim::{ClaimApprovalStatus, ClaimBody, claim_surfaceable, encode_claim_body};
use crate::{EntityId, Error, Result, Vault};

/// One actual tier-2 load. Native record-only skills have no file tree.
#[derive(Debug, Clone)]
pub struct LoadedSkillPack {
    pub record: SkillRecord,
    pub source_files: Option<Vec<crate::skill_hub::HubFile>>,
}

impl Vault {
    /// Bind one live attempt to the resident whose receipts it will produce,
    /// even if this attempt loads only shared skills or no skill at all.
    /// The marker is written before terminalization and is immutable.
    pub fn bind_resident_attempt(&self, attempt: AttemptId, resident: &EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            let row = AttemptQueue::new(self)
                .get_in_txn(txn, attempt)?
                .ok_or(Error::EntityNotFound)?;
            if row.state.is_terminal() {
                return Err(Error::InvalidClaimBody("cannot bind a terminal attempt"));
            }
            super::resident::bind_receipt_in_txn(
                self,
                txn,
                &crate::receipt::attempt_pack_receipt_id(&attempt),
                resident,
            )
        })
    }

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
        self.load_skill_pack_bound(attempt, skill, None, at)
    }

    /// Loads a resident fork only for its named owner. The check and manifest
    /// stamp share a transaction; an unscoped load cannot use a bound fork.
    pub fn load_resident_skill_pack(
        &self,
        attempt: AttemptId,
        resident: &EntityId,
        skill: &EntityId,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.load_skill_pack_bound(attempt, skill, Some(*resident), at)
    }

    fn load_skill_pack_bound(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        resident: Option<EntityId>,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.with_write_txn(|txn| {
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
                return Err(Error::EntityNotFound);
            }
            let record = self.read_skill_record_in_txn(txn, skill)?;
            if super::resident_of(&record)? != resident {
                return Err(Error::InvalidClaimBody(
                    "skill belongs to a different resident",
                ));
            }
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
            if let Some(resident) = resident {
                let receipt = crate::receipt::attempt_pack_receipt_id(&attempt);
                super::resident::bind_receipt_in_txn(self, txn, &receipt, &resident)?;
                super::resident::bind_skill_in_txn(self, txn, &receipt, skill)?;
            }
            AttemptQueue::new(self).append_manifest_entry_in_txn(
                txn,
                attempt,
                ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at),
            )?;
            Ok(LoadedSkillPack {
                record,
                source_files,
            })
        })
    }

    /// Pick a resident's best version with the shared UCB bandit and stamp
    /// exactly that entity's manifest/evidence binding in one pack-load call.
    /// A winner that is no longer active refuses at the load door rather than
    /// silently loading a runner-up under an out-of-date candidate ranking.
    pub fn select_and_load_resident_skill_pack(
        &self,
        attempt: AttemptId,
        resident: &EntityId,
        versions: &[EntityId],
        at: u64,
    ) -> Result<Option<(EntityId, LoadedSkillPack)>> {
        let Some((winner, _)) =
            crate::skill_reliability::rank_resident_skill_versions(self, resident, versions)?
                .into_iter()
                .next()
        else {
            return Ok(None);
        };
        let pack = self.load_resident_skill_pack(attempt, resident, &winner, at)?;
        Ok(Some((winner, pack)))
    }

    /// Load one surfaceable actor claim; content digest is its revision, never a made-up counter.
    pub fn load_attempt_actor_claim(
        &self,
        attempt: AttemptId,
        claim: &EntityId,
        at: u64,
    ) -> Result<ClaimBody> {
        self.load_actor_claim_bound(attempt, claim, None, at)
    }

    /// Loads one resident's self-model, never another actor's lesson or fit.
    pub fn load_resident_actor_claim(
        &self,
        attempt: AttemptId,
        resident: &EntityId,
        claim: &EntityId,
        at: u64,
    ) -> Result<ClaimBody> {
        self.load_actor_claim_bound(attempt, claim, Some(*resident), at)
    }

    fn load_actor_claim_bound(
        &self,
        attempt: AttemptId,
        claim: &EntityId,
        resident: Option<EntityId>,
        at: u64,
    ) -> Result<ClaimBody> {
        self.with_write_txn(|txn| {
            let body = self
                .get_claim_in_txn(txn, claim)?
                .ok_or(Error::EntityNotFound)?;
            if body.predicate.starts_with("actor.")
                && !matches!(&body.subject,
                    crate::claim::ClaimSubject::Entity(actor) if Some(*actor) == resident)
            {
                return Err(Error::InvalidClaimBody(
                    "actor self-model belongs to a different resident",
                ));
            }
            if !body.predicate.starts_with("actor.")
                || !claim_surfaceable(&body)
                || body.valid_from.is_some_and(|start| start > at)
                || body.valid_to.is_some_and(|end| end <= at)
            {
                return Err(Error::InvalidClaimBody(
                    "pack load requires a current actor claim",
                ));
            }
            if let Some(resident) = resident {
                super::resident::bind_receipt_in_txn(
                    self,
                    txn,
                    &crate::receipt::attempt_pack_receipt_id(&attempt),
                    &resident,
                )?;
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
