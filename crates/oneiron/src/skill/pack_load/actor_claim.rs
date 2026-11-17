//! Actor-claim loads on an attempt: one surfaceable `actor.*` claim, a
//! resident's own self-model only, its content digest stamped as the
//! manifest revision and the claim captured in the read set.

use crate::attempt_queue::{AttemptId, AttemptQueue, ManifestEntry, ManifestKind, ReadSetProducer};
use crate::claim::{ClaimBody, claim_surfaceable, encode_claim_body};
use crate::{EntityId, Error, Result, Vault};

impl Vault {
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
        self.with_write_txn_grouped(|txn| {
            let body = self
                .get_claim_in_txn(txn, claim)?
                .ok_or(Error::EntityNotFound)?;
            if body.predicate.starts_with("actor.") {
                let allowed = match resident {
                    Some(resident) => {
                        // A resident's shells merged into it read as its own
                        // (FIX 9073): the redirect authority names them.
                        crate::skill_reliability::redirect_equivalent_subjects_in_txn(
                            self, &*txn, &resident,
                        )?
                    }
                    None => Vec::new(),
                };
                if !matches!(&body.subject,
                    crate::claim::ClaimSubject::Entity(actor) if allowed.contains(actor))
                {
                    return Err(Error::InvalidClaimBody(
                        "actor self-model belongs to a different resident",
                    ));
                }
            }
            // A claim whose every cited TURN is erased has no live support,
            // however late it replicated (FIX 8643): it is not loaded.
            if !body.predicate.starts_with("actor.")
                || !claim_surfaceable(&body)
                || !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, txn, claim)?
                || !crate::claim::has_live_support_in_txn(&self.store, txn, &body)?
                || body.valid_from.is_some_and(|start| start > at)
                || body.valid_to.is_some_and(|end| end <= at)
            {
                return Err(Error::InvalidClaimBody(
                    "pack load requires a current actor claim",
                ));
            }
            if let Some(resident) = resident {
                super::super::resident::bind_receipt_in_txn(
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
            // Capture only (FIX 7017): the CLAIM this load read.
            self.record_attempt_sources_best_effort_in_txn(
                txn,
                attempt,
                ReadSetProducer::ACTOR_CLAIM,
                Some(vec![*claim]),
            );
            Ok(body)
        })
    }
}
