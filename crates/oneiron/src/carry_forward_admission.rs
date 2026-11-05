//! The engine side of carry-forward claims (`write_envelope::carry_forward`):
//! the confidence floor enforced at local put admission, which reads the
//! stored prior claim and the policy manifest, and the vault's typed
//! carry-forward write door.

use oneiron_contracts::claim::ClaimApprovalStatus;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::carry_forward::{
    CarryForwardClaim, CarryForwardKind, actor_from_evidence,
};
use crate::write_envelope::claim_body::ClaimBody;

/// Enforce the floor on local put admission. Replay validates the claim shape,
/// but receives final CRDT heads without their local transition history. A
/// local below-floor final state requires a sealed proof from its canonical
/// transition validator; new generic/raw Auto claims are refused.
/// Admission axes travel together so the proof cannot be paired with the
/// wrong target metadata at the common materialization door.
pub(crate) struct CarryForwardAdmission<'a> {
    pub(crate) envelope: Option<&'a WriteEnvelope>,
    pub(crate) transition: Option<&'a crate::batch::VerifiedClaimTransition>,
    pub(crate) occurred: TimeRange,
    pub(crate) learned_at: u64,
}

pub(crate) fn validate_admission(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    admission: CarryForwardAdmission<'_>,
) -> Result<()> {
    let Some(kind) = CarryForwardKind::from_predicate(&body.predicate) else {
        return Ok(());
    };
    let prior = prior_claim(store, txn, id)?;
    let actor = admission
        .envelope
        .map(|envelope| envelope.actor().entity_ref())
        .or_else(|| {
            prior
                .as_ref()
                .and_then(|prior| prior.evidence.as_ref())
                .and_then(actor_from_evidence)
        });
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    if body.confidence >= policy.carry_forward_floor(kind, actor)
        || body.approval == ClaimApprovalStatus::Proposed
    {
        return Ok(());
    }
    if let Some(proof) = admission.transition
        && proof.matches_put(
            store,
            txn,
            id,
            body,
            admission.occurred,
            admission.learned_at,
        )?
    {
        return Ok(());
    }
    Err(Error::InvalidClaimBody(
        "carry-forward confidence requires verified lifecycle transition",
    ))
}

fn prior_claim(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("carry-forward prior header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    crate::write_envelope::claim_body::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        .map(Some)
}

impl Vault {
    /// Write one typed forward claim through the standard envelope and Gate.
    /// Low-confidence Auto requests are forced to Proposed. An explicit
    /// approval or rejection is not silently rewritten; the existing claim
    /// lifecycle and its authenticated consent door must authorize it.
    ///
    /// # Errors
    /// Returns a validation, authority or Gate error on an invalid write.
    pub fn put_carry_forward_claim(
        &self,
        id: &EntityId,
        claim: CarryForwardClaim,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if !matches!(
            envelope.approval(),
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
        ) {
            return Err(Error::InvalidClaimBody(
                "carry-forward consent must use the authenticated resolution door",
            ));
        }
        let candidate = claim.clone().into_candidate()?;
        self.with_write_txn_grouped(|txn| {
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            let held = claim.confidence
                < policy.carry_forward_floor(claim.kind, Some(envelope.actor().entity_ref()));
            let envelope = if held && envelope.approval() == ClaimApprovalStatus::Auto {
                envelope
                    .clone()
                    .with_approval(ClaimApprovalStatus::Proposed)
            } else {
                envelope.clone()
            };
            self.batch_in()
                .claim_candidate(id, candidate, &envelope, occurred, learned_at)
                .apply_recording_gate_decisions(txn)
        })
    }
}
