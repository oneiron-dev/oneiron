//! Where a recipe's output lands (FIX 8725, FIX 8726).
//!
//! An output the Gate allows applies at once, as the Dreamer's other output
//! does (OF-023, owner ruling 10-18: "autoapply + revert rather than
//! holdout"): it lands Auto and the owner reverts it as any Dreamer change.
//! It is held Proposed for the owner's review only where a hold is due: the
//! Gate parks or refuses the applied write (a critical class, a policy that
//! keeps the Dreamer at Proposed), or the evidence is imported, which waits
//! in its import's review (ARCH-0027). The held write is the one recipes
//! always made, so nothing that landed before stops landing.
//!
//! The output is born in the one project its evidence sits in. The write
//! that commits it reads the evidence again, its bytes, trust and project,
//! and refuses when any moved since the draft. Evidence in no single project
//! keeps today's placement, the default project.

use super::{
    Evidence, RESULT, RecipeResult, cached_result, claim_hash, envelope, invalid, provenance,
    read_evidence,
};
use crate::claim::ClaimSource;
use crate::dreamer_runner::{DreamerAdmittedAttempt, WeaveRecipePin};
use crate::write_envelope::WriteActor;
use crate::{ClaimApprovalStatus, ClaimCandidate, EntityId, Error, Result, TimeRange, Vault};

/// A drafted output, with the evidence it was drafted from.
pub(super) struct Drafted<'a> {
    pub(super) attempt: &'a DreamerAdmittedAttempt,
    pub(super) pin: &'a WeaveRecipePin,
    pub(super) actor: WriteActor,
    pub(super) id: EntityId,
    pub(super) candidate: ClaimCandidate,
    pub(super) evidence: &'a Evidence,
    /// When the output is born: its occurrence and its learned time.
    pub(super) at: TimeRange,
}

/// Lands `drafted` applied where the Gate allows it, else held Proposed,
/// with its committed result in the same write.
pub(super) fn land(vault: &Vault, drafted: &Drafted<'_>) -> Result<()> {
    if drafted.evidence.source != ClaimSource::Imported {
        match write(vault, drafted, ClaimApprovalStatus::Auto) {
            // The Gate held the applied write back, whatever its reason: the
            // output is held instead, as every recipe output was before.
            Err(Error::Gate(_)) => {}
            landed => return landed,
        }
    }
    write(vault, drafted, ClaimApprovalStatus::Proposed)
}

/// One write of `drafted` under `approval`: the evidence read again, the
/// claim born in the evidence's project, and the result bound to the claim
/// as it landed.
fn write(vault: &Vault, drafted: &Drafted<'_>, approval: ClaimApprovalStatus) -> Result<()> {
    let Drafted {
        attempt,
        pin,
        actor,
        id,
        candidate,
        evidence,
        at,
    } = drafted;
    vault.with_write_txn_grouped(|txn| {
        if cached_result(vault, txn, attempt, pin, *actor, id)? {
            return Ok(());
        }
        let current = read_evidence(vault, txn, *actor, pin.evidence)?;
        if current.source != evidence.source
            || current.hash != evidence.hash
            || current.project != evidence.project
        {
            return Err(invalid());
        }
        let mut candidate = candidate.clone();
        if let Some(project) = evidence.project {
            let facet = crate::batch::claim_candidate_apply::claim_candidate_birth_facet(
                &vault.store,
                txn,
                id,
            )?;
            candidate = candidate.with_scope_stamps(facet, project);
        }
        let mut envelope = envelope(
            *actor,
            evidence.source,
            provenance(pin, attempt, evidence.hash)?,
            approval,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(id, candidate, &envelope, *at, at.start)
            .apply_recording_gate_decisions(txn)?;
        let body = vault.get_claim_in_txn(txn, id)?.ok_or_else(invalid)?;
        if evidence
            .project
            .is_some_and(|project| body.scope_project != project)
        {
            return Err(invalid());
        }
        let result = RecipeResult {
            version: 1,
            pin_hash: pin.binding_hash(),
            actor: actor.entity_ref().to_hex(),
            source: evidence.source.as_str().into(),
            evidence_hash: evidence.hash,
            claim_hash: claim_hash(&body)?,
            applied: body.approval == ClaimApprovalStatus::Auto,
        };
        RESULT.put(&vault.store, txn, &attempt.status.attempt.id, &result)
    })
}
