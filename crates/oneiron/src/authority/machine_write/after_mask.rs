//! Renewing a MACHINE claim's proof after the write door's secret mask
//! rewrote it in the same transaction (FIX 11356).

use ed25519_dalek::Signature;

use super::machine_claim_transcript;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::{ClaimCandidate, MachineWriteSignature, WriteEnvelope};

/// A MACHINE candidate the write door's secret mask
/// (`batch::secret_scan::mask_batch_ops`) rewrote in this transaction, after
/// its writer signed the unmasked bytes, is signed again here over its
/// post-mask body, so admission verifies what is stored. The caller passes
/// the pre-mask candidate only for an id the mask actually changed; every
/// other candidate keeps its proof byte for byte, as does every replayed or
/// replicated op, which the mask never rewrites. Renewal needs both the old
/// proof to verify over the pre-mask body and the signer the host retained
/// for the actor to hold the proof's key; otherwise the envelope is left as
/// it is, and admission decides as before. A bogus proof is never renewed
/// into a valid one here.
pub(crate) fn resign_machine_claim_after_mask_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    pre_mask: &ClaimCandidate,
    candidate: &ClaimCandidate,
    envelope: &mut WriteEnvelope,
    facet: EntityId,
) -> Result<()> {
    let Some(proof) = envelope.machine_signature() else {
        return Ok(());
    };
    if envelope.actor().actor_class() != EdgeActorClass::System {
        return Ok(());
    }
    let Some(vault_id) =
        super::super::authority_fold_readonly_for_store_in_txn(store, store.privacy_posture, txn)?
            .vault_id
    else {
        return Ok(());
    };
    // The old proof must bind the bytes the writer signed: verify it over
    // the pre-mask body exactly as admission verifies the stored one, and
    // renew nothing when it does not.
    let pre_body = pre_mask.clone().into_claim_body(envelope, facet)?;
    let key = match super::super::strong_ed25519_key(&proof.public_key) {
        Ok(key) => key,
        Err(_) => return Ok(()),
    };
    if key
        .verify_strict(
            &machine_claim_transcript(&vault_id, id, &pre_body)?,
            &Signature::from_bytes(&proof.signature),
        )
        .is_err()
    {
        return Ok(());
    }
    let signer = store
        .machine_write_signers
        .lock()
        .map_err(|_| Error::InvariantViolation("machine signer lock poisoned"))?
        .get(&envelope.actor().entity_ref())
        .cloned();
    let Some((public_key, sign)) = signer else {
        return Ok(());
    };
    if public_key != proof.public_key {
        return Ok(());
    }
    let body = candidate.clone().into_claim_body(envelope, facet)?;
    let signature = sign(&machine_claim_transcript(&vault_id, id, &body)?)?;
    if signature != proof.signature {
        *envelope = envelope
            .clone()
            .with_machine_signature(MachineWriteSignature {
                public_key,
                signature,
            });
    }
    Ok(())
}
