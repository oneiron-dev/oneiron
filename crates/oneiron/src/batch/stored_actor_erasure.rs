//! Immediate materialization of an already-authorized actor erasure.
use super::{ApplyOpsGateMode, VerifiedClaimTransition, apply_ops_with_gate_mode};
use crate::deletion::ActorErasureWriter;
use crate::{EntityId, Result};

pub(crate) fn materialize_stored_section_fit_actor_erasure_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
    receipt: &EntityId,
) -> Result<bool> {
    let Some((ops, proof)) =
        VerifiedClaimTransition::stored_section_fit_actor_erasure(erase, receipt)?
    else {
        return Ok(false);
    };
    let (vault, wtxn, _) = erase.parts();
    apply_ops_with_gate_mode(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        ops,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        ApplyOpsGateMode::new(false, true).with_verified_claim_transitions(vec![proof]),
    )?;
    Ok(true)
}
