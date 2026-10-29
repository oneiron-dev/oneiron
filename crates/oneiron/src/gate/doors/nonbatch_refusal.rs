//! A non-batch reference refusal, carried out of its failed write and
//! receipted outside it (FIX 9109).
//!
//! A reference Deny at a non-batch door (the Dreamer attachment) is recorded
//! inside the write transaction that then rolls back, so no refusal receipt
//! survives. A reference refusal leaves its receipt outside the rolled-back
//! transaction instead, as a batch per-element deny already does: the door
//! carries the denied slot's pointer out of the failed write, and the caller
//! receipts it on a small write of its own once the write has rolled back.
//! The caller still hears today's refusal either way, and a receipt that
//! cannot be written is logged, never a new failure.

use super::{ClaimGateWrite, GateWriteMode, RecordedClaimGateDecision};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::gate::decision::GateReasonCode;
use crate::gate::resolution::PolicyManifestResolution;
use crate::store::Store;
use crate::write_envelope::WriteActor;

/// [`super::check_claim_policy_for_write_with_record_with_reader`] that also
/// carries the reference refusal out of the failed write (FIX 9109).
///
/// On the door's unresolved-record-reference denial, the denied slot's
/// pointer is read from the failed write's own snapshot, while that
/// transaction is still open, into `carried_refusal`, so the caller can
/// receipt the refusal with [`receipt_carried_reference_refusal`] once the
/// write has rolled back. Every other outcome leaves `carried_refusal`
/// alone, and the caller hears the door's own result either way: a slot
/// that no longer reads carries nothing but changes no error.
#[expect(
    clippy::too_many_arguments,
    reason = "the record seam's arguments plus the writer's own scoped read and the carried refusal"
)]
pub(crate) fn check_claim_policy_for_write_with_record_with_reader_carrying_refusal(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    reader: &crate::claim::ScopedRead<'_>,
    carried_refusal: &mut Option<String>,
) -> Result<()> {
    let body = write.body;
    match super::check_claim_policy_for_write_with_record_with_reader(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        recorded_decision,
        reader,
    ) {
        Err(err) if is_reference_denial(&err) => {
            if let Ok(Some(field)) = super::unresolved_claim_reference(reader, &*wtxn, body) {
                *carried_refusal = Some(field);
            }
            Err(err)
        }
        outcome => outcome,
    }
}

/// Whether `err` is the claim gate's unresolved-record-reference denial.
fn is_reference_denial(err: &Error) -> bool {
    let Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) = err else {
        return false;
    };
    reason_codes.contains(&GateReasonCode::DenyUnresolvedRecordReference.as_str())
}

/// Receipts a reference refusal the non-batch door carried out of its failed
/// write (FIX 9109): `writer`'s, through `row`, at the carried `field`, on a
/// small write of its own, through the batch path's receipt fn, so it
/// survives the write it answers. The caller runs it once the refused write
/// has rolled back and still hears that refusal. Answers the receipt's id;
/// a receipt that cannot be written is logged and answers `None`, and
/// changes nothing else.
pub(crate) fn receipt_carried_reference_refusal(
    vault: &Vault,
    writer: WriteActor,
    row: &'static str,
    field: String,
) -> Option<String> {
    let memory = vault.memory(writer.entity_ref(), writer.actor_class());
    let facts = crate::receipt::ReferenceRefusalFacts {
        actor: writer.entity_ref(),
        actor_class: writer.actor_class(),
        row,
        field,
        outcome: crate::receipt::ReferenceOutcome::Refused,
    };
    crate::receipt::receipt_refusal(
        &memory,
        &facts,
        crate::memory::RefusalReason::InventedReference,
    )
    .unwrap_or_else(|error| {
        tracing::warn!(%error, row, "a refusal went unreceipted");
        None
    })
}
