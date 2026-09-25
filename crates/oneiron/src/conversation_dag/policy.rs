//! Actor-bound write-policy preflight for the append operation.

use super::AppendRecord;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::error::Result;
use crate::{EntityId, Vault, WriteEnvelope, WriteProvenance};
use heed::RwTxn;
use rmpv::Value;

pub(super) fn check_append_policy(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    input: &AppendRecord,
    bytes: &[u8],
) -> Result<()> {
    let envelope = WriteEnvelope::new(
        input.actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("kind"),
            Value::from("conversation_append"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    // A synthetic operation body is checked, never stored as an extra CLAIM.
    // This is the same operation-effect mode as the typed memory write doors.
    let mut body = ClaimBody::new(
        "conversation.append_record",
        ClaimSubject::Entity(input.conversation),
        Value::Map(vec![
            (Value::from("record"), Value::from(id.to_hex())),
            (Value::from("body"), Value::Binary(bytes.to_vec())),
            (
                Value::from("parent"),
                input.parent.map_or(Value::Nil, |p| Value::from(p.to_hex())),
            ),
            (Value::from("advance"), Value::Boolean(input.advance)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(envelope.source());
    body.evidence = Some(crate::write_envelope::write_envelope_evidence(
        &envelope, None,
    ));
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    crate::gate::check_claim_policy_for_write(
        &vault.store,
        txn,
        id,
        crate::gate::ClaimGateWrite::plain(&body, Some(&envelope)),
        &policy,
        crate::gate::GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent: false,
            include_source_in_gate_input: true,
        },
        true,
    )
}
