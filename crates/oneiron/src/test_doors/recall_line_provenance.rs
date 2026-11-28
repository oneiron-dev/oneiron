//! Fixture writes for the line-provenance recall tests.

use crate::claim::{ClaimBody, EvidenceKind, EvidenceRef};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance, write_envelope_evidence};
use crate::{EntityId, TimeRange, Vault};

/// Lands a fixture CLAIM, including reserved bookkeeping predicates and a typed evidence TURN.
pub fn put_claim(
    vault: &Vault,
    id: &EntityId,
    mut body: ClaimBody,
    turn: Option<EntityId>,
    learned_at: u64,
    producer: EntityId,
) -> Result<()> {
    if let Some(turn) = turn {
        let evidence = crate::claim::public_evidence_value(&[EvidenceRef {
            entity: turn.to_hex(),
            kind: EvidenceKind::Turn,
            doc: turn.to_hex(),
            at: Vec::new(),
            span: None,
            quote_sha256: None,
        }])?;
        body.evidence = Some(rmpv::Value::Map(vec![("evidence_refs".into(), evidence)]));
    }
    let source = body.source.ok_or(crate::Error::InvalidClaimBody(
        "fixture claim source is missing",
    ))?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(producer, EdgeActorClass::Human),
        source,
        WriteProvenance::new("recall-line-provenance-fixture".into())?,
        body.approval,
    );
    body.evidence = Some(write_envelope_evidence(&envelope, body.evidence.take()));
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    vault.with_write_txn_grouped(|txn| {
        vault.put_reserved_claim_attributed_in_txn(txn, id, &body, occurred, learned_at, &envelope)
    })
}
