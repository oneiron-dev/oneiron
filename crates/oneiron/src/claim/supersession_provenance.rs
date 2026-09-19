//! Runner-owned companion claims; structural taint mirrors also run on replay.
use super::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_evidence_taint};
use crate::write_envelope::{
    ClaimCandidate, SourceLineage, WriteActor, WriteEnvelope, WriteProvenance,
};
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;

const PREDICATE: &str = "core.supersession.provenance";
fn get<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(rows) = value else {
        return None;
    };
    let mut rows = rows.iter().filter(|(key, _)| key.as_str() == Some(name));
    let value = &rows.next()?.1;
    rows.next().is_none().then_some(value)
}
fn id(value: &Value) -> Result<EntityId> {
    let Value::Binary(raw) = value else {
        return Err(Error::InvalidClaimBody("supersession entity ref"));
    };
    EntityId::from_bytes(
        raw.as_slice()
            .try_into()
            .map_err(|_| Error::InvalidClaimBody("supersession entity ref"))?,
    )
}
pub(super) fn envelope(body: &ClaimBody) -> Result<WriteEnvelope> {
    let malformed = || Error::InvalidClaimBody("supersession envelope missing");
    let evidence = body.evidence.as_ref().ok_or_else(malformed)?;
    let actor = id(get(evidence, "actor_entity_ref").ok_or_else(malformed)?)?;
    let class = get(evidence, "actor_class")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .and_then(crate::edge::EdgeActorClass::try_from_u8)
        .ok_or_else(malformed)?;
    let source = body.source.ok_or_else(malformed)?;
    let mut lineage = SourceLineage::of(source);
    if let Some(Value::Array(values)) = get(evidence, "lineage") {
        for value in values {
            lineage = lineage.with(
                value
                    .as_str()
                    .and_then(ClaimSource::parse)
                    .ok_or_else(malformed)?,
            );
        }
    }
    Ok(WriteEnvelope::with_lineage(
        WriteActor::new(actor, class),
        source,
        WriteProvenance::new(get(evidence, "provenance").ok_or_else(malformed)?.clone())?,
        ClaimApprovalStatus::Proposed,
        lineage,
    ))
}
fn companion_id(new: &EntityId, old: &EntityId, predicate: &str) -> EntityId {
    let mut h = blake3::Hasher::new();
    h.update(b"oneiron.supersession.companion.v1");
    h.update(new.as_bytes());
    h.update(old.as_bytes());
    h.update(predicate.as_bytes());
    let mut raw = [0; 16];
    raw.copy_from_slice(&h.finalize().as_bytes()[..16]);
    raw[6] = (raw[6] & 0x0f) | 0x70;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    EntityId::from_bytes(raw).expect("valid content-addressed entity id")
}
#[expect(
    clippy::too_many_arguments,
    reason = "runner companion binds the exact two heads and write envelope"
)]
pub(super) fn write_companion(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    new: &EntityId,
    old: &EntityId,
    body: &ClaimBody,
    old_body: &ClaimBody,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<()> {
    let source = crate::dreamer_consolidation::source_meet(
        claim_evidence_taint(body)
            .or(body.source)
            .unwrap_or(ClaimSource::Imported),
        claim_evidence_taint(old_body)
            .or(old_body.source)
            .unwrap_or(ClaimSource::Imported),
    );
    let value = Value::Map(vec![
        (Value::from("new"), Value::Binary(new.as_bytes().to_vec())),
        (Value::from("old"), Value::Binary(old.as_bytes().to_vec())),
        (Value::from("taint"), Value::from(source.as_str())),
    ]);
    let envelope = WriteEnvelope::with_lineage(
        envelope.actor(),
        source,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("supersession")),
            (
                Value::from("parent_provenance"),
                envelope.provenance().value().clone(),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
        envelope.lineage().clone().with(source),
    );
    write(
        vault,
        txn,
        companion_id(new, old, PREDICATE),
        body,
        ClaimCandidate::new(PREDICATE, ClaimSubject::Entity(*new), value, 1.0)
            .with_evidence(Value::Map(vec![(
                Value::from("refs"),
                Value::Array(vec![
                    Value::Binary(new.as_bytes().to_vec()),
                    Value::Binary(old.as_bytes().to_vec()),
                ]),
            )]))
            .with_scope(Value::Map(vec![(
                Value::from(super::CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
                Value::from(source.as_str()),
            )])),
        &envelope,
        now,
    )
}
pub(super) fn write_coaching(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    new: &EntityId,
    old: &EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<()> {
    let envelope = WriteEnvelope::with_lineage(
        envelope.actor(),
        envelope.source(),
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("supersession")),
            (
                Value::from("parent_provenance"),
                envelope.provenance().value().clone(),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
        envelope.lineage().clone(),
    );
    let candidate = ClaimCandidate::new(
        super::PREDICATE_CONFLICT_OPEN,
        body.subject,
        Value::from(body.predicate.as_str()),
        1.0,
    )
    .with_evidence(Value::Map(vec![(
        Value::from("refs"),
        Value::Array(vec![
            Value::Binary(new.as_bytes().to_vec()),
            Value::Binary(old.as_bytes().to_vec()),
        ]),
    )]))
    .with_scope(body.scope.clone().unwrap_or(Value::Map(Vec::new())));
    write(
        vault,
        txn,
        companion_id(new, old, super::PREDICATE_CONFLICT_OPEN),
        body,
        candidate,
        &envelope,
        now,
    )
}
fn write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
    mut candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<()> {
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(existing) = vault.get_claim_in_txn(txn, &id)? {
        let mut expected = candidate.into_claim_body(envelope);
        // Approval is the gate's result, not part of the deterministic candidate.
        expected.approval = existing.approval;
        if existing != expected {
            return Err(Error::InvalidClaimBody(
                "supersession companion identity collision",
            ));
        }
        return Ok(());
    }
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            envelope,
            crate::temporal::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply_recording_gate_decisions(txn)
}

pub(super) fn validate(body: &ClaimBody) -> Result<()> {
    if body.predicate != PREDICATE {
        return Ok(());
    }
    let new = id(get(&body.value, "new").ok_or(Error::InvalidClaimBody("supersession new ref"))?)?;
    let old = id(get(&body.value, "old").ok_or(Error::InvalidClaimBody("supersession old ref"))?)?;
    let source = get(&body.value, "taint")
        .and_then(Value::as_str)
        .and_then(ClaimSource::parse)
        .ok_or(Error::InvalidClaimBody("supersession taint"))?;
    if new == old
        || body.subject != ClaimSubject::Entity(new)
        || body.source != Some(source)
        || claim_evidence_taint(body) != Some(source)
    {
        return Err(Error::InvalidClaimBody(
            "supersession provenance mirror mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
