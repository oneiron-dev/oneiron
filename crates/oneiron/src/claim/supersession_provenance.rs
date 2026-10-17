//! Runner-owned companion claims; structural taint mirrors also run on replay.
use super::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_evidence_taint};
use crate::entity_id::derived_domains::SUPERSESSION_COMPANION;
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
fn companion_id(new: &EntityId, old: &EntityId, predicate: &str) -> Result<EntityId> {
    EntityId::derive(
        SUPERSESSION_COMPANION,
        &[new.as_bytes(), old.as_bytes(), predicate.as_bytes()],
    )
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
    let mut candidate = ClaimCandidate::new(PREDICATE, ClaimSubject::Entity(*new), value, 1.0)
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
        )]));
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    write(
        vault,
        txn,
        companion_id(new, old, PREDICATE)?,
        candidate,
        &envelope,
        now,
    )
}

/// A `core.conflict.open` marker for one claim pair, built but not written.
/// A writer that keeps its own transaction bookkeeping signs and applies it
/// once [`ConflictMarker::landed_in_txn`] has ruled out a replay.
pub(crate) struct ConflictMarker {
    pub(crate) id: EntityId,
    pub(crate) candidate: ClaimCandidate,
    pub(crate) envelope: WriteEnvelope,
}

impl ConflictMarker {
    /// Whether this exact marker is already stored. A replay finds it and
    /// writes nothing; a different row under the pair's id is a collision.
    pub(crate) fn landed_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        landed(vault, txn, &self.id, &self.candidate, &self.envelope)
    }
}

/// The marker naming `new` against `old` under the pair's deterministic id:
/// evidence refs `[new, old]`, `body`'s predicate as its value, and every
/// scope axis of `body` (world, relationship, scope map, facet and project).
pub(crate) fn conflict_marker(
    new: &EntityId,
    old: &EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
) -> Result<ConflictMarker> {
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
    let mut candidate = ClaimCandidate::new(
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
    .with_scope(body.scope.clone().unwrap_or(Value::Map(Vec::new())))
    .with_scope_stamps(body.scope_facet, body.scope_project);
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(relationship) = body.rel {
        candidate = candidate.with_relationship(relationship);
    }
    Ok(ConflictMarker {
        id: companion_id(new, old, super::PREDICATE_CONFLICT_OPEN)?,
        candidate,
        envelope,
    })
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
    let marker = conflict_marker(new, old, body, envelope)?;
    write(
        vault,
        txn,
        marker.id,
        marker.candidate,
        &marker.envelope,
        now,
    )
}
fn landed(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    candidate: &ClaimCandidate,
    envelope: &WriteEnvelope,
) -> Result<bool> {
    let Some(existing) = vault.get_claim_in_txn(txn, id)? else {
        return Ok(false);
    };
    let candidate = candidate.clone();
    let mut expected = candidate.into_claim_body(envelope, vault.default_facet_in_txn(txn)?)?;
    // Approval is the gate's result, not part of the deterministic candidate.
    expected.approval = existing.approval;
    if existing != expected {
        return Err(Error::InvalidClaimBody(
            "supersession companion identity collision",
        ));
    }
    Ok(true)
}
fn write(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<()> {
    if landed(vault, txn, &id, &candidate, envelope)? {
        return Ok(());
    }
    let mut envelope = envelope.clone();
    vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
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
