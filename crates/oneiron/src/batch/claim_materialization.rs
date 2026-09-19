//! Exact-operation envelope handoff. This is not a gate authorization.

use std::collections::VecDeque;

use super::{
    ApplyOpsGateMode, BaseWriteOrigin, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    reject_overlay_member_base_write,
};
use crate::claim::{
    ClaimBody, ClaimLifecycleStatus, ClaimSource, decode_claim_body, encode_claim_body,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::write_envelope::{SourceLineage, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, Vault};
use rmpv::Value;

/// Private fields prevent a caller from attaching an arbitrary envelope to a Put.
/// The provenance owner supplies its sealed payload. Lifecycle reconstruction
/// instead requires a current row and a host-authored immutable binding.
#[derive(Debug)]
pub(crate) struct ClaimMaterialization {
    id: EntityId,
    occurred: crate::temporal::TimeRange,
    learned_at: u64,
    data: Vec<u8>,
    reserved: bool,
    envelope: WriteEnvelope,
    prior: Option<[u8; 32]>,
}

impl ClaimMaterialization {
    pub(crate) fn provenance(write: crate::provenance::ProvenanceMaterialization) -> Result<Self> {
        let prior = write.prior();
        let (id, occurred, learned_at, data, envelope) = write.into_parts();
        let body = crate::claim::validate_claim_body_and_decode(&data, true)?;
        let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
        let class =
            crate::provenance::resolve_persisted_actor_class(&record, body.evidence.as_ref())?;
        if body.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE
            || envelope.actor() != WriteActor::new(record.actor_entity_ref, class)
            || body.source != Some(envelope.source()) && body.source.is_some()
            || body.approval != envelope.approval()
            || envelope.provenance().value() != &body.value
            || envelope.lineage() != &SourceLineage::of(envelope.source())
        {
            return Err(binding_error());
        }
        Ok(Self {
            id,
            occurred,
            learned_at,
            data,
            reserved: true,
            envelope,
            prior,
        })
    }

    /// Only closing the current active row is admitted. No actor or evidence
    /// argument exists. The body must be identical except for life and valid_to.
    pub(crate) fn lifecycle(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Option<Self>> {
        let BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        } = op
        else {
            return Err(binding_error());
        };
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let Some(valid_to) = next.valid_to else {
            return Err(binding_error());
        };
        if valid_to < header.occurred_start {
            return Err(Error::InvalidTimeRange {
                start: header.occurred_start,
                end: valid_to,
            });
        }
        let mut expected = prior.clone();
        expected.lifecycle = next.lifecycle;
        expected.valid_to = next.valid_to;
        if prior.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                next.lifecycle,
                ClaimLifecycleStatus::Retracted | ClaimLifecycleStatus::Superseded
            )
            || encode_claim_body(&expected)? != *data
            || occurred.start != header.occurred_start
            || occurred.end != valid_to
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let Some(envelope) = lifecycle_envelope(store, txn, id, &prior)? else {
            return Ok(None);
        };
        let binding = Self {
            id: *id,
            occurred: *occurred,
            learned_at: *learned_at,
            data: data.clone(),
            reserved: false,
            envelope,
            prior: Some(row_digest(&raw)),
        };
        // Retraction records a gate decision before consuming the Put. Check
        // the reconstructed actor now, before any non-transactional metrics.
        binding.validate_actor(store, txn)?;
        Ok(Some(binding))
    }

    /// Admit only a current-row demotion and its exact ClaimOf weight update.
    /// This does not widen the operation allowlist of other materializations.
    pub(crate) fn apply_demotion(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        ops: Vec<BatchOp>,
    ) -> Result<()> {
        let Some(BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }) = ops.first()
        else {
            return Err(binding_error());
        };
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || occurred.start != header.occurred_start
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let expected = demotion_body(&vault.store, txn, id, &prior, &next, &ops[1..])?;
        if encode_claim_body(&expected)? != *data {
            return Err(binding_error());
        }
        let mut bindings = Vec::new();
        if let Some(envelope) = lifecycle_envelope(&vault.store, txn, id, &prior)? {
            let binding = Self {
                id: *id,
                occurred: *occurred,
                learned_at: *learned_at,
                data: data.clone(),
                reserved: false,
                envelope,
                prior: Some(row_digest(&raw)),
            };
            binding.validate_actor(&vault.store, txn)?;
            bindings.push(binding);
        }
        // No binding still means the existing first-party local policy, not
        // authority inferred from evidence. The pipeline refreshes a consumed
        // binding from the finalized row, atomically with the edge update.
        super::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, false).with_claim_materializations(bindings),
        )
    }

    pub(super) fn matches_op(&self, op: &BatchOp) -> bool {
        matches!(op, BatchOp::Put { id, entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred, learned_at, data, allow_maintenance: false,
            allow_reserved_predicate, hub_sync_imported: false }
            if *id == self.id && *occurred == self.occurred && *learned_at == self.learned_at
                && *data == self.data && *allow_reserved_predicate == self.reserved)
    }

    pub(crate) fn envelope(&self) -> &WriteEnvelope {
        &self.envelope
    }

    pub(super) fn validate_actor(&self, store: &Store, txn: &heed::RoTxn<'_>) -> Result<()> {
        let current = store.entities.get(txn, self.id.as_bytes())?;
        if current.as_ref().map(|raw| row_digest(raw)) != self.prior {
            return Err(binding_error());
        }
        if !self.reserved {
            let authored = store.vault_meta.get(txn, &authored_key(&self.id))?;
            if authored.as_deref() != self.prior.as_ref().map(<[u8; 32]>::as_slice) {
                return Err(binding_error());
            }
        }
        crate::gate::validate_write_envelope(&self.envelope)?;
        let actor = self.envelope.actor();
        let raw = store
            .entities
            .get(txn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())
    }
}

/// Consumes only the next exact binding, then validates its current authority.
pub(super) fn consume_claim_materialization(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    claim_materializations: &mut VecDeque<ClaimMaterialization>,
    op: &BatchOp,
    origin: BaseWriteOrigin<'_>,
) -> Result<Option<ClaimMaterialization>> {
    if claim_materializations
        .front()
        .is_some_and(|binding| binding.matches_op(op))
    {
        let binding = claim_materializations
            .pop_front()
            .expect("matched front binding");
        binding.validate_actor(store, txn)?;
        reject_overlay_member_base_write(store, &binding.envelope().actor().entity_ref(), origin)?;
        Ok(Some(binding))
    } else if !claim_materializations.is_empty()
        && matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        )
    {
        Err(Error::InvalidClaimBody(
            "claim materialization operation mismatch",
        ))
    } else {
        Ok(None)
    }
}

/// Rebuild the permitted body delta instead of trusting caller-supplied axes.
fn demotion_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    prior: &ClaimBody,
    next: &ClaimBody,
    tail: &[BatchOp],
) -> Result<ClaimBody> {
    use crate::claim::{
        CLAIM_SCOPE_DEMOTION_RUNG_KEY, ClaimDemotionRung, ClaimSubject, claim_demotion_rung,
    };
    use crate::edge::{EdgeKind, validate_edge_weight};
    use crate::vault::{edge_kind_prefix, parse_edge_record};

    if prior.lifecycle != ClaimLifecycleStatus::Active {
        return Err(binding_error());
    }
    let before = claim_demotion_rung(prior)?;
    let after = claim_demotion_rung(next)?;
    let mut expected = prior.clone();
    let rung = match (before, after, tail) {
        (
            None | Some(ClaimDemotionRung::Decayed),
            Some(ClaimDemotionRung::Decayed),
            [
                BatchOp::SetEdgeWeight {
                    src,
                    kind: EdgeKind::ClaimOf,
                    tgt,
                    weight,
                },
            ],
        ) if src == id && prior.subject == ClaimSubject::Entity(*tgt) => {
            validate_edge_weight(*weight)?;
            let mut current = None;
            for entry in store
                .edges_out
                .prefix_iter(txn, &edge_kind_prefix(id, EdgeKind::ClaimOf))?
            {
                let (key, value) = entry?;
                let edge = parse_edge_record(&key, &value)?;
                if edge.target == *tgt && current.replace(edge.weight).is_some() {
                    return Err(binding_error());
                }
            }
            if *weight > current.ok_or(binding_error())? {
                return Err(binding_error());
            }
            "decayed"
        }
        (
            Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened),
            Some(ClaimDemotionRung::Weakened),
            [],
        ) if next.confidence.is_finite()
            && (0.0..=1.0).contains(&next.confidence)
            && next.confidence <= prior.confidence =>
        {
            expected.confidence = next.confidence;
            "weakened"
        }
        (Some(ClaimDemotionRung::Weakened), Some(ClaimDemotionRung::Stale), []) => {
            expected.stale = true;
            "stale"
        }
        _ => return Err(binding_error()),
    };
    let mut scope = match expected.scope.take() {
        None => Vec::new(),
        Some(Value::Map(entries)) => entries,
        Some(_) => return Err(binding_error()),
    };
    scope.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
    scope.push((
        Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
        Value::from(rung),
    ));
    expected.scope = Some(Value::Map(scope));
    Ok(expected)
}

fn row_digest(raw: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw).into()
}

fn binding_error() -> Error {
    Error::InvalidClaimBody("claim materialization binding mismatch")
}

/// A private local key, never reconstructed from a raw or replicated Put.
/// Its digest binds authority to one finalized row, not to the id forever.
fn authored_key(id: &EntityId) -> Vec<u8> {
    let mut key = b"claim:materialization:authored:v1:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

/// Called only after a gated ClaimCandidate or a consumed lifecycle binding.
/// Read the finalized row, including its body and metadata, rather than the
/// pre-serialization candidate. A newly authorized writer replaces the prior
/// binding atomically; the old writer's sealed operation still pins its prior
/// row and therefore cannot consume the new writer's authority.
pub(super) fn bind_committed_claim(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(binding_error())?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(binding_error());
    }
    let digest = row_digest(&raw);
    store.vault_meta.put(txn, &authored_key(id), &digest)?;
    Ok(())
}

/// A successful unbound write must not inherit an earlier writer's authority,
/// even when it copies that writer's evidence verbatim. Rejected writes do not
/// reach this point, and transaction rollback restores the prior binding.
pub(super) fn invalidate_authored_claim(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta.delete(txn, &authored_key(id))?;
    Ok(())
}

/// Evidence alone grants nothing. The private host-written digest must match
/// before the current claim's immutable axes can reconstruct an envelope.
fn lifecycle_envelope(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Option<WriteEnvelope>> {
    let Some(bytes) = store.vault_meta.get(txn, &authored_key(id))? else {
        return Ok(None);
    };
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(binding_error())?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || bytes.as_ref() != row_digest(&raw).as_slice()
    {
        return Err(binding_error());
    }
    let authored = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
    if encode_claim_body(body)? != encode_claim_body(&authored)? {
        return Err(binding_error());
    }
    let Value::Map(entries) = authored.evidence.as_ref().ok_or(binding_error())? else {
        return Err(binding_error());
    };
    let get = |key: &str| -> Result<&Value> {
        let mut values = entries.iter().filter(|(k, _)| k.as_str() == Some(key));
        let value = &values.next().ok_or(binding_error())?.1;
        if values.next().is_some() {
            return Err(binding_error());
        }
        Ok(value)
    };
    let Value::Binary(actor_bytes) = get("actor_entity_ref")? else {
        return Err(binding_error());
    };
    let actor = EntityId::from_bytes(
        actor_bytes
            .as_slice()
            .try_into()
            .map_err(|_| binding_error())?,
    )?;
    let class = match get("actor_class")?.as_u64() {
        Some(0) => crate::edge::EdgeActorClass::Human,
        Some(1) => crate::edge::EdgeActorClass::Agent,
        Some(2) => crate::edge::EdgeActorClass::System,
        _ => return Err(binding_error()),
    };
    let source = authored.source.ok_or(binding_error())?;
    let mut lineage = SourceLineage::of(source);
    if entries.iter().any(|(k, _)| k.as_str() == Some("lineage")) {
        let Value::Array(sources) = get("lineage")? else {
            return Err(binding_error());
        };
        for value in sources {
            lineage = lineage.with(
                ClaimSource::parse(value.as_str().ok_or(binding_error())?).ok_or(binding_error())?,
            );
        }
    }
    let mut envelope = WriteEnvelope::with_lineage(
        WriteActor::new(actor, class),
        source,
        WriteProvenance::new(get("provenance")?.clone())?,
        body.approval,
        lineage,
    );
    if let Some(tag) = &body.session_tag {
        envelope = envelope.with_session_tag(tag);
    }
    Ok(Some(envelope))
}

/// The locally attested writer of this exact row. Evidence copied through a
/// raw or replicated Put is not an authorship capability.
pub(crate) fn authenticated_claim_author_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Option<WriteActor>> {
    Ok(lifecycle_envelope(store, txn, id, body)?.map(|envelope| envelope.actor()))
}

/// The operation list is checked as a whole, then again at consumption. Missing,
/// duplicate or extra envelopes cannot shift a later operation's actor.
pub(crate) fn apply_owner_bound_claim_puts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
    bindings: Vec<ClaimMaterialization>,
    persist_pending: bool,
) -> Result<()> {
    let mut remaining = bindings.iter();
    for op in &ops {
        if matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        ) {
            if !remaining
                .next()
                .is_some_and(|binding| binding.matches_op(op))
            {
                return Err(binding_error());
            }
        } else if !matches!(
            op,
            BatchOp::Edge {
                kind: crate::edge::EdgeKind::ClaimOf,
                ..
            } | BatchOp::EdgeWithCreatedAt {
                kind: crate::edge::EdgeKind::Supersedes,
                ..
            }
        ) {
            return Err(binding_error());
        }
    }
    if remaining.next().is_some() {
        return Err(binding_error());
    }
    super::apply_ops_with_gate_mode(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        ops,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        ApplyOpsGateMode::new(false, persist_pending).with_claim_materializations(bindings),
    )
}

#[cfg(test)]
mod tests;
