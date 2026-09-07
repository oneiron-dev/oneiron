//! Exact-operation envelope handoff. This is not a gate authorization.

use super::{ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
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
            || occurred.end != valid_to.max(header.occurred_start)
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let Some(envelope) = lifecycle_envelope(store, txn, id, &prior)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            id: *id,
            occurred: *occurred,
            learned_at: *learned_at,
            data: data.clone(),
            reserved: false,
            envelope,
            prior: Some(row_digest(&raw)),
        }))
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
mod tests {
    mod freshness;

    use super::*;
    use crate::claim::{ClaimApprovalStatus, ClaimSubject};
    use crate::edge::EdgeActorClass;
    use crate::temporal::TimeRange;
    use crate::test_util::entity;
    use crate::write_envelope::ClaimCandidate;

    fn fixture() -> Result<(tempfile::TempDir, Vault, WriteActor)> {
        let dir = tempfile::tempdir().expect("temporary vault");
        let vault = Vault::open(dir.path(), crate::config::VaultConfig::default())?;
        let actor = WriteActor::new(entity(0x61), EdgeActorClass::Human);
        for id in [actor.entity_ref(), entity(0x62), entity(0x63)] {
            vault.put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"",
            )?;
        }
        permit(
            &vault,
            actor.entity_ref(),
            &[
                ClaimSource::Imported,
                ClaimSource::ToolOutput,
                ClaimSource::Generated,
            ],
        )?;
        Ok((dir, vault, actor))
    }

    fn permit(vault: &Vault, actor: EntityId, sources: &[ClaimSource]) -> Result<()> {
        let mut manifest =
            rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice())
                .expect("manifest");
        let Value::Map(entries) = &mut manifest else {
            panic!("manifest map");
        };
        let (_, Value::Map(trust)) = entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("source_trust"))
            .expect("source trust")
        else {
            panic!("trust map");
        };
        for source in sources {
            trust.retain(|(key, _)| key.as_str() != Some(source.as_str()));
            trust.push((
                Value::from(source.as_str()),
                Value::Map(vec![
                    ("actor_ref".into(), actor.to_hex().into()),
                    (
                        "max_auto_sensitivity".into(),
                        u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND).into(),
                    ),
                    ("receipted".into(), true.into()),
                    ("warned".into(), true.into()),
                ]),
            ));
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encode");
        crate::test_util::put_policy_manifest_bytes(
            vault,
            crate::gate::default_policy_manifest_id()?,
            &bytes,
        )
    }

    fn candidate(vault: &Vault, actor: WriteActor, id: EntityId) -> Result<()> {
        let envelope = WriteEnvelope::with_lineage(
            actor,
            ClaimSource::ToolOutput,
            WriteProvenance::new(Value::from("host operation"))?,
            ClaimApprovalStatus::Auto,
            SourceLineage::of(ClaimSource::ToolOutput).with(ClaimSource::Generated),
        );
        vault
            .batch()
            .claim_candidate(
                &id,
                ClaimCandidate::new(
                    "test.materialization",
                    ClaimSubject::Entity(entity(0x62)),
                    Value::from("fact"),
                    1.0,
                ),
                &envelope,
                TimeRange {
                    start: 10,
                    end: u64::MAX,
                },
                10,
            )
            .commit()
    }

    #[test]
    fn owner_materialization_preserves_auto_actor_and_complete_lineage_through_lifecycle()
    -> Result<()> {
        let (_dir, vault, actor) = fixture()?;
        let old = entity(0x64);
        let new = entity(0x65);
        candidate(&vault, actor, old)?;
        candidate(&vault, actor, new)?;
        let before = vault.get_claim(&old)?.expect("claim");
        vault.supersede_claim(&new, &old, 20)?;
        let closed = vault.get_claim(&old)?.expect("closed");
        assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(closed.evidence, before.evidence);
        assert_eq!(closed.source, Some(ClaimSource::ToolOutput));
        assert_eq!(closed.approval, ClaimApprovalStatus::Auto);
        // A permit for the declared source cannot cover a revoked lineage member.
        permit(&vault, actor.entity_ref(), &[ClaimSource::ToolOutput])?;
        let before = vault.get_claim(&new)?.expect("new");
        assert!(vault.retract_claim(&new, 30).is_err());
        assert_eq!(vault.get_claim(&new)?.expect("unchanged"), before);
        permit(
            &vault,
            actor.entity_ref(),
            &[ClaimSource::ToolOutput, ClaimSource::Generated],
        )?;
        vault.retract_claim(&new, 30)?;
        assert_eq!(
            vault.get_claim(&new)?.expect("closed").evidence,
            before.evidence
        );
        Ok(())
    }

    #[test]
    fn owner_materialization_rejects_actor_source_and_operation_rebinding() -> Result<()> {
        let (_dir, vault, actor) = fixture()?;
        let id = entity(0x64);
        candidate(&vault, actor, id)?;
        let mut body = vault.get_claim(&id)?.expect("claim");
        let txn = vault.store.env.read_txn()?;
        assert!(lifecycle_envelope(&vault.store, &txn, &entity(0x65), &body)?.is_none());
        let original = body.clone();
        body.source = Some(ClaimSource::Observed);
        assert!(lifecycle_envelope(&vault.store, &txn, &id, &body).is_err());
        body = original.clone();
        let Some(Value::Map(entries)) = &mut body.evidence else {
            panic!("stamp");
        };
        entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("actor_entity_ref"))
            .expect("actor")
            .1 = Value::Binary(entity(0x63).as_bytes().to_vec());
        assert!(lifecycle_envelope(&vault.store, &txn, &id, &body).is_err());
        body = original;
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(20);
        let op = BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: TimeRange { start: 10, end: 20 },
            learned_at: 10,
            data: encode_claim_body(&body)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        };
        let binding = ClaimMaterialization::lifecycle(&vault.store, &txn, &op)?.expect("bound");
        assert!(binding.matches_op(&op));
        for changed in 0..4 {
            let mut wrong = op.clone();
            let BatchOp::Put {
                id,
                occurred,
                learned_at,
                data,
                ..
            } = &mut wrong
            else {
                unreachable!()
            };
            match changed {
                0 => *id = entity(0x65),
                1 => occurred.end += 1,
                2 => *learned_at += 1,
                _ => data.push(0),
            }
            assert!(!binding.matches_op(&wrong));
            assert!(ClaimMaterialization::lifecycle(&vault.store, &txn, &wrong).is_err());
        }
        Ok(())
    }

}
