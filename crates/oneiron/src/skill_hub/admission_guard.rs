//! Imported and hub-derived instruction authority at the single SKILL materialization door.
use super::HubAdmissionProof;
use super::package_codec::invalid;
use crate::side_table::{self, Raw, SideTable, StagedRow};
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    claim::ClaimSource,
    entity_id::EntityId,
    error::{Error, Result},
    skill::{SkillLifecycle, SkillRecord},
    store::Store,
};

/// Origin marker for a hub-materialized skill (imported flag, optional
/// forked-from parent id); survives deletion so it cannot be laundered by
/// delete/recreate.
///
/// The write half of this table is a [`StagedRow`] built here for
/// [`crate::batch::put_apply::apply`] (outside this module) to commit inside
/// its own put transaction alongside the rest of the entity write.
const ORIGIN: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::SKILL_HUB_ORIGIN);

impl crate::Vault {
    pub(in crate::skill_hub) fn admit_hub_skill_record_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        occurred: crate::TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        proof: HubAdmissionProof,
    ) -> Result<()> {
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id: proof.id(),
                entity_type: crate::registry::ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            crate::batch::ApplyOpsGateMode::new(false, true).with_hub_admission(proof),
        )
    }
}
fn origin(record: &SkillRecord) -> Vec<u8> {
    let mut out = vec![u8::from(record.source == ClaimSource::Imported)];
    if let Some(parent) = record.forked_from {
        out.extend_from_slice(parent.as_bytes());
    }
    out
}
/// Read-only preflight. Its optional marker is staged only after all remote-refusal checks.
/// Markers survive deletion, so delete/recreate cannot launder a governed id into owner-authored content.
pub(crate) fn check_hub_skill_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &SkillRecord,
    replaces_source: bool,
    proof: Option<&HubAdmissionProof>,
) -> Result<Option<StagedRow>> {
    super::package_codec::check_source_binding_update(store, txn, id, record, replaces_source)?;
    let marked = ORIGIN.get(store, txn, id)?;
    let current_origin = origin(record);
    if let Some(marked) = &marked
        && marked.as_slice() != current_origin.as_slice()
    {
        return Err(invalid(
            "hub or fork origin cannot be removed, including after deletion",
        ));
    }
    if marked.is_none() && !has_import_origin(store, txn, record)? {
        return Ok(None);
    }
    let prior = store
        .entities
        .get(txn, id.as_bytes())?
        .map(|raw| {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
                return Err(invalid("skill id type changed"));
            }
            crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
        })
        .transpose()?;
    if let Some(prior) = &prior
        && origin(prior) != current_origin
    {
        return Err(invalid("hub or fork origin is immutable"));
    }
    let unchanged_active = prior
        .as_ref()
        .is_some_and(|prior| prior.lifecycle_status == SkillLifecycle::Active)
        && prior
            .as_ref()
            .map(crate::skill_optimize::skill_body_binding_digest)
            .transpose()?
            == Some(crate::skill_optimize::skill_body_binding_digest(record)?);
    if record.lifecycle_status == SkillLifecycle::Active && !unchanged_active {
        let proof = proof.ok_or_else(|| {
            invalid("hub or fork activation requires local consent and held-out replay")
        })?;
        let encoded = crate::skill::encode_skill_record(record)?;
        if !proof.binds(id, &encoded) {
            return Err(invalid(
                "hub admission proof does not bind this exact record",
            ));
        }
    }
    marked
        .is_none()
        .then(|| ORIGIN.stage(id, &current_origin))
        .transpose()
}

/// A local owner-authored fork is not a marketplace import. Imported ancestry
/// stays governed across arbitrary forks; missing or cyclic ancestry refuses.
fn has_import_origin(store: &Store, txn: &heed::RoTxn<'_>, record: &SkillRecord) -> Result<bool> {
    if record.source == ClaimSource::Imported {
        return Ok(true);
    }
    let mut parent = record.forked_from;
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = parent {
        if seen.len() >= 128 || !seen.insert(id) {
            return Err(invalid("invalid skill fork ancestry"));
        }
        if ORIGIN.contains(store, txn, &id)? {
            return Ok(true);
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or_else(|| invalid("skill fork ancestry is missing"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("skill ancestor header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Err(invalid("skill ancestor changed type"));
        }
        let prior = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if prior.source == ClaimSource::Imported {
            return Ok(true);
        }
        parent = prior.forked_from;
    }
    Ok(false)
}
