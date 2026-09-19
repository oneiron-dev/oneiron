//! Imported and hub-derived instruction authority at the single SKILL materialization door.
use super::package_codec::invalid;
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    claim::ClaimSource,
    entity_id::EntityId,
    error::{Error, Result},
    skill::{SkillLifecycle, SkillRecord},
    store::Store,
};

pub(super) fn ticket_key(id: &EntityId) -> Vec<u8> {
    key(b"skill_hub/admission-ticket/v1\0", id)
}
fn origin_key(id: &EntityId) -> Vec<u8> {
    key(b"skill_hub/origin/v1\0", id)
}
fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
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
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    super::package_codec::check_source_binding_update(store, txn, id, record, replaces_source)?;
    let key = origin_key(id);
    let marked = store.vault_meta.get(txn, &key)?;
    let current_origin = origin(record);
    if let Some(marked) = &marked
        && marked.as_ref() != current_origin.as_slice()
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
        let ticket = store.vault_meta.get(txn, &ticket_key(id))?.ok_or_else(|| {
            invalid("hub or fork activation requires local consent and held-out replay")
        })?;
        let encoded = crate::skill::encode_skill_record(record)?;
        if ticket.as_ref() != blake3::hash(&encoded).as_bytes() {
            return Err(invalid(
                "hub admission ticket does not bind this exact record",
            ));
        }
    }
    Ok(marked.is_none().then_some((key, current_origin)))
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
        if store.vault_meta.get(txn, &origin_key(&id))?.is_some() {
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
