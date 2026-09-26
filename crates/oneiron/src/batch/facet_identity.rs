//! PERSON/FACET persona materialization shared by authored and replayed masks.
use super::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::{
    EntityId,
    error::{Error, Result},
    store::Store,
    temporal::TimeRange,
};

pub(super) fn reconcile_identity_facet(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    data: &[u8],
    occurred: TimeRange,
    learned: u64,
) -> Result<()> {
    if !crate::companion::is_identity_facet_body(data) {
        return Ok(());
    }
    let record = crate::companion::decode_companion_record_body(data)?;
    let person = match record.subject {
        crate::companion::CompanionSubject::Persona { persona_ref } => persona_ref,
        crate::companion::CompanionSubject::Relationship { source_ref, .. } => source_ref,
    };
    super::person_substrate::validate_scope_identity(person)?;
    if person == id {
        return Err(Error::CorruptedIndex("persona and facet ids must differ"));
    }
    if let Some(raw) = store.entities.get(txn, person.as_bytes())? {
        if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_PERSON) {
            return Err(Error::CorruptedIndex("persona subject is not PERSON"));
        }
    } else {
        super::put_apply::stage_entity_body_row(
            store,
            txn,
            &person,
            ENTITY_TYPE_PERSON,
            occurred,
            learned,
            b"",
        )?;
        super::put_apply::stage_entity_index_rows(
            store,
            txn,
            &person,
            ENTITY_TYPE_PERSON,
            occurred,
            learned,
        )?;
        let prefix = store.short_id_prefix(ENTITY_TYPE_PERSON)?;
        let plan =
            super::plan_short_id_update(store, txn, &person, ENTITY_TYPE_PERSON, &prefix, b"")?;
        super::apply_short_id_plan(store, txn, &person, plan)?;
        crate::federation::record_scope::stamp_put(
            store,
            txn,
            person,
            ENTITY_TYPE_PERSON,
            b"",
            false,
        )?;
    }
    super::person_substrate::ensure_person_substrate(store, txn, person, occurred, learned)?;
    super::edge_apply::apply_edge_with_created_at(
        store,
        txn,
        person,
        crate::edge::EdgeKind::HasFacet,
        id,
        1.0,
        learned,
        crate::affect::Vad::NEUTRAL,
        None,
    )
}
/// A substrate cannot be replaced by an arbitrary opaque mask or old identity.
pub(super) fn validate_facet_overwrite(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    data: &[u8],
) -> Result<()> {
    if let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..]) {
        if entries.iter().any(|(key, _)| {
            matches!(
                key.as_str(),
                Some("visibility" | "scopeRelationshipIds" | "worldId")
            )
        }) {
            return Err(Error::InvalidClaimBody("retired facet privacy axis"));
        }
        if entries
            .iter()
            .any(|(key, value)| key.as_str() == Some("kind") && value.as_str() == Some("substrate"))
        {
            let mut keys = std::collections::BTreeSet::new();
            if entries.len() != 3
                || entries
                    .iter()
                    .any(|(key, _)| key.as_str().is_none_or(|key| !keys.insert(key)))
            {
                return Err(Error::InvalidClaimBody("invalid substrate fields"));
            }
            let person = entries
                .iter()
                .find(|(key, _)| key.as_str() == Some("person_ref"))
                .and_then(|(_, v)| v.as_slice())
                .and_then(|bytes| bytes.try_into().ok())
                .and_then(|bytes| EntityId::from_bytes(bytes).ok())
                .ok_or(Error::InvalidClaimBody("substrate PERSON id"))?;
            if crate::claim::substrate_facet_id(person)? != id {
                return Err(Error::InvalidClaimBody("substrate id must bind PERSON"));
            }
        }
    }
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(());
    };
    if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_FACET) {
        return Ok(());
    }
    let prior = &raw[ENTITY_METADATA_HEADER_LEN..];
    let profile = crate::companion::is_identity_facet_body(prior);
    if profile && !crate::companion::is_identity_facet_body(data) {
        return Err(Error::InvalidClaimBody(
            "identity facet shape cannot change",
        ));
    }
    if let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &prior[..])
        && entries
            .iter()
            .any(|(k, v)| k.as_str() == Some("kind") && v.as_str() == Some("substrate"))
        && data != prior
    {
        return Err(Error::InvalidClaimBody("substrate facet is immutable"));
    }
    Ok(())
}
