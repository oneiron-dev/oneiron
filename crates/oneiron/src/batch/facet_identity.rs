//! Core half of `batch::facet_identity`: its store-layer items live in `oneiron_store::batch::facet_identity` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::facet_identity::*;

use super::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_FACET;
use crate::{
    EntityId,
    error::{Error, Result},
    store::Store,
};

/// A substrate cannot be replaced by an arbitrary opaque mask.
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
            if crate::write_envelope::claim_body::substrate_facet_id(person)? != id {
                return Err(Error::InvalidClaimBody("substrate id must bind PERSON"));
            }
        }
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(());
    };
    if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_FACET) {
        return Ok(());
    }
    let prior = &raw[ENTITY_METADATA_HEADER_LEN..];
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
