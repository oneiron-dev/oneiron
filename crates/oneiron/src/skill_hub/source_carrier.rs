//! Holder-bound exact source custody over ordinary replicated ASSET rows.
//! The holder and content hash are immutable identity, never install authority.
use sha2::{Digest, Sha256};

use super::HubPackage;
use super::package_codec::{decode_hub_package, encode_hub_package, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::skill::SkillContentHash;

pub(super) use crate::store::skill_source_carrier::{canonical_source_package, source_carrier_id};
pub(crate) use crate::store::skill_source_carrier::{decode_source_carrier, encode_source_carrier};
#[cfg(feature = "sync")]
pub(crate) use crate::store::skill_source_carrier::{
    source_carrier_holder, source_carrier_matches_id,
};

pub(crate) fn validate_hub_source_carrier_put(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
) -> Result<()> {
    super::source_custody::validate_registered_source_target(store, txn, id, entity_type, bytes)?;
    let previous = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?;
    if let Some(raw) = &previous {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("hub source carrier header"))?;
        if header.entity_type == ENTITY_TYPE_ASSET
            && decode_source_carrier(&raw[ENTITY_METADATA_HEADER_LEN..])?.is_some()
            && (entity_type != header.entity_type || raw[ENTITY_METADATA_HEADER_LEN..] != *bytes)
        {
            return Err(invalid(
                "content-addressed hub source cannot be overwritten",
            ));
        }
    }
    if entity_type == ENTITY_TYPE_ASSET
        && let Some((holder, package)) = decode_source_carrier(bytes)?
    {
        let hash = package.content_hash()?;
        if source_carrier_id(&holder, &hash)? != *id || holder == *id {
            return Err(invalid(
                "source carrier ID disagrees with holder and content",
            ));
        }
        super::source_custody::check_source_target(store, txn, id)?;
        super::source_custody::check_source_custody(store, txn, &holder, &hash)?;
        if let Some(raw) = previous
            && raw[ENTITY_METADATA_HEADER_LEN..] != *bytes
        {
            return Err(invalid("source hash collides with an existing asset"));
        }
    }
    Ok(())
}

pub(super) fn read_source_carrier_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    carrier: &EntityId,
) -> Result<Option<(EntityId, HubPackage)>> {
    Ok(read_source_carrier_sourced_in_txn(store, txn, carrier)?.0)
}

/// The same carrier read, including bodies rejected before package decoding.
pub(super) fn read_source_carrier_sourced_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    carrier: &EntityId,
) -> Result<(Option<(EntityId, HubPackage)>, Option<Vec<EntityId>>)> {
    if store.off_record_sessions.contains_entity(carrier)? {
        return Ok((None, None));
    }
    let (entity_type, body) = match crate::vault::live_entity_row_in_txn(store, txn, carrier)? {
        crate::vault::LiveEntityRow::Live { entity_type, body } => (entity_type, body),
        crate::vault::LiveEntityRow::Absent => return Ok((None, Some(Vec::new()))),
        crate::vault::LiveEntityRow::DeletedShell => return Ok((None, None)),
    };
    let sources = Some(vec![*carrier]);
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok((None, sources));
    }
    let Some((holder, package)) = decode_source_carrier(&body)? else {
        return Ok((None, sources));
    };
    if source_carrier_id(&holder, &package.content_hash()?)? != *carrier {
        return Err(invalid("stored source carrier identity drift"));
    }
    let custody_sources = super::source_custody::check_source_custody_sourced(
        store,
        txn,
        &holder,
        &package.content_hash()?,
    )?;
    Ok((
        Some((holder, package)),
        crate::attempt_queue::source_rows::union_source_rows([sources, custody_sources]),
    ))
}
