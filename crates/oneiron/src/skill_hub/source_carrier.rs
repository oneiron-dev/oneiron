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

const MAGIC: &[u8] = b"oneiron.hub-source.v1\0";
const DOMAIN: &[u8] = b"oneiron.hub-source.asset.v1\0";

pub(super) fn source_carrier_id(holder: &EntityId, hash: &SkillContentHash) -> Result<EntityId> {
    let digest = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(holder.as_bytes())
        .chain_update(hash.as_bytes())
        .finalize();
    EntityId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| invalid("source ID width"))?,
    )
}

pub(crate) fn encode_source_carrier(holder: &EntityId, package: &HubPackage) -> Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(holder.as_bytes());
    out.extend_from_slice(&encode_hub_package(&canonical_source_package(package)?)?);
    Ok(out)
}

/// Historical erase closure needs only the fixed holder reference. It must
/// scrub a matching source even if a peer corrupted the package payload; this
/// accessor grants no admission and is never used to materialize source bytes.
#[cfg(feature = "sync")]
pub(crate) fn source_carrier_holder(bytes: &[u8]) -> Option<EntityId> {
    let rest = bytes.strip_prefix(MAGIC)?;
    EntityId::from_bytes(rest.get(..16)?.try_into().ok()?).ok()
}

/// The holder is read from the envelope, not guessed from a content-index winner.
/// Unrelated ASSETs return None; malformed source envelopes fail closed.
pub(crate) fn decode_source_carrier(bytes: &[u8]) -> Result<Option<(EntityId, HubPackage)>> {
    if super::package_codec::is_hub_package_envelope(bytes) {
        return Err(invalid("holderless packages are not source carriers"));
    }
    let Some(rest) = bytes.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    let holder = EntityId::from_bytes(
        rest.get(..16)
            .ok_or_else(|| invalid("truncated source holder"))?
            .try_into()
            .map_err(|_| invalid("source holder width"))?,
    )?;
    let package = decode_hub_package(&rest[16..])?;
    if encode_source_carrier(&holder, &package)? != bytes {
        return Err(invalid("noncanonical source carrier"));
    }
    Ok(Some((holder, package)))
}

pub(crate) fn validate_hub_source_carrier_put(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
) -> Result<()> {
    super::source_custody::validate_registered_source_target(store, txn, id, entity_type, bytes)?;
    let previous = store.entities.get(txn, id.as_bytes())?;
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
    if store.off_record_sessions.contains_entity(carrier)? {
        return Ok(None);
    }
    let crate::vault::LiveEntityRow::Live { entity_type, body } =
        crate::vault::live_entity_row_in_txn(store, txn, carrier)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(None);
    }
    let Some((holder, package)) = decode_source_carrier(&body)? else {
        return Ok(None);
    };
    if source_carrier_id(&holder, &package.content_hash()?)? != *carrier {
        return Err(invalid("stored source carrier identity drift"));
    }
    super::source_custody::check_source_custody(store, txn, &holder, &package.content_hash()?)?;
    Ok(Some((holder, package)))
}

pub(super) fn canonical_source_package(package: &HubPackage) -> Result<HubPackage> {
    let record = crate::skill::SkillRecord::new(
        &package.record.skill_id,
        &package.record.desc,
        &package.record.version,
        crate::claim::ClaimApprovalStatus::Proposed,
        crate::skill::SkillLifecycle::Candidate,
        crate::claim::ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![("source".into(), "byte-custody".into())]),
    )
    .with_content_hash(package.content_hash()?);
    let mut canonical =
        HubPackage::new(record, package.files.clone(), package.capabilities.clone());
    canonical.format = package.format;
    Ok(canonical)
}

/// Only a valid envelope at its derived ID can extend deletion's graph scope.
/// Malformed historical payloads are still scrubbed, but grant no other erasure.
#[cfg(feature = "sync")]
pub(crate) fn source_carrier_matches_id(bytes: &[u8], id: &EntityId) -> bool {
    let Ok(Some((holder, package))) = decode_source_carrier(bytes) else {
        return false;
    };
    package
        .content_hash()
        .and_then(|hash| source_carrier_id(&holder, &hash))
        .is_ok_and(|expected| expected == *id)
}
