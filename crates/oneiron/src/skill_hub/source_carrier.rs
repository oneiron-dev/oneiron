//! Content-addressed HubPackage custody over ordinary replicated ASSET rows.
//!
//! The local `vault_meta` sidecar stays the primary projection. Every persist
//! also writes the same exact bytes to a content-derived ASSET carrier in the
//! same transaction, so sync carries source with the skill instead of
//! stranding it. Lookup falls back to the carrier only when the sidecar is
//! absent, and only on exact identity plus record-metadata match.
//!
//! A carrier is inert Candidate data: no signature, no authority, no Active
//! reach. The admission and activation guards never read it.
use sha2::{Digest, Sha256};

use super::HubPackage;
use super::package_codec::{decode_hub_package, invalid, is_hub_package_envelope};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::skill::SkillContentHash;

/// Domain tag for the carrier derivation. It binds the truncated digest to
/// hub source custody so a pack-source id can never alias a carrier id.
const SOURCE_CARRIER_DOMAIN: &[u8] = b"oneiron.hub-source.asset.v1\0";

/// Derives the carrier id from the package tree hash. Same content is one
/// carrier whichever road it arrives on; the id claims nothing about authors.
pub(crate) fn source_carrier_id(hash: &SkillContentHash) -> Result<EntityId> {
    let digest = Sha256::new()
        .chain_update(SOURCE_CARRIER_DOMAIN)
        .chain_update(hash.as_bytes())
        .finalize();
    let bytes: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| invalid("source carrier ID width"))?;
    EntityId::from_bytes(bytes)
}

/// Decodes only hub-package envelopes. Any other ASSET body is an ordinary
/// asset, never a source candidate, so it maps to `None` instead of an error.
pub(crate) fn decode_source_carrier(bytes: &[u8]) -> Result<Option<HubPackage>> {
    if !is_hub_package_envelope(bytes) {
        return Ok(None);
    }
    let package = decode_hub_package(bytes)?;
    if package != canonical_source_package(&package)? {
        return Err(invalid(
            "source carrier contains noncanonical authority metadata",
        ));
    }
    Ok(Some(package))
}

/// Raw and replay immutability for carriers, mirroring the pack-source guard.
/// All puts, including replay, check content and source identity. No local
/// installation is reconstructed from a peer's source-bearing blob.
pub(crate) fn validate_hub_source_carrier_put(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
) -> Result<()> {
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
        && let Some(package) = decode_source_carrier(bytes)?
    {
        if source_carrier_id(&package.content_hash()?)? != *id {
            return Err(invalid("source carrier ID disagrees with content hash"));
        }
        if let Some(raw) = previous
            && raw[ENTITY_METADATA_HEADER_LEN..] != *bytes
        {
            return Err(invalid("source hash collides with an existing asset"));
        }
    }
    Ok(())
}

/// Reads a live carrier and re-verifies its id against the recomputed tree
/// hash. Deleted shells, off-record rows, foreign types, and ordinary
/// non-envelope assets all read as absent; only identity drift is an error.
pub(crate) fn read_source_carrier_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    carrier: &EntityId,
) -> Result<Option<HubPackage>> {
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
    let Some(package) = decode_source_carrier(&body)? else {
        return Ok(None);
    };
    if source_carrier_id(&package.content_hash()?)? != *carrier {
        return Err(invalid("stored source carrier identity drift"));
    }
    Ok(Some(package))
}

/// Strip mutable approvals, scores, provenance and publisher state from byte
/// custody. The carrier cannot become an alternate authority-bearing SKILL row.
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
