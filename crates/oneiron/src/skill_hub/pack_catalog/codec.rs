//! Canonical source-bearing ASSET envelopes: immutable content, not authority.
use super::{PackSource, invalid};
use crate::skill_hub::HubFile;
use crate::{EntityId, error::Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const FORMAT: &str = "oneiron.pack_source.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    content_hash: String,
    files: Vec<TextFile>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextFile {
    path: String,
    content: String,
}

pub(super) fn encode(source: &PackSource) -> Result<Vec<u8>> {
    let files = source
        .files
        .iter()
        .map(|f| {
            Ok(TextFile {
                path: f.path.clone(),
                content: String::from_utf8(f.content.clone())
                    .map_err(|_| invalid("source is not UTF-8"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    rmp_serde::to_vec_named(&Envelope {
        format: FORMAT.to_owned(),
        content_hash: source.hash.to_hex(),
        files,
    })
    .map_err(|_| invalid("source encoding failed"))
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Option<PackSource>> {
    #[derive(Deserialize)]
    struct Marker {
        format: String,
    }
    let Ok(marker) = rmp_serde::from_slice::<Marker>(bytes) else {
        return Ok(None);
    };
    if marker.format != FORMAT {
        return Ok(None);
    }
    if bytes.len() > crate::skill_hub::MAX_HUB_PACKAGE_TOTAL_BYTES + 1024 * 1024 {
        return Err(invalid("source envelope too large"));
    }
    let envelope: Envelope =
        rmp_serde::from_slice(bytes).map_err(|_| invalid("invalid source envelope"))?;
    let source = PackSource::from_files(
        envelope
            .files
            .into_iter()
            .map(|f| HubFile::new(f.path, f.content.into_bytes()))
            .collect(),
    )?;
    if source.hash.to_hex() != envelope.content_hash || encode(&source)? != bytes {
        return Err(invalid("noncanonical or drifted source envelope"));
    }
    Ok(Some(source))
}

pub(super) fn source_id(source: &PackSource) -> Result<EntityId> {
    let digest = Sha256::new()
        .chain_update(b"oneiron.pack-source.asset.v1\0")
        .chain_update(source.hash.as_bytes())
        .finalize();
    let bytes: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| invalid("source ID width"))?;
    EntityId::from_bytes(bytes)
}

/// All puts, including replay, check content and source identity. No local
/// installation is reconstructed from a peer's source-bearing blob.
pub(crate) fn validate_pack_source_put(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
) -> Result<()> {
    let previous = store.entities.get(txn, id.as_bytes())?;
    if let Some(raw) = &previous {
        let header = crate::batch::EntityMetadataHeader::parse(raw)
            .ok_or(crate::error::Error::CorruptedIndex("pack source header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_ASSET
            && decode(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?.is_some()
            && (entity_type != header.entity_type
                || raw[crate::batch::ENTITY_METADATA_HEADER_LEN..] != *bytes)
        {
            return Err(invalid(
                "content-addressed pack source cannot be overwritten",
            ));
        }
    }
    if entity_type == crate::registry::ENTITY_TYPE_ASSET
        && let Some(source) = decode(bytes)?
    {
        if source_id(&source)? != *id {
            return Err(invalid("source entity ID disagrees with content hash"));
        }
        if let Some(raw) = previous
            && raw[crate::batch::ENTITY_METADATA_HEADER_LEN..] != *bytes
        {
            return Err(invalid("source hash collides with an existing asset"));
        }
    }
    Ok(())
}
