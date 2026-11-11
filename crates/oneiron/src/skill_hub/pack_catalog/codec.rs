//! Canonical source-bearing ASSET envelopes: immutable content, not authority.
use super::{PackSource, invalid};
use crate::entity_id::derived_domains::PACK_SOURCE_ASSET;
use crate::skill_hub::HubFile;
use crate::{EntityId, error::Result};
use serde::{Deserialize, Serialize};
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

/// Whether [`decode`] reads `bytes` as a pack source, valid or not: its
/// marker names this codec's format (FIX 22091).
pub(crate) fn names_pack_source(bytes: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Marker {
        format: String,
    }
    rmp_serde::from_slice::<Marker>(bytes).is_ok_and(|marker| marker.format == FORMAT)
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

/// The ASSET id of a pack source, derived from its canonical tree content hash.
pub(super) fn source_id(source: &PackSource) -> Result<EntityId> {
    EntityId::derive(PACK_SOURCE_ASSET, &[&source.hash.as_bytes()[..]])
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
    let previous = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?;
    // The bytes the previous row holds, a carrier's read from its body file
    // (FIX 22091): a source is compared by what it holds, never its manifest.
    let previous = match &previous {
        Some(raw) => {
            let header = crate::batch::EntityMetadataHeader::parse(raw)
                .ok_or(crate::error::Error::CorruptedIndex("pack source header"))?;
            let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
            Some(
                if header.entity_type == crate::registry::ENTITY_TYPE_ASSET {
                    (
                        true,
                        crate::store::asset_carrier_body_in_txn(store, txn, id, body)?,
                    )
                } else {
                    (false, std::borrow::Cow::Borrowed(body))
                },
            )
        }
        None => None,
    };
    if let Some((true, old)) = &previous
        && decode(old)?.is_some()
        && (entity_type != crate::registry::ENTITY_TYPE_ASSET || **old != *bytes)
    {
        return Err(invalid(
            "content-addressed pack source cannot be overwritten",
        ));
    }
    if entity_type == crate::registry::ENTITY_TYPE_ASSET
        && let Some(source) = decode(bytes)?
    {
        if source_id(&source)? != *id {
            return Err(invalid("source entity ID disagrees with content hash"));
        }
        if let Some((_, old)) = &previous
            && **old != *bytes
        {
            return Err(invalid("source hash collides with an existing asset"));
        }
    }
    Ok(())
}
