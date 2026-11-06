//! Fail-closed whole-payload validation before a recovery mutation.

use super::canonical::{CanonicalSnapshot, id, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};

mod documents;
mod entity_documents;
mod entity_history;
mod manifest;
mod window_rows;
pub(super) use documents::DocumentRows;
pub(super) use entity_documents::EntityDocumentRows;
pub(super) use manifest::ManifestValidation;
pub(super) use window_rows::WindowRows;

/// Drain the NOTE-only validator for native document capture callers.
pub(super) fn validate_documents(snapshot: &CanonicalSnapshot) -> Result<()> {
    let mut validation = DocumentRows::default();
    while !validation.advance(snapshot, usize::MAX)? {}
    Ok(())
}

/// Drain the generic document validator for native document capture callers.
pub(super) fn validate_entity_documents(snapshot: &CanonicalSnapshot) -> Result<()> {
    let mut validation = EntityDocumentRows::default();
    while !validation.advance(snapshot, usize::MAX)? {}
    Ok(())
}

/// Recovery-only proof for an AddressedTo edge retained by a soft-erased
/// TURN. Ordinary peer replay never receives this trust: the old `to` bytes
/// are gone, so only a validated local canonical snapshot of the retained
/// shell and its BaseEdge can carry the historical structural fact.
pub(crate) fn trusted_soft_addressing_edge(
    snapshot: &CanonicalSnapshot,
    source: &crate::EntityId,
    target: &crate::EntityId,
    value: &[u8],
) -> Result<bool> {
    let Some(tombstone) = snapshot
        .tombstones
        .iter()
        .find(|row| row.id == *source.as_bytes())
    else {
        return Ok(false);
    };
    let decoded = crate::deletion::decode_tombstone_value(&tombstone.value);
    if decoded.reason != Some(crate::deletion::TombstoneReason::UserDelete) {
        return Err(invalid(
            "addressing source is not a retained user-delete shell",
        ));
    }
    let source_row = snapshot
        .entity_blobs
        .iter()
        .find(|row| row.id == *source.as_bytes())
        .ok_or(invalid("missing retained addressing shell"))?;
    let header = EntityMetadataHeader::parse(&source_row.blob)
        .ok_or(invalid("invalid retained addressing shell"))?;
    if source_row.blob.len() != ENTITY_METADATA_HEADER_LEN
        || header.entity_type != crate::registry::ENTITY_TYPE_TURN
    {
        return Err(invalid("addressing shell is not an erased TURN"));
    }
    // A canonical window need not contain a recipient from another month.
    // If it does, validate it here; otherwise the capture/replay doors prove
    // the PERSON or AGENT_DEF against the vault holding the neighboring window.
    if let Some(recipient) = snapshot
        .entity_blobs
        .iter()
        .find(|row| row.id == *target.as_bytes())
        && EntityMetadataHeader::parse(&recipient.blob).is_none_or(|h| {
            !matches!(
                h.entity_type,
                crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF
            )
        })
    {
        return Err(invalid(
            "retained addressing recipient is not a PERSON or AGENT_DEF",
        ));
    }
    let fields = crate::edge::decode_edge_value_for_kind(crate::EdgeKind::AddressedTo, value)?;
    if fields.layout != crate::edge::EdgeValueLayout::Structural
        || fields.weight != 1.0
        || fields.created_at != header.learned_at
        || !snapshot.base_edges.iter().any(|row| {
            row.source == *source.as_bytes()
                && row.kind == crate::EdgeKind::AddressedTo as u8
                && row.target == *target.as_bytes()
                && row.value == value
        })
    {
        return Err(invalid(
            "retained addressing edge differs from canonical shell",
        ));
    }
    Ok(true)
}

/// A document pointer in a raw entity row MUST have its value in the artifact.
/// Do not trust the writer: decoded payloads enter this gate too.
fn pointer(body: &[u8]) -> Result<Option<String>> {
    let mut reader = std::io::Cursor::new(body);
    let Ok(value) = rmpv::decode::read_value(&mut reader) else {
        return Ok(None);
    };
    let rmpv::Value::Map(fields) = value else {
        return Ok(None);
    };
    let refs: Vec<_> = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some("entity_doc_ref"))
        .collect();
    if refs.is_empty() {
        return Ok(None);
    }
    if refs.len() != 1 || reader.position() != body.len() as u64 {
        return Err(invalid("entity document pointer encoding"));
    }
    let value = refs[0]
        .1
        .as_str()
        .ok_or(invalid("entity document pointer type"))?;
    id(super::canonical::parse_id(value)?)?;
    Ok(Some(value.to_owned()))
}

/// A causal row binds inside itself: every version leads to the head, pins
/// quote their version, and forks, receipts and purges name carried versions.
fn validate_document_metadata(
    fields: &BTreeMap<String, Vec<u8>>,
    body_field: Option<&str>,
) -> Result<()> {
    for (field, bytes) in fields {
        validate_document_metadata_field(field, bytes, body_field)?;
    }
    Ok(())
}

fn validate_document_metadata_field(
    field: &str,
    bytes: &[u8],
    body_field: Option<&str>,
) -> Result<()> {
    if Some(field) == body_field {
        return Err(invalid("document body duplicated in metadata"));
    }
    let mut cursor = bytes;
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("document metadata encoding"))?;
    if !cursor.is_empty() {
        return Err(invalid("trailing document metadata bytes"));
    }
    crate::ports::validate_metadata(field, &value)?;
    Ok(())
}

/// A scope summary's purpose and derivation (FIX 756): only those two keys,
/// each one whole value of its own type.
fn validate_summary_meta(fields: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for (field, bytes) in fields {
        validate_summary_meta_field(field, bytes)?;
    }
    Ok(())
}

fn validate_summary_meta_field(field: &str, bytes: &[u8]) -> Result<()> {
    match field {
        "purpose" => decode_whole::<crate::scope_summary::SummaryPurpose>(bytes)?,
        "derivation" => decode_whole::<crate::scope_summary::SummaryDerivation>(bytes)?,
        _ => return Err(invalid("entity document summary meta field")),
    }
    Ok(())
}

/// Whether `bytes` are exactly one MessagePack value of `T`.
fn decode_whole<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<()> {
    let mut reader = std::io::Cursor::new(bytes);
    rmp_serde::from_read::<_, T>(&mut reader)
        .map_err(|_| invalid("entity document summary meta encoding"))?;
    if usize::try_from(reader.position()).ok() != Some(bytes.len()) {
        return Err(invalid("trailing entity document summary meta bytes"));
    }
    Ok(())
}

pub(super) fn strict<T: Ord>(values: impl IntoIterator<Item = T>) -> Result<()> {
    let mut previous = None;
    for value in values {
        if previous.as_ref().is_some_and(|old| old >= &value) {
            return Err(invalid("duplicate or unordered canonical record"));
        }
        previous = Some(value);
    }
    Ok(())
}
