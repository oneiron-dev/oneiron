//! Fail-closed whole-payload validation before a recovery mutation.

use super::canonical::{
    CanonicalEntityDocument, CanonicalForkStatus, CanonicalSnapshot, id, invalid,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};

mod documents;
mod entity_documents;
mod window_rows;
pub(super) use documents::DocumentRows;
pub(super) use entity_documents::EntityDocumentRows;
pub(super) use window_rows::WindowRows;

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

pub(super) fn validate_manifest_and_order(snapshot: &CanonicalSnapshot) -> Result<()> {
    if crate::deletion::parse_window_label(&snapshot.window).is_none() {
        return Err(invalid("window key"));
    }
    if snapshot.schema_manifest.oneiron_schema_version != crate::store::STORAGE_ABI_VERSION
        || snapshot.schema_manifest.container_schema_version != 3
        || snapshot.schema_manifest.loro_version.is_empty()
    {
        return Err(invalid("unsupported schema manifest"));
    }
    strict(snapshot.entity_blobs.iter().map(|row| row.id))?;
    strict(snapshot.retained_claim_worlds.iter().map(|row| row.id))?;
    strict(
        snapshot
            .custody_transitions
            .iter()
            .map(|row| (row.id, row.piece)),
    )?;
    strict(snapshot.room_turns.iter().map(|row| row.key.as_str()))?;
    for row in &snapshot.room_turns {
        if !crate::room_codec::carrier_parts::is_part_key(&row.key) {
            super::canonical::parse_id(&row.key)?;
        }
    }
    strict(snapshot.room_facts.iter().map(|row| row.key.as_str()))?;
    strict(snapshot.document_pins.iter().map(|row| row.key.as_str()))?;
    strict(snapshot.peer_origins.iter().map(|row| row.id))?;
    // Custody transitions ride base windows only (OF-422).
    if snapshot.window.contains('@') && !snapshot.custody_transitions.is_empty() {
        return Err(invalid("custody transition in a world window"));
    }
    // Room turn rows ride base windows only (OF-522).
    if snapshot.window.contains('@') && !snapshot.room_turns.is_empty() {
        return Err(invalid("room turn row in a world window"));
    }
    // Room side rows too (FIX 1794).
    if snapshot.window.contains('@') && !snapshot.room_facts.is_empty() {
        return Err(invalid("room side row in a world window"));
    }
    // And document quote pins (FIX 853).
    if snapshot.window.contains('@') && !snapshot.document_pins.is_empty() {
        return Err(invalid("document pin in a world window"));
    }
    strict(
        snapshot
            .base_edges
            .iter()
            .map(|row| (row.source, row.kind, row.target)),
    )?;
    strict(snapshot.tombstones.iter().map(|row| row.id))?;
    strict(snapshot.suppressed_tasks.iter())?;
    for task in &snapshot.suppressed_tasks {
        let held = snapshot
            .entity_blobs
            .binary_search_by_key(task, |row| row.id)
            .ok()
            .and_then(|at| EntityMetadataHeader::parse(&snapshot.entity_blobs[at].blob));
        if held.is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_TASK) {
            return Err(invalid("suppressed task outside the window"));
        }
    }
    // A peer origin names a row the window holds, by the digest of its whole
    // blob (FIX 4550): never an absent row's, nor an earlier body's.
    for origin in &snapshot.peer_origins {
        let held = snapshot
            .entity_blobs
            .binary_search_by_key(&origin.id, |row| row.id)
            .ok()
            .map(|at| *blake3::hash(&snapshot.entity_blobs[at].blob).as_bytes());
        if held != Some(origin.digest) {
            return Err(invalid("peer origin outside the window"));
        }
    }
    strict(
        snapshot
            .container_manifests
            .iter()
            .map(|row| row.container_id.as_str()),
    )?;
    if snapshot.container_manifests != snapshot.expected_containers() {
        return Err(invalid("container manifest coverage"));
    }
    Ok(())
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
fn validate_history(row: &CanonicalEntityDocument) -> Result<()> {
    strict(row.record_fields.iter())?;
    if row.record_fields.iter().any(|field| {
        !crate::ports::is_metadata_field(field) || row.field.as_deref() == Some(field.as_str())
    }) || (row.field.is_none() && !row.record_fields.is_empty())
    {
        return Err(invalid("document native record fields"));
    }
    validate_document_metadata(&row.metadata, row.field.as_deref())?;
    validate_summary_meta(&row.summary_meta)?;
    let Some(history) = &row.history else {
        return Ok(());
    };
    if !history.shallow
        && history.pins.is_empty()
        && history.receipts.is_empty()
        && history.forks.is_empty()
        && history.purges.is_empty()
    {
        return Err(invalid("entity document history without causal state"));
    }
    if !history.purges.is_empty() && !history.shallow {
        return Err(invalid("entity document purge without a purge floor"));
    }
    let texts = history.texts()?;
    let head = texts
        .len()
        .checked_sub(1)
        .ok_or(invalid("entity document history has no head"))?;
    if texts[head] != row.text || history.versions[head].metadata != row.metadata {
        return Err(invalid("entity document head version"));
    }
    let mut reached = vec![false; texts.len()];
    reached[head] = true;
    for (index, version) in history.versions.iter().enumerate().rev() {
        validate_document_metadata(&version.metadata, row.field.as_deref())?;
        validate_summary_meta(&version.summary_meta)?;
        if !reached[index] {
            return Err(invalid("entity document version is not before its head"));
        }
        if history.shallow && index > 0 && version.parents.is_empty() {
            return Err(invalid("entity document version precedes its purge floor"));
        }
        strict(version.parents.iter().copied())?;
        for &parent in &version.parents {
            let parent = parent as usize;
            if parent >= index {
                return Err(invalid("entity document version parent"));
            }
            reached[parent] = true;
        }
    }
    let version = |index: u32| (index as usize) < texts.len();
    strict(history.pins.iter().map(|pin| pin.citation))?;
    for pin in &history.pins {
        for value in [pin.citation, pin.document].into_iter().chain(pin.actor) {
            id(value)?;
        }
        let text = texts
            .get(pin.version as usize)
            .ok_or(invalid("entity document pin version"))?;
        let (start, end) = (pin.start as usize, pin.end as usize);
        let quote: String = text
            .chars()
            .skip(start)
            .take(end.saturating_sub(start))
            .collect();
        if start > end
            || end > text.chars().count()
            || quote != pin.quote
            || blake3::hash(quote.as_bytes()).as_bytes() != &pin.hash
        {
            return Err(invalid("entity document pin quote"));
        }
    }
    strict(history.receipts.iter().map(|receipt| receipt.receipt))?;
    for receipt in &history.receipts {
        for value in [receipt.receipt, receipt.proposal, receipt.fork]
            .into_iter()
            .chain(receipt.actor)
        {
            id(value)?;
        }
        if !version(receipt.before) || !version(receipt.after) {
            return Err(invalid("entity document receipt version"));
        }
    }
    strict(history.forks.iter().map(|fork| fork.fork))?;
    for fork in &history.forks {
        for value in [fork.fork, fork.proposal, fork.parent_document]
            .into_iter()
            .chain(fork.actor)
        {
            id(value)?;
        }
        let pending = fork.status == CanonicalForkStatus::Pending;
        match fork.base {
            Some(base) if version(base) => {}
            None if history.shallow && !pending => {}
            _ => return Err(invalid("entity document fork base")),
        }
        if let Some(metadata) = &fork.output_metadata {
            validate_document_metadata(metadata, row.field.as_deref())?;
        }
        if fork.output_metadata.is_some() != pending
            || fork.output.is_some() != pending
            || fork.proposal_index >= fork.proposal_len
        {
            return Err(invalid("entity document fork state"));
        }
    }
    strict(history.purges.iter().map(|purge| purge.receipt))?;
    for purge in &history.purges {
        for value in [purge.receipt, purge.document]
            .into_iter()
            .chain(purge.actor)
        {
            id(value)?;
        }
        if !version(purge.requested) || !version(purge.applied) {
            return Err(invalid("entity document purge version"));
        }
    }
    Ok(())
}

fn validate_document_metadata(
    fields: &BTreeMap<String, Vec<u8>>,
    body_field: Option<&str>,
) -> Result<()> {
    for (field, bytes) in fields {
        if Some(field.as_str()) == body_field {
            return Err(invalid("document body duplicated in metadata"));
        }
        let mut cursor = bytes.as_slice();
        let value = rmpv::decode::read_value(&mut cursor)
            .map_err(|_| invalid("document metadata encoding"))?;
        if !cursor.is_empty() {
            return Err(invalid("trailing document metadata bytes"));
        }
        crate::ports::validate_metadata(field, &value)?;
    }
    Ok(())
}

/// A scope summary's purpose and derivation (FIX 756): only those two keys,
/// each one whole value of its own type.
fn validate_summary_meta(fields: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for (field, bytes) in fields {
        match field.as_str() {
            "purpose" => decode_whole::<crate::scope_summary::SummaryPurpose>(bytes)?,
            "derivation" => decode_whole::<crate::scope_summary::SummaryDerivation>(bytes)?,
            _ => return Err(invalid("entity document summary meta field")),
        }
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
