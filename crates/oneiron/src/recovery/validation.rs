//! Fail-closed whole-payload validation before a recovery mutation.

use super::canonical::{CanonicalSnapshot, id, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate(snapshot: &CanonicalSnapshot) -> Result<()> {
    let window = snapshot.window.as_bytes();
    if window.len() != 7
        || window[4] != b'-'
        || !window[..4].iter().all(u8::is_ascii_digit)
        || !window[5..].iter().all(u8::is_ascii_digit)
        || !(1..=12).contains(&snapshot.window[5..].parse::<u8>().unwrap_or(0))
    {
        return Err(invalid("window key"));
    }
    if snapshot.schema_manifest.oneiron_schema_version != crate::store::STORAGE_ABI_VERSION
        || snapshot.schema_manifest.container_schema_version != 1
        || snapshot.schema_manifest.loro_version.is_empty()
    {
        return Err(invalid("unsupported schema manifest"));
    }
    strict(snapshot.entity_blobs.iter().map(|row| row.id))?;
    strict(
        snapshot
            .base_edges
            .iter()
            .map(|row| (row.source, row.kind, row.target)),
    )?;
    strict(snapshot.tombstones.iter().map(|row| row.id))?;
    strict(
        snapshot
            .container_manifests
            .iter()
            .map(|row| row.container_id.as_str()),
    )?;
    if snapshot.container_manifests != snapshot.expected_containers() {
        return Err(invalid("container manifest coverage"));
    }
    let deleted: BTreeMap<_, _> = snapshot
        .tombstones
        .iter()
        .map(|row| (row.id, crate::deletion::decode_tombstone_value(&row.value)))
        .collect();
    for entity in &snapshot.entity_blobs {
        id(entity.id)?;
        if let Some(tombstone) = deleted.get(&entity.id)
            && (tombstone.is_hard() || entity.blob.len() != ENTITY_METADATA_HEADER_LEN)
        {
            return Err(invalid("tombstoned entity payload"));
        }
        let header = EntityMetadataHeader::parse(&entity.blob).ok_or(invalid("entity envelope"))?;
        crate::registry::validate_entity_type(header.entity_type)?;
        if header.occurred_start > header.occurred_end {
            return Err(invalid("entity time range"));
        }
        let body = &entity.blob[ENTITY_METADATA_HEADER_LEN..];
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM && !body.is_empty() {
            crate::claim::validate_claim_body_and_decode(body, true)?;
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE && !body.is_empty() {
            crate::note::decode_note_body_using(body, crate::note::NoteKind::wire)?;
        }
    }
    for edge in &snapshot.base_edges {
        id(edge.source)?;
        id(edge.target)?;
        if deleted
            .get(&edge.source)
            .is_some_and(crate::deletion::DecodedTombstoneValue::is_hard)
            || deleted
                .get(&edge.target)
                .is_some_and(crate::deletion::DecodedTombstoneValue::is_hard)
        {
            return Err(invalid("hard-deleted edge endpoint"));
        }
        let kind = crate::edge::EdgeKind::try_from_u8(edge.kind).ok_or(invalid("edge kind"))?;
        crate::edge::decode_edge_value_for_kind(kind, &edge.value)?;
    }
    for tombstone in &snapshot.tombstones {
        id(tombstone.id)?;
        let decoded = crate::deletion::decode_tombstone_value(&tombstone.value);
        if decoded.reason == Some(crate::deletion::TombstoneReason::ArchivedByCleanup) {
            return Err(invalid("local-only archive in window snapshot"));
        }
        if !decoded.is_hard()
            && !snapshot
                .entity_blobs
                .iter()
                .any(|row| row.id == tombstone.id)
        {
            return Err(invalid("soft tombstone missing retained shell"));
        }
        if !matches!(tombstone.value.len(), 8 | 25)
            || tombstone.deleted_at
                != crate::deletion::decode_tombstone_value(&tombstone.value).deleted_at
        {
            return Err(invalid("tombstone timestamp or encoding"));
        }
    }
    validate_documents(snapshot)
}

pub(super) fn validate_documents(snapshot: &CanonicalSnapshot) -> Result<()> {
    strict(
        snapshot
            .doc_snapshots
            .iter()
            .map(|row| (row.entity_id, row.head)),
    )?;
    strict(snapshot.document_heads.iter().map(|row| row.entity_id))?;
    strict(snapshot.head_move_receipts.iter().map(|row| row.id))?;
    let mut cores = BTreeMap::new();
    for entity in &snapshot.entity_blobs {
        let header =
            EntityMetadataHeader::parse(&entity.blob).ok_or(invalid("document owner header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
            && entity.blob.len() > ENTITY_METADATA_HEADER_LEN
        {
            cores.insert(
                entity.id,
                crate::note::decode_note_body_using(
                    &entity.blob[ENTITY_METADATA_HEADER_LEN..],
                    crate::note::NoteKind::wire,
                )?,
            );
        }
    }
    let docs: BTreeSet<_> = snapshot
        .doc_snapshots
        .iter()
        .map(|row| (row.entity_id, row.head))
        .collect();
    let heads: BTreeMap<_, _> = snapshot
        .document_heads
        .iter()
        .map(|row| (row.entity_id, row.head))
        .collect();
    for row in &snapshot.doc_snapshots {
        id(row.entity_id)?;
        id(row.head)?;
        id(row.birth_actor)?;
        let core = cores
            .get(&row.entity_id)
            .ok_or(invalid("document owner is not a NOTE"))?;
        if row.birth_actor != *core.author_ref.as_bytes() || !heads.contains_key(&row.entity_id) {
            return Err(invalid("document birth binding"));
        }
        row.rebuild()?;
        let header = snapshot
            .entity_blobs
            .iter()
            .find(|entity| entity.id == row.entity_id)
            .and_then(|entity| EntityMetadataHeader::parse(&entity.blob))
            .ok_or(invalid("document envelope"))?;
        if row.birth_at != header.learned_at {
            return Err(invalid("document birth timestamp binding"));
        }
        if row.head == row.entity_id {
            let birth = row
                .authorship
                .iter()
                .find(|record| record.operation.as_bytes() == &row.entity_id)
                .ok_or(invalid("NOTE birth provenance missing"))?;
            if birth.actor != core.author_ref
                || birth.actor_class != "ledger"
                || birth.grant.is_some()
                || birth.command_hash != *blake3::hash(core.markdown.as_bytes()).as_bytes()
            {
                return Err(invalid("NOTE birth provenance binding"));
            }
        }
        if row.head != row.entity_id
            && heads.get(&row.entity_id) != Some(&row.head)
            && !row.authorship.is_empty()
        {
            return Err(invalid("proposal value claims authority"));
        }
    }
    // A switch moves the head to its fork; a merge or reject keeps it.
    let mut switched = BTreeSet::new();
    for row in &snapshot.head_move_receipts {
        let receipt = row.decode()?;
        let head_binding = match receipt.verdict {
            crate::note::NoteVerdict::Switch => receipt.head == receipt.fork,
            _ => receipt.head == receipt.previous_head,
        };
        if !cores.contains_key(&row.entity_id) || !head_binding {
            return Err(invalid("receipt canonical identity"));
        }
        if receipt.verdict == crate::note::NoteVerdict::Switch {
            switched.insert((row.entity_id, *receipt.head.as_bytes()));
        }
        let fork = *receipt.fork.as_bytes();
        if docs.contains(&(row.entity_id, fork)) && heads.get(&row.entity_id) != Some(&fork) {
            return Err(invalid("decided proposal retains text"));
        }
    }
    for entity in cores.keys() {
        if heads
            .get(entity)
            .is_none_or(|head| !docs.contains(&(*entity, *head)))
        {
            return Err(invalid("live NOTE has no canonical document value"));
        }
    }
    for row in &snapshot.document_heads {
        if !cores.contains_key(&row.entity_id)
            || (row.head != row.entity_id && !switched.contains(&(row.entity_id, row.head)))
            || !docs.contains(&(row.entity_id, row.head))
        {
            return Err(invalid("canonical document identity"));
        }
    }
    super::document::validate_workflows(snapshot)
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
