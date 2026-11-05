//! Native histories in the exact raw image rows, before their first landing.
//!
//! These are source/schema checks, not a native admission or carrier receipt.
//! Opaque rows gain no native authority through this path.

use std::collections::BTreeMap;

use super::super::forks::{ENTITY_DOC_FORK, ENTITY_DOC_FORK_SNAPSHOT, ForkRecord};
use super::super::native_skill_state::validate_image_history;
use super::super::{EntityDoc, document, storage};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::ports::DocumentSlot;
use crate::side_table::{self, FixedSideKey, HexId, SideKey};

type ImageRows = BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>;

#[derive(Default)]
struct Slot<'a> {
    snapshot: Option<&'a [u8]>,
    updates: Vec<&'a [u8]>,
}

fn invalid() -> Error {
    Error::CorruptedIndex("checkpoint raw native SKILL state source")
}

/// The caller retains the closed image owner through this check and landing.
/// No returned value can turn caller-provided rows into a native source.
pub(crate) fn validate_native_image_rows(databases: &ImageRows) -> Result<()> {
    let rows = databases.get("sync_state").ok_or_else(invalid)?;
    let mut slots: BTreeMap<&[u8], Slot<'_>> = BTreeMap::new();
    for (key, value) in rows {
        if let Some(slot) = key.strip_prefix(side_table::DOCUMENT_SNAPSHOT.prefix) {
            slots.entry(slot).or_default().snapshot = Some(value);
        } else if let Some(key) = key.strip_prefix(side_table::DOCUMENT_UPDATE.prefix)
            && let Some((slot, rest)) = key.split_at_checked(DocumentSlot::WIDTH)
            && rest.starts_with(b":")
        {
            // The native row port imports every raw suffix in key order,
            // even when the sequence spelling itself is not recognized.
            slots.entry(slot).or_default().updates.push(value);
        }
    }
    for (slot, group) in slots {
        let Some(snapshot) = group.snapshot else {
            // No joined document exists here yet. This is not a native
            // admission for these opaque/pending bytes at a later ingress.
            continue;
        };
        if let Some(doc) = validate_image_history(std::iter::once(snapshot).chain(group.updates))? {
            DocumentSlot::decode_key(slot).ok_or_else(invalid)?;
            require_source_heads(databases, slot, &doc)?;
        }
    }
    for (key, snapshot) in rows {
        let Some(key) = key.strip_prefix(ENTITY_DOC_FORK_SNAPSHOT.decl().prefix) else {
            continue;
        };
        let Some(doc) = validate_image_history(std::iter::once(snapshot.as_slice()))? else {
            continue;
        };
        let fork = String::decode_key(key).ok_or_else(invalid)?;
        let record_key = ENTITY_DOC_FORK.decl().prefix;
        let value = rows
            .iter()
            .find(|(key, _)| key.strip_prefix(record_key) == Some(fork.as_bytes()))
            .map(|(_, value)| value)
            .ok_or_else(invalid)?;
        let record: ForkRecord = storage::decode(value)?;
        require_fork_basis(&fork, &record, &doc)?;
    }
    Ok(())
}

/// A selected raw head binds its source entity to this source slot. Retained
/// history may have no current head; a fact's own publication slot remains
/// historical after SWITCH and is deliberately not compared here.
fn require_source_heads(databases: &ImageRows, slot: &[u8], doc: &EntityDoc) -> Result<()> {
    let rows = databases.get("vault_meta").ok_or_else(invalid)?;
    for (key, value) in rows {
        let Some(key) = key.strip_prefix(storage::ENTITY_DOC_HEAD.decl().prefix) else {
            continue;
        };
        let Ok(head) = storage::decode::<storage::Head>(value) else {
            // Opaque rows remain data, never a source admission.
            continue;
        };
        if head.document.as_bytes() != slot {
            continue;
        }
        let entity = HexId::decode_key(key).ok_or_else(invalid)?;
        if head.entity != entity.0.to_hex() || head.entity != doc.birth().entity {
            return Err(invalid());
        }
    }
    Ok(())
}

fn require_fork_basis(fork: &str, record: &ForkRecord, doc: &EntityDoc) -> Result<()> {
    if record.fork != fork || record.entity != doc.birth().entity {
        return Err(invalid());
    }
    EntityId::from_hex(fork)?;
    EntityId::from_hex(&record.parent_document)?;
    let base = document::decode_frontier(&record.base)?;
    if doc.doc.frontiers_to_vv(&base).is_none() {
        return Err(invalid());
    }
    Ok(())
}
