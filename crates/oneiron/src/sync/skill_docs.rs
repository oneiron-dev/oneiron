//! Linked native SKILL document data beside its exact entities-map row.
//!
//! This family is separate from MESSAGE witnesses. Reassembly does not
//! authorize a record put or install a document. The ingest door consumes
//! the data only under its selected own-device import and ordinary gates.

use std::collections::BTreeSet;

use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::bridge::BRIDGE_ORIGIN;
use super::carrier_parts::{
    Parts, admit_part, is_part_key, join_parts, split_parts, unreferenced_parts, write_parts,
};
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::entity_doc::{CarriedRecordDocument, export_skill_record_document_in_txn};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

pub(crate) const SKILL_DOCS_MAP: &str = "skill_docs";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("skill document refused: {reason}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedHead {
    record: CarriedRecordDocument,
    snapshot: Parts,
}

fn encode(carried: &CarriedHead) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(carried).map_err(|_| refused("does not encode"))
}

fn decode(bytes: &[u8]) -> Result<(CarriedHead, EntityId)> {
    let carried: CarriedHead =
        rmp_serde::from_slice(bytes).map_err(|_| refused("not a document head"))?;
    let entity = carried.record.entity()?;
    if encode(&carried)? != bytes || !carried.snapshot.well_formed() {
        return Err(refused("not a whole head in its one spelling"));
    }
    Ok((carried, entity))
}

/// Every insertion, including retained operations, has one spelling.
pub(crate) fn admit_skill_doc_carrier(
    window: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if window.is_some_and(|window| window.world().is_some()) {
        return Err(refused("in a world window"));
    }
    if is_part_key(map_key) {
        return admit_part(map_key, value);
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    let (_, entity) = decode(bytes)?;
    if entity.to_hex() != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
}

pub(crate) fn admit_skill_doc_map(window: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|key, value| match value {
        ValueOrContainer::Value(value) => rows.push((key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (key, value) in &rows {
        admit_skill_doc_carrier(window, key, value)?;
    }
    Ok(())
}

/// Reassembles only the head filed under this selected row, when all its
/// parts are present. This returns data, never an admitted-pair witness.
pub(crate) fn selected_record_document(
    doc: &LoroDoc,
    entity: &EntityId,
    raw: &[u8],
) -> Result<Option<(CarriedRecordDocument, Vec<u8>)>> {
    if !holds_skill_doc_map(doc) {
        return Ok(None);
    }
    let map = doc.get_map(SKILL_DOCS_MAP);
    let Some(bytes) = map_get_bytes(&map, &entity.to_hex()) else {
        return Ok(None);
    };
    let (carried, owner) = decode(&bytes)?;
    if owner != *entity {
        return Err(refused("filed under another row"));
    }
    let Some(snapshot) = join_parts(&map, &carried.snapshot) else {
        return Ok(None);
    };
    carried.record.document(raw, &snapshot)?;
    Ok(Some((carried.record, snapshot)))
}

/// The entity carriers affected by head or part inserts. A part-only delta
/// re-presents the actual existing entities-map row to the ordinary ladder;
/// it must not use a postcommit document installer to bypass that ladder.
pub(crate) fn affected_rows(doc: &LoroDoc, updated: &BTreeSet<String>) -> BTreeSet<EntityId> {
    if !holds_skill_doc_map(doc) {
        return BTreeSet::new();
    }
    let parts_changed = updated.iter().any(|key| is_part_key(key));
    head_rows(&doc.get_map(SKILL_DOCS_MAP))
        .into_iter()
        .filter_map(|(key, bytes)| {
            let (head, entity) = decode(&bytes).ok()?;
            (updated.contains(&key)
                || (parts_changed && head.snapshot.keys().any(|part| updated.contains(&part))))
            .then_some(entity)
        })
        .collect()
}

/// Source capture is one read transaction: the immutable row, actual head,
/// retained document/floor and first-Candidate hash cannot race each other.
/// No federation/guest or receiver admission is conferred by this helper.
pub(crate) fn mirror_skill_document(
    vault: &Vault,
    doc: &LoroDoc,
    entity: &EntityId,
    window: &WindowKey,
) -> Result<bool> {
    if window.world().is_some() {
        return Ok(false);
    }
    let Some(raw) = map_get_bytes(&doc.get_map("entities"), &entity.to_hex()) else {
        return Ok(false);
    };
    let source = {
        let txn = vault.store.env.read_txn()?;
        export_skill_record_document_in_txn(&vault.store, &txn, entity, &raw)?
    };
    let Some((record, snapshot)) = source else {
        return Ok(false);
    };
    let map = doc.get_map(SKILL_DOCS_MAP);
    let key = entity.to_hex();
    let held = map_get_bytes(&map, &key)
        .map(|bytes| decode(&bytes))
        .transpose()?
        .map(|(held, _)| held);
    if let Some(held) = &held {
        let local = record.native();
        let remote = held.record.native();
        if !(local.holds(remote) || local.replaces(remote))
            || (remote.covers(local)
                && held.record.source_birth_frontier() == record.source_birth_frontier()
                && held.record.refinement_origin() == record.refinement_origin())
            || remote.purges(local)
        {
            return Ok(false);
        }
    }
    let (parts, pieces) = split_parts(&snapshot)?;
    let carried = CarriedHead {
        record,
        snapshot: parts,
    };
    if let Some(held) = &held
        && !carried.record.native().covers(held.record.native())
        && (!carried.record.native().replaces(held.record.native())
            || carried.record.native().purges(held.record.native()))
    {
        super::window::require_history_free_window(vault, window)?;
    }
    map_insert_bytes(&map, &key, &encode(&carried)?)?;
    commit(doc);
    write_parts(&map, &pieces, || commit(doc))?;
    // A part can be shared with another head. Remove only parts no current
    // head references, after the replacement and all its pieces are present.
    let mut referenced = BTreeSet::new();
    for (_, bytes) in head_rows(&map) {
        let (head, _) = decode(&bytes)?;
        referenced.extend(head.snapshot.keys());
    }
    for part in unreferenced_parts(&map, &referenced) {
        map_delete(&map, &part)?;
    }
    commit(doc);
    Ok(true)
}

fn commit(doc: &LoroDoc) {
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
}

fn head_rows(map: &LoroMap) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|key, value| {
        if !is_part_key(key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
        {
            rows.push((key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

fn holds_skill_doc_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(SKILL_DOCS_MAP))
}

/// Erase and membership cleanup use the same history-free pin as the
/// MESSAGE family, before deleting any head or orphaned part.
pub(crate) fn scrub_skill_docs(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_skill_doc_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(SKILL_DOCS_MAP);
    let entities = doc.get_map("entities");
    let mut gone = Vec::new();
    let mut referenced = BTreeSet::new();
    {
        let txn = vault.store.env.read_txn()?;
        for (key, bytes) in head_rows(&map) {
            let (head, entity) = decode(&bytes)?;
            if !map_contains_binary(&entities, &key)
                || crate::ports::removed_in_txn(&vault.store, &txn, &entity)?
            {
                gone.push(key);
            } else {
                referenced.extend(head.snapshot.keys());
            }
        }
    }
    gone.extend(unreferenced_parts(&map, &referenced));
    if gone.is_empty() {
        return Ok(false);
    }
    if let Some(window) = history_free {
        super::window::require_history_free_window(vault, window)?;
    }
    for key in gone {
        map_delete(&map, &key)?;
    }
    commit(doc);
    Ok(true)
}
