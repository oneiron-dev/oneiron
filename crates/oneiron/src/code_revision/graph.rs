//! child_of lifecycle edges and the entity guards a revision write must clear.

use std::collections::{HashSet, VecDeque};

use heed::{RoTxn, RwTxn};

use crate::affect::Vad;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, child_of_prefix};
use crate::code_artifact::decode_code_artifact_body;
use crate::edge::{EdgeKind, encode_edge_value, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::ppr;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::store::Store;

use super::storage::get_code_revision_in_txn;
use super::types::CodeRevision;

pub(super) fn put_lifecycle_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    created_at: u64,
    graph_changed: &mut bool,
) -> Result<()> {
    let weight = kind.default_weight().unwrap_or(1.0);
    let value = encode_edge_value(kind, weight, created_at, Vad::NEUTRAL, None)?;
    let key_out = Store::encode_edge_key(src, kind, tgt);
    let key_in = Store::encode_edge_key(tgt, kind, src);
    let changed = store
        .edges_out
        .get(wtxn, &key_out)?
        .is_none_or(|existing| existing != value.as_slice())
        || store
            .edges_in
            .get(wtxn, &key_in)?
            .is_none_or(|existing| existing != value.as_slice());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    if changed {
        ppr::invalidate_ppr_for_edge(store, wtxn, src, tgt)?;
        *graph_changed = true;
    }
    Ok(())
}

pub(super) fn validate_child_of_insert(
    store: &Store,
    txn: &RwTxn<'_>,
    child: &EntityId,
    parent: &EntityId,
) -> Result<()> {
    let parents = child_of_parents(store, txn, child)?;
    if parents.len() > 1 || parents.first().is_some_and(|existing| existing != parent) {
        return Err(Error::ChildOfCardinality);
    }
    if child == parent || would_create_child_of_cycle(store, txn, child, parent)? {
        return Err(Error::CycleDetected);
    }
    Ok(())
}

fn would_create_child_of_cycle(
    store: &Store,
    txn: &RwTxn<'_>,
    child: &EntityId,
    parent: &EntityId,
) -> Result<bool> {
    let mut frontier = VecDeque::new();
    frontier.push_back(*parent);
    let mut visited = HashSet::new();
    visited.insert(*parent);
    let mut traversed_steps = 0usize;

    while let Some(node) = frontier.pop_front() {
        for next_parent in child_of_parents(store, txn, &node)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
            if next_parent == *child {
                return Ok(true);
            }
            if visited.insert(next_parent) {
                frontier.push_back(next_parent);
            }
        }
    }

    Ok(false)
}

fn child_of_parents(store: &Store, txn: &RwTxn<'_>, child: &EntityId) -> Result<Vec<EntityId>> {
    let prefix = child_of_prefix(child);
    let mut parents = Vec::new();
    for entry in store.edges_out.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        let edge = parse_strict_edge_record(&key, &value)?;
        if edge.kind != EdgeKind::ChildOf {
            return Err(Error::CorruptedIndex("edge record"));
        }
        parents.push(edge.target);
    }
    parents.sort_unstable();
    parents.dedup();
    Ok(parents)
}

pub(super) fn require_known_code_revision(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<CodeRevision> {
    require_entity_type(
        store,
        rtxn,
        revision_id,
        ENTITY_TYPE_CODE_ARTIFACT,
        "code revision id must be a CODE_ARTIFACT entity",
    )?;
    get_code_revision_in_txn(store, rtxn, revision_id)?.ok_or(Error::InvalidCodeArtifactBody(
        "code revision must be finalized before it can be referenced",
    ))
}

pub(super) fn require_code_artifact_body(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Vec<u8>> {
    code_artifact_body_bytes(store, rtxn, revision_id)
}

pub(super) fn code_artifact_body_bytes(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Vec<u8>> {
    let Some(raw) = store.entities.get(rtxn, revision_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(Error::InvalidCodeArtifactBody(
            "revision_id must be a CODE_ARTIFACT entity",
        ));
    }
    decode_code_artifact_body(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?,
    )?;
    Ok(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
}

pub(super) fn require_revision_session(
    revision: &CodeRevision,
    session_id: EntityId,
    context: &'static str,
) -> Result<()> {
    if revision.session_id != session_id {
        return Err(Error::InvalidCodeArtifactBody(context));
    }
    Ok(())
}

pub(super) fn require_code_revision_ancestor(
    store: &Store,
    rtxn: &RoTxn<'_>,
    parent_revision_id: &EntityId,
    ancestor_revision_id: &EntityId,
) -> Result<()> {
    let mut cursor = *parent_revision_id;
    let mut visited = HashSet::new();

    for _ in 0..MAX_ANCESTOR_DEPTH {
        if cursor == *ancestor_revision_id {
            return Ok(());
        }
        if !visited.insert(cursor) {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision parent chain contains a cycle",
            ));
        }
        let revision = require_known_code_revision(store, rtxn, &cursor)?;
        let Some(parent_id) = revision.parent_revision_id else {
            break;
        };
        cursor = parent_id;
    }

    if visited.len() >= MAX_ANCESTOR_DEPTH {
        return Err(Error::IndexOverflow("code_revision_parent_chain"));
    }
    Err(Error::InvalidCodeArtifactBody(
        "reverted_to_revision_id must be an ancestor of parent_revision_id",
    ))
}

pub(super) fn require_entity_type(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    expected_type: u8,
    context: &'static str,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != expected_type {
        return Err(Error::InvalidCodeArtifactBody(context));
    }
    Ok(())
}
