//! Shared project-hub edge admission and final graph invariant.
//! The project body owns parent links; no generic edge door may invent or
//! retire them. The same check runs after batch materialization so an edge
//! staged before its endpoint type is known cannot escape validation.

use super::{HUB_MEMBERSHIP_WEIGHT, ProjectRecord, is_project_entity};
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::ManifestDbs;
use heed::RoTxn;
use std::collections::BTreeSet;

fn invalid() -> Error {
    RecordError::InvalidProjectBody("project hub edge violates its parent or claim boundary").into()
}

fn entity_type(store: &impl ManifestDbs, txn: &RoTxn<'_>, id: EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("project edge endpoint header"))?;
    Ok((raw.len() > ENTITY_METADATA_HEADER_LEN).then_some(header.entity_type))
}

fn body(store: &impl ManifestDbs, txn: &RoTxn<'_>, id: EntityId) -> Result<ProjectRecord> {
    let raw = store
        .entities()
        .get(txn, id.as_bytes())?
        .ok_or(Error::CorruptedIndex("project edge source missing"))?;
    rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("project edge source body"))
}

/// Only the project rule claim is about the hub itself. All other CLAIM
/// links remain outside the collection graph; scope_project alone is not a
/// permit to attach a CLAIM to a project entity.
fn leader_chat_rule_about_project(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    claim_id: EntityId,
    project: EntityId,
    kind: EdgeKind,
) -> Result<bool> {
    if kind != EdgeKind::ClaimOf || entity_type(store, txn, claim_id)? != Some(ENTITY_TYPE_CLAIM) {
        return Ok(false);
    }
    let raw = store
        .entities()
        .get(txn, claim_id.as_bytes())?
        .ok_or_else(invalid)?;
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(
        body.predicate == super::leader_chat::LEADER_CHAT_RULE_PREDICATE
            && body.subject == crate::claim::ClaimSubject::Entity(project)
            && body.scope_project == project
            && matches!(body.value, rmpv::Value::Boolean(_)),
    )
}

/// Applies to public puts, replay puts and the session overlay's paired edge
/// writer. A parent link has one legal target and one pinned stored weight;
/// other `belongs_to` relations (including project-to-ORG) keep their kind.
pub(crate) fn validate_project_edge_put(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
) -> Result<()> {
    let source_project = is_project_entity(store, txn, src)?;
    let target_project = is_project_entity(store, txn, tgt)?;
    // No provisional hub link to an absent endpoint: it could later become
    // a CLAIM. Sync defers such rows before reaching this writer.
    let admitted_goal = target_project
        && kind == EdgeKind::ClaimOf
        && entity_type(store, txn, src)? == Some(ENTITY_TYPE_CLAIM)
        && super::admitted_claim_of_project(store, txn, src, tgt)?;
    if (source_project
        && matches!(
            entity_type(store, txn, tgt)?,
            None | Some(ENTITY_TYPE_CLAIM)
        ))
        || (target_project
            && (entity_type(store, txn, src)?.is_none()
                || (entity_type(store, txn, src)? == Some(ENTITY_TYPE_CLAIM)
                    && !leader_chat_rule_about_project(store, txn, src, tgt, kind)?))
            && !admitted_goal)
    {
        return Err(invalid());
    }
    if source_project && target_project && kind == EdgeKind::BelongsTo {
        let parent = tgt.to_hex();
        if src == tgt
            || !body(store, txn, src)?.parents.contains(&parent)
            || weight != HUB_MEMBERSHIP_WEIGHT
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// The public direct `port_edge_delete` door does not run the batch projector.
/// A combined body update + edge delete remains legal through the batch path,
/// whose final-state validation runs after the projector.
pub(crate) fn validate_project_edge_delete(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    if kind == EdgeKind::BelongsTo
        && is_project_entity(store, txn, src)?
        && is_project_entity(store, txn, tgt)?
        && body(store, txn, src)?.parents.contains(&tgt.to_hex())
    {
        return Err(invalid());
    }
    Ok(())
}

/// Validate the FINAL rows of a transaction, not the intermediate op order.
/// Check both directions of every touched PROJECT or CLAIM, including edges
/// written before the endpoint arrived, and require exact parent adjacency.
pub(crate) fn validate_project_graph(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    touched: &BTreeSet<EntityId>,
) -> Result<()> {
    for id in touched {
        let is_project = is_project_entity(store, txn, *id)?;
        if !is_project && entity_type(store, txn, *id)? != Some(ENTITY_TYPE_CLAIM) {
            continue;
        }
        let mut parents = BTreeSet::new();
        for (db, reverse) in [(store.edges_out(), false), (store.edges_in(), true)] {
            for row in db.prefix_iter(txn, id.as_bytes())? {
                let (key, value) = row?;
                let edge = parse_strict_edge_record(&key, &value)?;
                let (src, tgt) = if reverse {
                    (edge.target, edge.source)
                } else {
                    (edge.source, edge.target)
                };
                validate_project_edge_put(store, txn, src, edge.kind, tgt, edge.decoded.weight)?;
                if is_project
                    && !reverse
                    && edge.kind == EdgeKind::BelongsTo
                    && is_project_entity(store, txn, tgt)?
                {
                    parents.insert(tgt.to_hex());
                }
            }
        }
        if is_project && parents != body(store, txn, *id)?.parents.into_iter().collect() {
            return Err(invalid());
        }
    }
    Ok(())
}
