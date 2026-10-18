//! Dependency scheduling for the owning expression-preference archive adapter.
//! FIX 3678: each history is kept in the import's row index by its mapped
//! subject, predicate and native order; one history, a codec unit, is read
//! back whole only to check or restore it.
use std::io::{Read, Seek};

use super::archive_index::{
    FLAG_EXPRESSION, IndexedArchive, QUEUE_EXPRESSION, Tag, id_at, ready_key,
};
use super::document_import::parse_id;
use super::{ArchiveRecordKind, ExportEdge, ExportEntity};
use crate::claim::{
    ArchivedExpressionPreference, ClaimSubject, ExpressionPreferenceArchive, decode_claim_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::ENTITY_ID_LEN;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// A history key's tail: learned-at and id.
const ROW_TAIL_LEN: usize = 8 + ENTITY_ID_LEN;

pub(super) fn is_expression(row: &ExportEntity) -> bool {
    row.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && row
            .body
            .to_bytes()
            .ok()
            .and_then(|bytes| decode_claim_body(&bytes, false).ok())
            .is_some_and(|body| crate::claim::is_expression_preference_predicate(&body.predicate))
}

/// One expression row as its history holds it.
fn archived_row(
    archive: &IndexedArchive<'_, impl Read + Seek>,
    row: &ExportEntity,
) -> Result<ArchivedExpressionPreference> {
    let body = decode_claim_body(&row.body.to_bytes()?, false)?;
    let ClaimSubject::Entity(original_subject) = body.subject else {
        return Err(invalid("expression subject is not an entity"));
    };
    let subject = super::provenance_import::mapped(&archive.index, original_subject)?;
    Ok(ArchivedExpressionPreference {
        id: parse_id(&row.id)?,
        body,
        subject,
        occurred: TimeRange {
            start: row.occurred_start,
            end: row.occurred_end,
        },
        learned_at: row.learned_at,
    })
}

/// The history `group` (mapped subject, predicate and NUL) names, read back
/// from the row index in native order.
fn history(
    archive: &IndexedArchive<'_, impl Read + Seek>,
    group: &[u8],
) -> Result<ExpressionPreferenceArchive> {
    let mut rows = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, _)) = archive.index.next(Tag::History, group, after.as_deref())? {
        let id = id_at(&key, key.len() - ENTITY_ID_LEN)?;
        let (_, row) = archive
            .entity(&id)?
            .ok_or(Error::InvariantViolation("expression import lost a row"))?;
        rows.push(archived_row(archive, &row)?);
        after = Some(key);
    }
    ExpressionPreferenceArchive::new(rows)
}

/// Groups every expression row into its history, checks each history and the
/// supersedes edges it implies, and queues each under its first row.
pub(super) fn index_expressions<R: Read + Seek>(archive: &mut IndexedArchive<'_, R>) -> Result<()> {
    let claim = crate::registry::ENTITY_TYPE_CLAIM;
    let mut after = None;
    while let Some(id) = archive.next_of_type(claim, after.as_ref())? {
        after = Some(id);
        let Some((at, row)) = archive.entity(&id)? else {
            continue;
        };
        if !at.has(FLAG_EXPRESSION) {
            continue;
        }
        let archived = archived_row(archive, &row)?;
        let mut key = archived.subject.as_bytes().to_vec();
        key.extend_from_slice(archived.body.predicate.as_bytes());
        key.push(0);
        key.extend_from_slice(&row.learned_at.to_be_bytes());
        key.extend_from_slice(id.as_bytes());
        archive.index.put(Tag::History, &key, &[])?;
    }
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, _)) = archive.index.next(Tag::History, &[], after.as_deref())? {
        let group = key[..key.len() - ROW_TAIL_LEN].to_vec();
        let history = history(archive, &group)?;
        let first = history
            .ids()
            .next()
            .ok_or_else(|| invalid("empty history"))?;
        for id in history.ids() {
            archive.index.put(Tag::Waiting, id.as_bytes(), &[])?;
        }
        for (new, old, at) in history.supersessions() {
            let mut pair = new.as_bytes().to_vec();
            pair.extend_from_slice(old.as_bytes());
            archive
                .index
                .put(Tag::Supersedes, &pair, &at.to_be_bytes())?;
        }
        archive
            .index
            .put(Tag::HistoryPending, first.as_bytes(), &group)?;
        // The next group starts past every key under this one: its closing
        // NUL raised by one.
        let mut past = group;
        if let Some(end) = past.last_mut() {
            *end = 1;
        }
        after = Some(past);
    }
    // A missing edge is missing history, not permission to invent a link.
    // Cross-family, reversed, branching or externally targeted links refuse.
    let mut edges = archive.spool.rows(ArchiveRecordKind::Edge);
    while let Some((_, edge)) = edges.next_parsed::<ExportEdge>(&archive.spool)? {
        if edge.kind != EdgeKind::Supersedes as u8 {
            continue;
        }
        let source = parse_id(&edge.source)?;
        let target = parse_id(&edge.target)?;
        if !archive
            .entity_at(&source)?
            .is_some_and(|at| at.has(FLAG_EXPRESSION))
            && !archive
                .entity_at(&target)?
                .is_some_and(|at| at.has(FLAG_EXPRESSION))
        {
            continue;
        }
        let mut pair = source.as_bytes().to_vec();
        pair.extend_from_slice(target.as_bytes());
        let at = archive
            .index
            .get(Tag::Supersedes, &pair)?
            .and_then(|at| <[u8; 8]>::try_from(at.as_slice()).ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| invalid("ambiguous supersedes edge"))?;
        archive.index.remove(Tag::Supersedes, &pair)?;
        if edge.created_at != at
            || Some(edge.weight) != EdgeKind::Supersedes.default_weight()
            || edge.vad.is_some_and(|vad| vad != [0.0, 0.0, 0.0])
            || edge.provenance.is_some()
        {
            return Err(invalid("supersedes edge differs from native history"));
        }
    }
    if archive.index.any(Tag::Supersedes, &[])? {
        return Err(invalid("supersedes edge missing from history"));
    }
    Ok(())
}

/// Queues each history whose subject no pending row is; whether any.
pub(super) fn mark_ready<R: Read + Seek>(archive: &mut IndexedArchive<'_, R>) -> Result<bool> {
    let mut any = false;
    let mut at: Option<Vec<u8>> = None;
    while let Some((first, group)) = archive
        .index
        .next(Tag::HistoryPending, &[], at.as_deref())?
    {
        if !archive
            .index
            .contains(Tag::Waiting, &group[..ENTITY_ID_LEN])?
        {
            archive.index.put(
                Tag::Ready,
                &ready_key(QUEUE_EXPRESSION, &id_at(&first, 0)?),
                &[],
            )?;
            any = true;
        }
        at = Some(first);
    }
    Ok(any)
}

/// Restores the history queued under `id`; the ids it inserted and the rows
/// already here.
pub(super) fn restore<R: Read + Seek>(
    id: EntityId,
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &WriteActor,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<(Vec<EntityId>, usize)> {
    let group = archive
        .index
        .get(Tag::HistoryPending, id.as_bytes())?
        .ok_or(Error::InvariantViolation(
            "expression import queue lost history",
        ))?;
    let history = history(archive, &group)?;
    let (inserted, unchanged) = history.restore_in_txn(vault, txn, actor)?;
    archive.index.remove(Tag::HistoryPending, id.as_bytes())?;
    for id in history.ids() {
        archive.index.remove(Tag::Waiting, id.as_bytes())?;
    }
    let inserted_ids = if inserted == 0 {
        Vec::new()
    } else {
        history.ids().collect()
    };
    Ok((inserted_ids, unchanged))
}

/// Resolve the HOST-SUPPLIED actor before importing anything. An archive row
/// with the same id cannot create the local actor that authorizes this request.
pub(super) fn validate_local_actor(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &WriteActor,
) -> Result<()> {
    if vault
        .store
        .off_record_sessions
        .contains_entity(&actor.entity_ref())?
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor.entity_ref())?.is_live()
    {
        return Err(Error::EntityNotFound);
    }
    let raw = vault
        .get_raw_in(txn, &actor.entity_ref())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("import actor header"))?;
    crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())?;
    if vault.entity_lifecycle_state_in_txn(txn, &actor.entity_ref())?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(invalid("import actor is not locally active"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("expression preference import: {reason}"))
}
