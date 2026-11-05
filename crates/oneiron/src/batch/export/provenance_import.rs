//! Ordered archive restore through MODEL and edge-provenance owning doors.
//! FIX 3678: the MODEL map and each provenance cohort live in the import's row
//! index, keyed by subject edge and native order; one cohort, one edge's
//! history, is read back whole only to restore it.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use super::archive_index::{
    ArchiveIndex, FLAG_PROVENANCE, IndexedArchive, Loc, QUEUE_PROVENANCE, Tag, edge_key, id_at,
    id_list, ids_of, ready_key,
};
use super::document_import::{import_edge, matches_row, parse_id, stamp_archived_birth};
use super::{ArchiveRecordKind, ExportEdge, ExportEntity};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::ENTITY_ID_LEN;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject, decode_claim_body};
use crate::{
    Vault,
    entity_id::EntityId,
    error::{Error, Result},
    serialize::ExportBody,
};

/// A cohort key's subject edge: source, kind and target.
const EDGE_KEY_LEN: usize = 2 * ENTITY_ID_LEN + 1;

pub(super) fn is_provenance(row: &ExportEntity) -> bool {
    row.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && row
            .body
            .to_bytes()
            .ok()
            .and_then(|bytes| decode_claim_body(&bytes, true).ok())
            .is_some_and(|body| {
                body.predicate == crate::write_envelope::provenance::PREDICATE_EDGE_PROVENANCE
            })
}
pub(super) struct ModelImports {
    pub(super) inserted: usize,
    pub(super) unchanged: usize,
}
/// Each archived MODEL row, in id order, through its owning door; the
/// archive id → local id map is kept in the row index.
pub(super) fn restore_models<R: Read + Seek>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<ModelImports> {
    for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        crate::registry::ENTITY_TYPE_MODEL,
        None,
    )? {
        archive.index.put(Tag::LocalModel, row?.as_bytes(), &[])?;
    }
    let mut inserted = 0;
    let mut unchanged = 0;
    let model = crate::registry::ENTITY_TYPE_MODEL;
    let mut after = None;
    while let Some(id) = archive.next_of_type(model, after.as_ref())? {
        after = Some(id);
        let (_, row) = archive
            .entity(&id)?
            .ok_or(Error::InvariantViolation("archive index lost a MODEL"))?;
        let bytes = row.body.to_bytes()?;
        let (name, version) =
            crate::write_envelope::provenance::actor_substrate::decode_model_entity_body(&bytes)?;
        let local = vault.ensure_model_substrate_in_txn(txn, &name, &version, row.learned_at)?;
        if archive
            .index
            .insert(Tag::LocalModel, local.as_bytes(), &[])?
        {
            inserted += 1;
        } else {
            unchanged += 1;
        }
        archive
            .index
            .put(Tag::Model, parse_id(&row.id)?.as_bytes(), local.as_bytes())?;
    }
    Ok(ModelImports {
        inserted,
        unchanged,
    })
}
/// `id` as this vault holds it: an archived MODEL's local id, else itself.
pub(super) fn mapped(index: &ArchiveIndex<'_>, id: EntityId) -> Result<EntityId> {
    match index.get(Tag::Model, id.as_bytes())? {
        Some(local) => id_at(&local, 0),
        None => Ok(id),
    }
}
pub(super) fn mapped_edge(edge: &ExportEdge, index: &ArchiveIndex<'_>) -> Result<ExportEdge> {
    let mut edge = edge.clone();
    let source = parse_id(&edge.source)?;
    let mapped_source = mapped(index, source)?;
    if mapped_source != source {
        edge.source = mapped_source.to_hex();
    }
    let target = parse_id(&edge.target)?;
    let mapped_target = mapped(index, target)?;
    if mapped_target != target {
        edge.target = mapped_target.to_hex();
    }
    Ok(edge)
}
/// Keys each edge by its MODEL-mapped endpoints; the first in archive order
/// holds a key, as a search of the mapped edges in order finds it.
pub(super) fn index_mapped_edges<R: Read + Seek>(
    archive: &mut IndexedArchive<'_, R>,
) -> Result<()> {
    let mut edges = archive.spool.rows(ArchiveRecordKind::Edge);
    while let Some((loc, edge)) = edges.next_parsed::<ExportEdge>(&archive.spool)? {
        let edge = mapped_edge(&edge, &archive.index)?;
        let key = edge_key(
            &parse_id(&edge.source)?,
            edge.kind,
            &parse_id(&edge.target)?,
        );
        archive.index.insert(Tag::MappedEdge, &key, &loc.encode())?;
    }
    Ok(())
}
/// One provenance row's body as it is restored here, and the ids it waits on.
fn provenance_body(
    index: &ArchiveIndex<'_>,
    row: &ExportEntity,
) -> Result<(ClaimBody, Vec<EntityId>)> {
    let mut body = decode_claim_body(&row.body.to_bytes()?, true)?;
    if let ClaimSubject::Edge { source, target, .. } = &mut body.subject {
        *source = mapped(index, *source)?;
        *target = mapped(index, *target)?;
    }
    let mut models = BTreeMap::new();
    if let Some(substrate) =
        crate::write_envelope::provenance::codec::decode_edge_provenance_body(&body.value)
            .ok()
            .and_then(|record| record.substrate_ref)
        && let Some(local) = index.get(Tag::Model, substrate.as_bytes())?
    {
        models.insert(substrate, id_at(&local, 0)?);
    }
    let body = crate::provenance::archived_provenance_body(&body, &models)?;
    let ClaimSubject::Edge { source, target, .. } = body.subject else {
        return Err(invalid("provenance subject must be an edge"));
    };
    let record =
        crate::write_envelope::provenance::codec::decode_edge_provenance_body(&body.value)?;
    let waits = [source, target, record.actor_entity_ref]
        .into_iter()
        .chain(record.substrate_ref)
        .collect();
    Ok((body, waits))
}
/// Keys each edge-provenance row by its subject edge, learned-at and id, so
/// a cohort reads back in native order, and queues each cohort under its
/// first row.
pub(super) fn index_provenance<R: Read + Seek>(archive: &mut IndexedArchive<'_, R>) -> Result<()> {
    let claim = crate::registry::ENTITY_TYPE_CLAIM;
    let mut after = None;
    while let Some(id) = archive.next_of_type(claim, after.as_ref())? {
        after = Some(id);
        let Some((at, row)) = archive.entity(&id)? else {
            continue;
        };
        if !at.has(FLAG_PROVENANCE) {
            continue;
        }
        let (body, waits) = provenance_body(&archive.index, &row)?;
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = body.subject
        else {
            return Err(invalid("provenance subject must be an edge"));
        };
        let mut key = edge_key(&source, kind as u8, &target);
        key.extend_from_slice(&row.learned_at.to_be_bytes());
        key.extend_from_slice(id.as_bytes());
        archive.index.put(Tag::Cohort, &key, &id_list(&waits))?;
        archive.index.put(Tag::Waiting, id.as_bytes(), &[])?;
    }
    let mut after: Option<Vec<u8>> = None;
    let mut cohort: Option<Vec<u8>> = None;
    while let Some((key, _)) = archive.index.next(Tag::Cohort, &[], after.as_deref())? {
        let edge = key[..EDGE_KEY_LEN].to_vec();
        if cohort.as_deref() != Some(edge.as_slice()) {
            let first = id_at(&key, EDGE_KEY_LEN + 8)?;
            archive
                .index
                .put(Tag::CohortPending, first.as_bytes(), &edge)?;
            cohort = Some(edge);
        }
        after = Some(key);
    }
    Ok(())
}
/// Queues each cohort none of whose rows waits on a pending id; whether any.
pub(super) fn mark_ready<R: Read + Seek>(archive: &mut IndexedArchive<'_, R>) -> Result<bool> {
    let mut any = false;
    let mut at: Option<Vec<u8>> = None;
    while let Some((first, edge)) = archive.index.next(Tag::CohortPending, &[], at.as_deref())? {
        let mut waiting = false;
        let mut row: Option<Vec<u8>> = None;
        while !waiting
            && let Some((key, waits)) = archive.index.next(Tag::Cohort, &edge, row.as_deref())?
        {
            for id in ids_of(&waits)? {
                waiting |= archive.index.contains(Tag::Waiting, id.as_bytes())?;
            }
            row = Some(key);
        }
        if !waiting {
            archive.index.put(
                Tag::Ready,
                &ready_key(QUEUE_PROVENANCE, &id_at(&first, 0)?),
                &[],
            )?;
            any = true;
        }
        at = Some(first);
    }
    Ok(any)
}
/// Restores the cohort queued under `key`, its subject edge first; the ids
/// it inserted and the rows already here.
pub(super) fn restore<R: Read + Seek>(
    key: EntityId,
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<(BTreeSet<EntityId>, usize)> {
    let subject = archive
        .index
        .get(Tag::CohortPending, key.as_bytes())?
        .ok_or(Error::InvariantViolation(
            "provenance import queue lost cohort",
        ))?;
    let mut rows = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    while let Some((row_key, _)) = archive
        .index
        .next(Tag::Cohort, &subject, after.as_deref())?
    {
        let id = id_at(&row_key, EDGE_KEY_LEN + 8)?;
        let (_, row) = archive.entity(&id)?.ok_or(Error::InvariantViolation(
            "provenance import queue lost a row",
        ))?;
        let (body, _) = provenance_body(&archive.index, &row)?;
        rows.push((row, id, body));
        after = Some(row_key);
    }
    // Blind-review P1c (REVIEW-4389): an authored cut (FIX 7755) keeps its
    // active provenance Claim while the subject edge is gone, so a
    // whole-vault export carries the wrapper without its edge. When the edge
    // row is absent but both endpoints survive as archived entities, the
    // cohort restores without staging — and never recreates — the deleted
    // link. Any other absence stays a fail-closed archive defect.
    let cut = match archive.index.get(Tag::MappedEdge, &subject)? {
        Some(loc) => {
            let edge = mapped_edge(
                &archive.spool.parse::<ExportEdge>(Loc::decode(&loc)?)?,
                &archive.index,
            )?;
            stage_edge(vault, txn, &edge, &archive.index)?;
            false
        }
        None => {
            let source = id_at(&subject, 0)?;
            let target = id_at(&subject, ENTITY_ID_LEN + 1)?;
            if archive.entity(&source)?.is_none() || archive.entity(&target)?.is_none() {
                return Err(invalid("provenance subject edge missing from archive"));
            }
            true
        }
    };
    let new_ids = rows
        .iter()
        .filter_map(|(_, id, _)| {
            match crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, id) {
                Ok(false) => Some(Ok(*id)),
                Ok(true) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    // Typed puts can regenerate a cut link before or during this cohort.
    // Preserve an existing link on a pre-existing source, not one minted
    // by this import's earlier entity pass.
    let cut_subject = if cut {
        if subject.len() != EDGE_KEY_LEN {
            return Err(invalid("archive cohort subject is not an edge"));
        }
        let kind = crate::edge::EdgeKind::try_from_u8(subject[ENTITY_ID_LEN])
            .ok_or_else(|| invalid("archive cohort subject is not an edge"))?;
        Some((
            id_at(&subject, 0)?,
            kind,
            id_at(&subject, ENTITY_ID_LEN + 1)?,
        ))
    } else {
        None
    };
    let preserve_subject_edge = match cut_subject {
        Some((source, kind, target)) => {
            !archive.index.contains(Tag::Inserted, source.as_bytes())?
                && crate::ports::EdgeStoreRead::port_edge_get(
                    &vault.store,
                    txn,
                    &source,
                    kind,
                    &target,
                )?
                .is_some()
        }
        None => false,
    };
    let (inserted, unchanged) = restore_cohort(vault, txn, &rows, cut)?;
    if let Some((source, kind, target)) = cut_subject
        && !preserve_subject_edge
        && crate::ports::EdgeStoreRead::port_edge_get(&vault.store, txn, &source, kind, &target)?
            .is_some()
    {
        vault
            .batch_in()
            .delete_edge(&source, kind, &target)
            .apply(txn)?;
    }
    if inserted != new_ids.len() {
        return Err(Error::InvariantViolation("provenance import count drift"));
    }
    // FIX 1178: each landed row's archived birth, stamped once its final
    // body compares exact.
    for (_, id, _) in &rows {
        stamp_archived_birth(vault, txn, archive, id)?;
    }
    archive.index.remove(Tag::CohortPending, key.as_bytes())?;
    for (_, id, _) in &rows {
        archive.index.remove(Tag::Waiting, id.as_bytes())?;
    }
    Ok((new_ids, unchanged))
}
fn restore_cohort(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    rows: &[(ExportEntity, EntityId, ClaimBody)],
    cut: bool,
) -> Result<(usize, usize)> {
    let mut inserted = 0;
    let mut unchanged = 0;
    // The last row this restore inserted: on a learned-at tie the implicit
    // strictly-older closure cannot close it, so a successor names it as its
    // explicit prior when the archive holds it Superseded (FIX 9594).
    // REVIEW-4378 P1: IDs order nothing, so a tie may list the closer
    // before the Superseded row it closes. Restore every tied Superseded
    // row before its tie-mates (stable) so the closer still names it.
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&i| {
        (
            rows[i].0.learned_at,
            if rows[i].2.lifecycle == ClaimLifecycleStatus::Superseded {
                0
            } else {
                1
            },
        )
    });
    let mut previous: Option<(EntityId, u64, ClaimLifecycleStatus)> = None;
    for &i in &order {
        let (row, id, body) = &rows[i];
        let expected = ExportBody::from_bytes(
            &crate::write_envelope::claim_body::encode_claim_body(body)?,
            row.entity_type,
        );
        if let Some(existing) =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
        {
            if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live()
                || !matches_row(row, &existing, &expected)
            {
                return Err(invalid("archive provenance ID collision"));
            }
            unchanged += 1;
            // Blind-review P1 (REVIEW-4378-kimi): an existing row breaks the
            // tied-prior chain when the tracked prior is already closed —
            // re-naming it fails ProvenanceClaimAlreadyClosed.
            // Blind-review P1 (REVIEW-4378.md): a newly inserted still-live
            // tied prior survives the unchanged row so a later missing
            // tie-mate closes it; otherwise the final exact comparison
            // aborts a valid partially present cohort.
            let prior_live = previous
                .map(|(prior, _, _)| {
                    crate::vault::live_entity_row_in_txn(&vault.store, txn, &prior)
                        .map(|row| row.is_live())
                })
                .transpose()?
                .unwrap_or(false);
            // Blind-review P1 rounds 5-6 (REVIEW-4378.md + REVIEW-4378-kimi.md):
            // the archived closer itself is already present, so no later
            // missing row will close the newly restored tied prior. Close it
            // through the owner door now (edge restamped from the surviving
            // cohort inside), then break the chain as round 3 did; anything
            // else keeps round-4 behavior. A tied Retracted row closes the
            // prior the same way: retraction never reopens it.
            let closer_present = match previous {
                Some((_, prior_learned_at, lifecycle))
                    if prior_learned_at == row.learned_at
                        && lifecycle == ClaimLifecycleStatus::Superseded
                        && matches!(
                            body.lifecycle,
                            ClaimLifecycleStatus::Active | ClaimLifecycleStatus::Retracted
                        ) =>
                {
                    true
                }
                _ => false,
            };
            if closer_present && prior_live {
                if let Some((prior, _, _)) = previous {
                    vault.close_restored_tied_prior_in_txn(txn, &prior, id, row.learned_at, cut)?;
                }
                previous = None;
            } else if !prior_live {
                previous = None;
            }
            continue;
        }
        let explicit_prior = previous.and_then(|(prior, prior_learned_at, prior_lifecycle)| {
            (prior_learned_at == row.learned_at
                && prior_lifecycle == ClaimLifecycleStatus::Superseded)
                .then_some(prior)
        });
        vault.restore_archived_provenance_in_txn(
            txn,
            id,
            body,
            crate::temporal::TimeRange {
                start: row.occurred_start,
                end: row.occurred_end,
            },
            row.learned_at,
            explicit_prior.as_ref(),
            cut,
        )?;
        inserted += 1;
        previous = Some((*id, row.learned_at, body.lifecycle));
    }
    // A superseded row is never silently resurrected if its closing history
    // was absent or ambiguous. Every final lifecycle must reproduce exactly.
    for (row, id, body) in rows {
        let actual = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let expected = ExportBody::from_bytes(
            &crate::write_envelope::claim_body::encode_claim_body(body)?,
            row.entity_type,
        );
        if !matches_row(row, &actual, &expected) {
            return Err(invalid("archive provenance lifecycle not reconstructed"));
        }
    }
    Ok((inserted, unchanged))
}
pub(super) fn stage_edge(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    edge: &ExportEdge,
    inserted: &ArchiveIndex<'_>,
) -> Result<()> {
    // A link its pair does not prove is left out here and counted once, by
    // the import's last edge pass (FIX 6206).
    if edge.provenance.is_none() {
        import_edge(vault, txn, edge, inserted)?;
        return Ok(());
    }
    let source = parse_id(&edge.source)?;
    let target = parse_id(&edge.target)?;
    let kind = crate::edge::EdgeKind::try_from_u8(edge.kind)
        .ok_or_else(|| invalid("archive edge kind"))?;
    if let Some(existing) =
        crate::ports::EdgeStoreRead::port_edge_get(&vault.store, txn, &source, kind, &target)?
    {
        if existing.weight != edge.weight
            || existing.created_at != edge.created_at
            || existing.vad.map(|v| [v.valence, v.arousal, v.dominance]) != edge.vad
        {
            return Err(invalid("archive base edge collision"));
        }
        return Ok(());
    }
    let mut bare = edge.clone();
    bare.provenance = None;
    import_edge(vault, txn, &bare, inserted)?;
    Ok(())
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("provenance import: {reason}"))
}
