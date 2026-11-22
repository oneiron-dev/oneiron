//! The room a record sits in, up the edges and claim subjects of its
//! ancestors (rule 5), and every room a revision sits in (FIX 5861), on base
//! and through a session's composed view (FIX 6487): the walks the audience
//! predicate places a record by, split from their parent, which re-exports
//! them.
use super::*;

pub(crate) fn room_for_record_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Option<EntityId>> {
    room_for_revision_in(vault, txn, record, None)
}

/// [`room_for_record_in`] starting from `revision` of `record` when given,
/// so a served older revision is placed by its own subject. Every ancestor
/// is read, however many (rule 5): past its threshold row the walk asks
/// whether everything is okay, counted on every way out, and a record
/// already seen ends a cycle.
pub(super) fn room_for_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    revision: Option<&[u8]>,
) -> Result<Option<EntityId>> {
    room_for_revision_over(vault, &vault.store, txn, record, revision, None)
}

/// [`room_for_revision_in`] with each ancestor and edge read through `dbs`,
/// and, with `stretch`, a room stretch's shell taken as the room it maps to
/// ([`crate::off_record::StretchRoom::room_of`]).
pub(super) fn room_for_revision_over(
    vault: &Vault,
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    revision: Option<&[u8]>,
    stretch: Option<crate::off_record::StretchRoom>,
) -> Result<Option<EntityId>> {
    let mut walk = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::RoomAncestryRecords,
        record.as_bytes(),
    )?;
    let mut seen = BTreeSet::new();
    let room = room_walk_in(dbs, txn, record, revision, &mut seen, stretch);
    walk.rows(seen.len());
    walk.defer(&vault.store);
    room
}

/// The walk [`room_for_revision_over`] counts, each record it reaches in
/// `seen`.
fn room_walk_in(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    revision: Option<&[u8]>,
    seen: &mut BTreeSet<EntityId>,
    stretch: Option<crate::off_record::StretchRoom>,
) -> Result<Option<EntityId>> {
    let mut pending = vec![record];
    let mut room = None;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let raw = match revision.filter(|_| id == record) {
            Some(raw) => raw.to_vec(),
            None => crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)?
                .ok_or(Error::EntityNotFound)?,
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("room ancestor"))?;
        if h.entity_type == ENTITY_TYPE_CONVERSATION {
            let id = stretch.map_or(id, |stretch| stretch.room_of(id));
            if room.is_some_and(|r| r != id) {
                return Err(state("ambiguous room"));
            }
            room = Some(id);
            continue;
        }
        for kind in [
            EdgeKind::ChildOf,
            EdgeKind::PartOf,
            EdgeKind::Parent,
            EdgeKind::RepliesTo,
            EdgeKind::SpawnedBy,
            EdgeKind::BelongsTo,
        ] {
            pending.extend(counted_edge_ids(dbs, txn, &id, kind, false)?);
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if let crate::claim::ClaimSubject::Entity(subject) = body.subject {
                pending.push(subject);
            }
        }
    }
    Ok(room)
}

/// Every room the revision `raw` of `record` sits in (FIX 5861), up the
/// edges and claim subjects [`room_for_revision_in`] walks: an ancestor that
/// is gone is passed over, never a refusal, and a record that reaches two
/// rooms sits in both. Each ancestor and edge is read on base and through
/// `dbs`, a session's composed view (FIX 6487).
pub(super) fn rooms_of_revision_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    raw: &[u8],
) -> Result<BTreeSet<EntityId>> {
    let union = crate::store::ManifestDbs::is_union(dbs);
    let mut pending = vec![(record, raw.to_vec())];
    let mut seen = BTreeSet::from([record]);
    let mut rooms = BTreeSet::new();
    while let Some((id, bytes)) = pending.pop() {
        let Some(h) = EntityMetadataHeader::parse(&bytes) else {
            continue;
        };
        if h.entity_type == ENTITY_TYPE_CONVERSATION {
            rooms.insert(id);
            continue;
        }
        let mut next = Vec::new();
        for kind in [
            EdgeKind::ChildOf,
            EdgeKind::PartOf,
            EdgeKind::Parent,
            EdgeKind::RepliesTo,
            EdgeKind::SpawnedBy,
            EdgeKind::BelongsTo,
        ] {
            next.extend(counted_edge_ids(&vault.store, txn, &id, kind, false)?);
            if union {
                next.extend(counted_edge_ids(dbs, txn, &id, kind, false)?);
            }
        }
        if h.entity_type == ENTITY_TYPE_CLAIM
            && let Some(body) = bytes.get(ENTITY_METADATA_HEADER_LEN..)
            && let Ok(claim) = crate::claim::decode_claim_body(body, true)
            && let crate::claim::ClaimSubject::Entity(subject) = claim.subject
        {
            next.push(subject);
        }
        for ancestor in next {
            if seen.insert(ancestor) {
                for bytes in base_and_view_rows_in(vault, dbs, txn, ancestor)? {
                    pending.push((ancestor, bytes));
                }
            }
        }
    }
    Ok(rooms)
}

/// Whether the revision `raw` of `record` sits under `conversation`, up the
/// edges and claim subjects [`rooms_of_revision_in`] walks, on base and
/// through `dbs`: how a read over a room stretch tells a row the stretch
/// staged under its shell.
pub(crate) fn hangs_under_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    raw: &[u8],
    conversation: EntityId,
) -> Result<bool> {
    Ok(rooms_of_revision_in(vault, dbs, txn, record, raw)?.contains(&conversation))
}

/// The rows `id` holds on base and, when `dbs` composes a session's view
/// over it, in that view, each once (FIX 6487): an overlay row is read
/// beside the base one, never in its place. None for a record neither holds.
pub(super) fn base_and_view_rows_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Vec<Vec<u8>>> {
    let mut rows = Vec::new();
    if let Some(base) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? {
        rows.push(base);
    }
    if crate::store::ManifestDbs::is_union(dbs)
        && let Some(view) = crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &id)?
        && !rows.contains(&view)
    {
        rows.push(view);
    }
    Ok(rows)
}
