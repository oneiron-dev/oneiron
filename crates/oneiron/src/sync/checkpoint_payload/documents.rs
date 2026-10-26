//! The native entity-document carriers grouped with their document (FIX
//! 10932): a pending text edit (`qd:e:`) and a cached item's document
//! (`ri:d:`) are Loro bytes of their entity's document, whose stamps and
//! birth only that document's whole history shows. One row alone stays
//! under the vault-wide seal ([`super::rows`]); here each entity's rows of
//! one family form one group and split through the entity document's own
//! Loro seam (`crate::entity_doc::checkpoint`).
//!
//! A group is its basis, then its native rows in replay order. The basis is
//! the full snapshot and the pending rows of the slot the entity's text
//! plane appends to, read from the capture's one view and taken only as the
//! image takes them; a cached item's STATE whose payload is itself a full
//! history is its own basis. The basis is context: its parts rest at the
//! group's first native row as fragments, and a restore never writes them.
//! Each native part keeps its frame's sub-tag before its no-one content, its
//! locator naming its entity and sequence. A group's parts are published
//! only once their all-open rebuild gives every native row back; a group
//! with no full basis, or one that does not split or rebuild, publishes
//! nothing and its rows stay as one row alone leaves them.

use std::collections::{BTreeMap, BTreeSet};

use ::loro::{EncodedBlobMode, LoroDoc};
use heed::RoTxn;

use super::rows::{frame, id_after, pair_after};
use super::{CapturedSyncRow, DocumentBasis, SyncAtom, SyncCarrier, SyncPayloadOwners};
use crate::entity_doc::EntityDoc;
use crate::entity_doc::checkpoint::{join_entity_doc_loro, split_entity_doc_loro};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::DocumentSlot;
use crate::side_table::{self, Raw, SYNC_QD_E, SYNC_RESIDENCE_ITEM_DOCUMENT, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::loro::{Atom, OpenedRow, opened_atoms};
use crate::store::checkpoint_payload::rows::{
    ActorPart, OpenedOwnerRows, OwnerRef, RoundTripPolicy, RowDb, RowLocator, RowPart, bad_part,
};
use crate::sync::transport::{document_sub_tags, encode_document};

/// How a group's rows give their history back (Engine R1): the same
/// operations, in containers Loro may encode anew.
const ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// A basis part's path: `basis/{index}` at the group's first native row.
const BASIS: &str = "basis/";

/// A native frame's header: its tag, its entity and its sub-tag.
const HEADER: usize = 18;

const SNAPSHOTS: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_SNAPSHOT);
const UPDATES: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::DOCUMENT_UPDATE);

/// The native family a group's rows are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    /// Pending text edits, `qd:e:{entity}:{seq:08x}`.
    PendingEdit,
    /// A cached item's document, `ri:d:{entity}`.
    ResidenceItem,
}

impl Family {
    fn of(carrier: SyncCarrier) -> Option<Self> {
        match carrier {
            SyncCarrier::PendingEdit => Some(Self::PendingEdit),
            SyncCarrier::ResidenceItem => Some(Self::ResidenceItem),
            _ => None,
        }
    }

    /// The family and entity a native row's key names.
    fn named_by(key: &[u8]) -> Option<(Self, EntityId)> {
        if let Some((id, seq)) = pair_after(key, SYNC_QD_E.prefix) {
            return sequence(seq).then_some((Self::PendingEdit, id));
        }
        id_after(key, SYNC_RESIDENCE_ITEM_DOCUMENT.prefix).map(|id| (Self::ResidenceItem, id))
    }
}

/// Whether `seq` is a sequence as a pending edit's key spells it: eight
/// lowercase hex digits.
fn sequence(seq: &str) -> bool {
    u32::from_str_radix(seq, 16).is_ok_and(|seq_no| format!("{seq_no:08x}") == seq)
}

/// One native row of a group, as captured.
struct Native<'a> {
    index: usize,
    at: RowLocator,
    value: &'a [u8],
    kind: u8,
    payload: &'a [u8],
}

/// A captured row as one of a group's native rows: a pending edit's UPDATE,
/// or a cached item's STATE or UPDATE, each naming the entity its key does.
fn native<'a>(index: usize, row: &CapturedSyncRow<'a>) -> Option<(Family, EntityId, Native<'a>)> {
    let family = Family::of(row.carrier)?;
    let (named, entity) = Family::named_by(row.key)?;
    let frame = frame(row.value)?;
    let kinds: &[u8] = match family {
        Family::PendingEdit => &[document_sub_tags::UPDATE],
        Family::ResidenceItem => &[document_sub_tags::STATE, document_sub_tags::UPDATE],
    };
    if named != family || frame.entity != entity || !kinds.contains(&frame.kind) {
        return None;
    }
    let at = RowLocator::row(RowDb::SyncState, row.key.to_vec());
    let native = Native {
        index,
        at,
        value: row.value,
        kind: frame.kind,
        payload: frame.payload,
    };
    Some((family, entity, native))
}

/// Whether `bytes` is a full Loro history: a snapshot export, never a
/// shallow or state-only one, which reads as a shallow snapshot.
fn full_history(bytes: &[u8]) -> bool {
    LoroDoc::decode_import_blob_meta(bytes, true)
        .is_ok_and(|meta| meta.mode == EncodedBlobMode::Snapshot)
}

/// Whether `snapshot` is `entity`'s by its birth: an entity document's
/// birth names its entity. A text-plane document holds no birth, and its
/// slot names it; one whose birth does not read, the split refuses.
fn born_of(snapshot: &[u8], entity: EntityId) -> bool {
    let doc = EntityDoc::from_snapshot(snapshot).ok();
    doc.is_none_or(|doc| doc.birth().entity == entity.to_hex())
}

/// `entity`'s document basis as the capture's one view `txn` holds it: the
/// snapshot and pending rows (in replay order) of the slot its text plane
/// appends to, each only as the image takes it (`takes`). A basis row the
/// image leaves out leaves no basis.
pub(super) fn read_basis(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    entity: EntityId,
    takes: &dyn Fn(RowDb, &[u8], &[u8]) -> bool,
) -> Result<DocumentBasis> {
    let slot = DocumentSlot::of(entity);
    let Some(snapshot) = SNAPSHOTS.get(dbs, txn, &slot)? else {
        return Ok(DocumentBasis::default());
    };
    let db = RowDb::of(SNAPSHOTS.decl());
    let key = SNAPSHOTS.key_bytes(&slot);
    if !takes(db, key.as_slice(), snapshot.as_slice()) {
        return Ok(DocumentBasis::default());
    }
    let mut pending = Vec::new();
    let prefix = format!("{}:", slot.to_hex());
    for row in UPDATES.iter_raw_from(dbs, txn, prefix.as_bytes())? {
        let (key, value) = row?;
        let mut at = UPDATES.decl().prefix.to_vec();
        at.extend_from_slice(&key);
        if !takes(db, at.as_slice(), value.as_slice()) {
            return Ok(DocumentBasis::default());
        }
        pending.push(value);
    }
    Ok(DocumentBasis {
        snapshot: Some(snapshot),
        pending,
    })
}

/// Groups the native rows of `rows`, entity by entity and family by family,
/// each with its basis; each group's parts go to `emit` once proved.
/// Answers the indexes of the rows grouped.
pub(super) fn project(
    rows: &[CapturedSyncRow<'_>],
    owners: &dyn SyncPayloadOwners,
    basis: &mut dyn FnMut(EntityId) -> Result<DocumentBasis>,
    emit: &mut dyn FnMut(OwnerRef, SyncAtom) -> Result<()>,
) -> Result<BTreeSet<usize>> {
    let mut groups: BTreeMap<(Family, EntityId), Vec<Native<'_>>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        if let Some((family, entity, native)) = native(index, row) {
            groups.entry((family, entity)).or_default().push(native);
        }
    }
    let mut grouped = BTreeSet::new();
    for ((family, entity), mut natives) in groups {
        natives.sort_by(|a, b| a.at.key.cmp(&b.at.key));
        let updates = natives
            .iter()
            .all(|row| row.kind == document_sub_tags::UPDATE);
        let seed = match natives.as_slice() {
            [only] if only.kind == document_sub_tags::STATE => {
                if !full_history(only.payload) || !born_of(only.payload, entity) {
                    continue;
                }
                None
            }
            _ if updates => {
                let found = basis(entity)?;
                match found.snapshot {
                    Some(snapshot) if full_history(&snapshot) && born_of(&snapshot, entity) => {
                        Some((snapshot, found.pending))
                    }
                    _ => continue,
                }
            }
            _ => continue,
        };
        let Some(parts) = split(family, entity, seed.as_ref(), &natives) else {
            continue;
        };
        let owner = OwnerRef::entity(&owners.owner_entity(entity));
        for part in parts {
            emit(owner, part)?;
        }
        grouped.extend(natives.iter().map(|row| row.index));
    }
    Ok(grouped)
}

/// One group's parts, split and proved: its basis parts at its first native
/// row, then each native row's sub-tag and no-one content at its own
/// locator, each actor split out naming its part. `None` when it does not
/// split, or its all-open rebuild does not give every native row back.
fn split(
    family: Family,
    entity: EntityId,
    seed: Option<&(Vec<u8>, Vec<Vec<u8>>)>,
    natives: &[Native<'_>],
) -> Option<Vec<SyncAtom>> {
    let anchor = &natives.first()?.at;
    let mut rows: Vec<&[u8]> = Vec::new();
    if let Some((snapshot, pending)) = seed {
        rows.push(snapshot);
        rows.extend(pending.iter().map(Vec::as_slice));
    }
    let based = rows.len();
    rows.extend(natives.iter().map(|row| row.payload));
    let split = split_entity_doc_loro(&rows, ROUND_TRIP).ok()?;
    if split.len() != rows.len() {
        return None;
    }
    let mut parts = Vec::with_capacity(split.len());
    for (index, row) in split.into_iter().enumerate() {
        let (at, value) = match index.checked_sub(based) {
            None => (anchor.fragment(format!("{BASIS}{index}")), row.content),
            Some(native) => {
                let native = &natives[native];
                let mut value = vec![native.kind];
                value.extend(row.content);
                (native.at.clone(), value)
            }
        };
        let actors = row
            .atoms
            .into_iter()
            .map(|atom| ActorPart {
                actor_entity: atom.actor,
                content_locator: at.clone(),
                field: atom.field,
                bytes: atom.actor.as_bytes().to_vec(),
            })
            .collect();
        parts.push(SyncAtom {
            at,
            value,
            dependencies: Vec::new(),
            actors,
        });
    }
    // The all-open round trip, before any part is published.
    let opened: Vec<(&RowLocator, &[u8], Vec<Atom>)> = parts
        .iter()
        .map(|part| {
            let atoms = part.actors.iter().collect::<Vec<_>>();
            opened_atoms(&atoms).map(|atoms| (&part.at, part.value.as_slice(), atoms))
        })
        .collect::<Result<_>>()
        .ok()?;
    let rebuilt = rebuild(family, entity, &opened, based).ok()?;
    let given_back = rebuilt.len() == natives.len()
        && rebuilt.iter().zip(natives).all(|((at, value), native)| {
            *at == native.at && value.get(..HEADER) == native.value.get(..HEADER)
        });
    given_back.then_some(parts)
}

/// Rebuilds a group's native rows from its parts, `based` basis parts then
/// its native parts, each with the atoms that opened: every part joined in
/// order, each native row's own slice exported and rewrapped in its frame
/// as its sub-tag names it, and checked against its locator.
fn rebuild(
    family: Family,
    entity: EntityId,
    parts: &[(&RowLocator, &[u8], Vec<Atom>)],
    based: usize,
) -> Result<Vec<(RowLocator, Vec<u8>)>> {
    let mut opened = Vec::with_capacity(parts.len());
    let mut kinds = Vec::with_capacity(parts.len().saturating_sub(based));
    for (index, (_, content, atoms)) in parts.iter().enumerate() {
        let content = if index < based {
            *content
        } else {
            let (&kind, content) = content.split_first().ok_or_else(bad_part)?;
            kinds.push(kind);
            content
        };
        opened.push(OpenedRow {
            content,
            atoms: atoms.clone(),
        });
    }
    let joined = join_entity_doc_loro(&opened)?;
    if joined.len() != parts.len() || kinds.is_empty() {
        return Err(bad_part());
    }
    let natives = parts.iter().zip(joined).skip(based).zip(kinds);
    let mut rows = Vec::with_capacity(parts.len() - based);
    for (((at, _, _), slice), kind) in natives {
        let value = encode_document(entity, kind, &slice)
            .into_result()
            .map_err(|_| bad_part())?;
        check(family, at, &value)?;
        rows.push(((*at).clone(), value));
    }
    Ok(rows)
}

/// Refuses a rebuilt native row unless its frame reads as its locator names
/// it: the entity its key names, a pending edit's UPDATE at a sequence key,
/// or a cached item's full-history STATE or UPDATE, its payload the blob its
/// sub-tag says.
fn check(family: Family, at: &RowLocator, value: &[u8]) -> Result<()> {
    let named = Family::named_by(&at.key);
    let frame = frame(value).ok_or_else(bad_part)?;
    let blob = LoroDoc::decode_import_blob_meta(frame.payload, true).map_err(|_| bad_part())?;
    let shaped = match frame.kind {
        document_sub_tags::UPDATE => blob.mode == EncodedBlobMode::Updates,
        document_sub_tags::STATE => {
            family == Family::ResidenceItem && blob.mode == EncodedBlobMode::Snapshot
        }
        _ => false,
    };
    let whole = at.db == RowDb::SyncState && at.path.is_empty();
    if whole && shaped && named == Some((family, frame.entity)) {
        Ok(())
    } else {
        Err(bad_part())
    }
}

/// One group's parts in an opened compartment: its basis parts by index,
/// and its native parts.
#[derive(Default)]
struct OpenedGroup<'o> {
    basis: BTreeMap<usize, &'o RowPart>,
    natives: Vec<&'o RowPart>,
}

/// Puts back the native rows of `opened`'s document groups of `carrier`'s
/// family, each rebuilt from every part of its group in order. A part that
/// does not read as a group's refuses.
pub(super) fn restore(
    carrier: SyncCarrier,
    opened: &OpenedOwnerRows,
) -> Result<Vec<(RowLocator, Vec<u8>)>> {
    let mut groups: BTreeMap<(Family, EntityId), OpenedGroup<'_>> = BTreeMap::new();
    for part in &opened.rows {
        let RowPart::NoActor { at, .. } = part else {
            continue;
        };
        let (family, entity) = Family::named_by(&at.key).ok_or_else(bad_part)?;
        if Some(family) != Family::of(carrier) {
            return Err(bad_part());
        }
        let group = groups.entry((family, entity)).or_default();
        if at.path.is_empty() {
            group.natives.push(part);
            continue;
        }
        let index = at
            .path
            .strip_prefix(BASIS)
            .and_then(|index| index.parse().ok());
        let index: usize = index.ok_or_else(bad_part)?;
        if format!("{BASIS}{index}") != at.path || group.basis.insert(index, part).is_some() {
            return Err(bad_part());
        }
    }
    let mut restored = Vec::new();
    for ((family, entity), mut group) in groups {
        group.natives.sort_by(|a, b| a.at().key.cmp(&b.at().key));
        let anchor = group.natives.first().ok_or_else(bad_part)?.at();
        let based = group.basis.len();
        let ordered = group
            .basis
            .iter()
            .enumerate()
            .all(|(index, (at_index, part))| index == *at_index && part.at().key == anchor.key);
        if !ordered {
            return Err(bad_part());
        }
        let mut parts = Vec::with_capacity(based + group.natives.len());
        for part in group.basis.into_values().chain(group.natives) {
            let RowPart::NoActor { at, value } = part else {
                return Err(bad_part());
            };
            let actors: Vec<&ActorPart> = opened
                .actor_parts
                .iter()
                .filter(|actor| actor.content_locator == *at)
                .collect();
            parts.push((at, value.as_slice(), opened_atoms(&actors)?));
        }
        restored.extend(rebuild(family, entity, &parts, based)?);
    }
    Ok(restored)
}
