//! The document rows of entity and NOTE documents (KS7-2, FIX 6072): each
//! slot's snapshot and pending updates, joined to their owner through every
//! retained entity-document head, every head document a NOTE held, and the
//! entity a snapshot's own birth names; never by presuming a slot is its
//! entity. An entity document's slot is one group: its full snapshot and its
//! updates in replay order split together through the shared Loro
//! projection, the birth's actor and every stamp's out ([`super::loro`]).
//! A group that does not split stays whole under the vault-wide seal, named
//! with its owner: a shallow snapshot and its updates (Engine R3), a history
//! the projection does not give back, and every NOTE document until its own
//! projection lands. A slot nothing joins is named with no owner, and one
//! two owners claim with neither.

use std::collections::BTreeMap;

use heed::RoTxn;

use super::hex_id;
use crate::entity_doc::EntityDoc;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DocumentSlot, DocumentUpdateKey};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::loro::{self as shared, Atom, OpenedRow};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, RoundTripPolicy, RowLocator, RowPart,
    TypedRow, Unresolved,
};

/// The round trip an entity document's snapshot and updates take (Engine
/// R1): the same history, in containers Loro may encode anew. No row keeps
/// a digest of these bytes (the head, the state vector and the revision
/// ledger name versions and frontiers, never a container), so a restore has
/// none to derive again.
const ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// The carrier a NOTE document's Loro bytes are, until NOTE's own
/// projection lands.
const NOTE_DOC_ACTORS: &str = "NOTE document commit messages name actors";

/// Updates with no full snapshot to replay them on.
const NO_SNAPSHOT: &str = "entity document updates with no full snapshot";

const SNAPSHOTS: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_SNAPSHOT);
const UPDATES: SideTable<DocumentUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_UPDATE);
/// Each head document a NOTE's text plane held: the note, then the head.
const NOTE_HEAD_DOCS: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::NOTE_HEAD_DOC);

/// The document a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    EntityDoc,
    Note,
}

/// Who a slot's rows belong to: one owner and the document its bytes are,
/// or owners that disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claim {
    Owner(EntityId, Flavor),
    Shared,
}

impl Claim {
    /// This claim once a NOTE's head marker names the slot too: a NOTE moved
    /// onto the entity-document plane keeps that plane's codec, and any
    /// other pair is two owners.
    fn with_note(self, note: EntityId) -> Self {
        match self {
            Self::Owner(entity, flavor) if entity == note => Self::Owner(entity, flavor),
            _ => Self::Shared,
        }
    }
}

/// One slot's rows: its snapshot, and its updates in replay order.
#[derive(Default)]
struct Group {
    snapshot: Option<TypedRow<DocumentSlot, Vec<u8>>>,
    updates: Vec<TypedRow<DocumentUpdateKey, Vec<u8>>>,
}

impl Group {
    /// The entity the group's own snapshot's birth names, for a slot nothing
    /// else joins.
    fn birth_claim(&self) -> Option<Claim> {
        let snapshot = self.snapshot.as_ref()?;
        let entity = birth_owner(&snapshot.value)?;
        Some(Claim::Owner(entity, Flavor::EntityDoc))
    }

    /// Names each of the group's rows unclassified.
    fn name(self, out: &mut Captured, owner: Option<OwnerRef>, reason: Unresolved) {
        if let Some(row) = self.snapshot {
            out.unclassified(row.at, owner, reason);
        }
        for row in self.updates {
            out.unclassified(row.at, owner, reason);
        }
    }
}

/// The entity a snapshot's own birth names.
fn birth_owner(snapshot: &[u8]) -> Option<EntityId> {
    let doc = EntityDoc::from_snapshot(snapshot).ok()?;
    hex_id(&doc.birth().entity)
}

/// Captures every document row in `txn`, slot by slot: `heads` maps each
/// retained head's slot to its entity.
pub(super) fn capture(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    heads: BTreeMap<String, EntityId>,
    out: &mut Captured,
) -> Result<()> {
    let mut claims: BTreeMap<String, Claim> = heads
        .into_iter()
        .map(|(slot, entity)| (slot, Claim::Owner(entity, Flavor::EntityDoc)))
        .collect();
    // The NOTE getter captures these markers; here they only join slots.
    for row in NOTE_HEAD_DOCS.iter_raw_from(dbs, txn, &[])? {
        let (key, _) = row?;
        let Some((note, head)) = <(EntityId, EntityId)>::decode_key(&key) else {
            continue;
        };
        claims
            .entry(head.to_hex())
            .and_modify(|claim| *claim = claim.with_note(note))
            .or_insert(Claim::Owner(note, Flavor::Note));
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for row in rows::typed_rows(dbs, txn, SNAPSHOTS, out)? {
        let slot = row.key.to_hex();
        groups.entry(slot).or_default().snapshot = Some(row);
    }
    for row in rows::typed_rows(dbs, txn, UPDATES, out)? {
        let slot = row.key.slot.to_hex();
        groups.entry(slot).or_default().updates.push(row);
    }
    for (slot, group) in groups {
        let claim = claims.get(&slot).copied().or_else(|| group.birth_claim());
        match claim {
            Some(Claim::Owner(entity, Flavor::EntityDoc)) => split_slot(out, entity, group),
            Some(Claim::Owner(note, Flavor::Note)) => {
                let reason = Unresolved::ActorSplit(NOTE_DOC_ACTORS);
                group.name(out, Some(OwnerRef::entity(&note)), reason);
            }
            Some(Claim::Shared) => group.name(out, None, Unresolved::SharedOwners),
            None => group.name(out, None, Unresolved::NoOwner),
        }
    }
    Ok(())
}

/// Splits an entity document's slot as one group, under `entity`: its full
/// snapshot, whose birth names `entity`, then its updates in replay order.
fn split_slot(out: &mut Captured, entity: EntityId, group: Group) {
    let owner = OwnerRef::entity(&entity);
    if group.snapshot.is_none() {
        group.name(out, Some(owner), Unresolved::ActorSplit(NO_SNAPSHOT));
        return;
    }
    let snapshot = group.snapshot.as_ref().map(|row| row.bytes.as_slice());
    let updates = group.updates.iter().map(|row| row.bytes.as_slice());
    let rows: Vec<&[u8]> = snapshot.into_iter().chain(updates).collect();
    let birth = rows.first().copied().map(EntityDoc::from_snapshot);
    let outcome = match birth {
        Some(Ok(doc)) if doc.birth().entity == entity.to_hex() => {
            super::loro::split(&rows, ROUND_TRIP)
        }
        Some(Ok(_)) => Err(Unresolved::SharedOwners),
        _ => Err(Unresolved::Undecodable),
    };
    match outcome {
        Ok(split) => {
            let snapshot = group.snapshot.into_iter().map(|row| row.at);
            let ats = snapshot.chain(group.updates.into_iter().map(|row| row.at));
            for (at, row) in ats.zip(split) {
                shared::place(out, owner, at, row);
            }
        }
        Err(reason) => group.name(out, Some(owner), reason),
    }
}

/// Whether `at` is a document row this getter frames.
pub(super) fn owns(at: &RowLocator) -> bool {
    at.in_table(SNAPSHOTS.decl()) || at.in_table(UPDATES.decl())
}

/// Refuses a document row that is not, under its own key, a full entity
/// document snapshot or an update blob.
pub(super) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(SNAPSHOTS.decl()) {
        rows::check_row(SNAPSHOTS, at, value)?;
        super::loro::check_snapshot(value, None)
    } else {
        rows::check_row(UPDATES, at, value)?;
        super::loro::check_update(value)
    }
}

/// One slot's no-one-form rows in an opened compartment.
#[derive(Default)]
struct OpenedSlot<'o> {
    snapshot: Option<(&'o RowLocator, &'o [u8])>,
    updates: Vec<(&'o RowLocator, &'o [u8])>,
}

/// The slot a snapshot row's key names.
fn snapshot_slot(at: &RowLocator) -> Result<String> {
    let prefix = SNAPSHOTS.decl().prefix;
    let key = at.key.strip_prefix(prefix).ok_or_else(rows::bad_part)?;
    let slot = DocumentSlot::decode_key(key).ok_or_else(rows::bad_part)?;
    Ok(slot.to_hex())
}

/// The slot an update row's key names.
fn update_slot(at: &RowLocator) -> Result<String> {
    let prefix = UPDATES.decl().prefix;
    let key = at.key.strip_prefix(prefix).ok_or_else(rows::bad_part)?;
    let key = DocumentUpdateKey::decode_key(key).ok_or_else(rows::bad_part)?;
    Ok(key.slot.to_hex())
}

/// The atoms the opened actor parts naming `at` fill.
fn atoms_at(opened: &OpenedOwnerRows, at: &RowLocator) -> Result<Vec<Atom>> {
    let parts: Vec<&ActorPart> = opened
        .actor_parts
        .iter()
        .filter(|part| part.content_locator == *at)
        .collect();
    shared::opened_atoms(&parts)
}

/// Rebuilds each entity document slot `opened` holds as one group: its
/// snapshot, then its updates in key order, each filled with the actors that
/// opened, the snapshot's birth naming the compartment's entity. Each row's
/// bytes, by its locator, for the restore's join to write.
pub(super) fn join(opened: &OpenedOwnerRows) -> Result<BTreeMap<RowLocator, Vec<u8>>> {
    let mut slots: BTreeMap<String, OpenedSlot<'_>> = BTreeMap::new();
    for part in &opened.rows {
        let RowPart::NoActor { at, value } = part else {
            continue;
        };
        if at.in_table(SNAPSHOTS.decl()) {
            let slot = slots.entry(snapshot_slot(at)?).or_default();
            if slot.snapshot.replace((at, value.as_slice())).is_some() {
                return Err(rows::bad_part());
            }
        } else if at.in_table(UPDATES.decl()) {
            let slot = slots.entry(update_slot(at)?).or_default();
            slot.updates.push((at, value.as_slice()));
        }
    }
    let mut joined = BTreeMap::new();
    if slots.is_empty() {
        return Ok(joined);
    }
    let entity = super::tree_entity(opened)?;
    for slot in slots.into_values() {
        let snapshot = slot.snapshot.ok_or_else(rows::bad_part)?;
        let mut updates = slot.updates;
        updates.sort_by(|a, b| a.0.key.cmp(&b.0.key));
        let order: Vec<(&RowLocator, &[u8])> = std::iter::once(snapshot).chain(updates).collect();
        let mut group = Vec::with_capacity(order.len());
        for &(at, content) in &order {
            let atoms = atoms_at(opened, at)?;
            group.push(OpenedRow { content, atoms });
        }
        let bytes = super::loro::join(&group)?;
        let first = bytes.first().ok_or_else(rows::bad_part)?;
        super::loro::check_snapshot(first, Some(&entity))?;
        for ((at, _), row) in order.into_iter().zip(bytes) {
            joined.insert(at.clone(), row);
        }
    }
    Ok(joined)
}
