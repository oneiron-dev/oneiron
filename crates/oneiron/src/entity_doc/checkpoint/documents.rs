//! The document rows of entity and NOTE documents (KS7-2): each slot's
//! snapshot and pending updates, joined to their owner through every
//! retained entity-document head, every head document a NOTE held, and the
//! entity a snapshot's own birth names; never by presuming a slot is its
//! entity. Their Loro bytes name actors in their birth and commit messages,
//! which no split takes out, so each stays under the vault-wide seal, named
//! with its owner; a slot nothing joins is named with no owner.

use std::collections::BTreeMap;

use heed::RoTxn;

use super::{ENTITY_DOC_ACTORS, hex_id};
use crate::entity_doc::EntityDoc;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DocumentSlot, DocumentUpdateKey};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, Captured, OwnerRef, RowLocator, Unresolved};

/// The carrier a NOTE document's Loro bytes are.
const NOTE_DOC_ACTORS: &str = "NOTE document commit messages name actors";

const SNAPSHOTS: SideTable<DocumentSlot, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_SNAPSHOT);
const UPDATES: SideTable<DocumentUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DOCUMENT_UPDATE);
/// Each head document a NOTE's text plane held: the note, then the head.
const NOTE_HEAD_DOCS: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::NOTE_HEAD_DOC);

/// A slot's owner and the carrier its bytes are.
type SlotOwner = (EntityId, &'static str);

fn name(out: &mut Captured, at: RowLocator, owner: Option<SlotOwner>) {
    match owner {
        Some((entity, carrier)) => out.unclassified(
            at,
            Some(OwnerRef::entity(&entity)),
            Unresolved::ActorSplit(carrier),
        ),
        None => out.unclassified(at, None, Unresolved::NoOwner),
    }
}

/// The entity a snapshot's own birth names.
fn birth_owner(snapshot: &[u8]) -> Option<EntityId> {
    let doc = EntityDoc::from_snapshot(snapshot).ok()?;
    hex_id(&doc.birth().entity)
}

/// Names every document row in `txn` with its owner: `heads` maps each
/// retained head's slot to its entity.
pub(super) fn capture(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    heads: BTreeMap<String, EntityId>,
    out: &mut Captured,
) -> Result<()> {
    let mut owners: BTreeMap<String, SlotOwner> = heads
        .into_iter()
        .map(|(slot, entity)| (slot, (entity, ENTITY_DOC_ACTORS)))
        .collect();
    // The NOTE getter captures these markers; here they only join slots.
    for row in NOTE_HEAD_DOCS.iter_raw_from(dbs, txn, &[])? {
        let (key, _) = row?;
        if let Some((note, head)) = <(EntityId, EntityId)>::decode_key(&key) {
            owners
                .entry(head.to_hex())
                .or_insert((note, NOTE_DOC_ACTORS));
        }
    }
    for row in rows::typed_rows(dbs, txn, SNAPSHOTS, out)? {
        let slot = row.key.to_hex();
        let owner = match owners.get(&slot) {
            Some(owner) => Some(*owner),
            None => birth_owner(&row.value).map(|entity| (entity, ENTITY_DOC_ACTORS)),
        };
        if let Some(owner) = owner {
            owners.insert(slot, owner);
        }
        name(out, row.at, owner);
    }
    for row in rows::typed_rows(dbs, txn, UPDATES, out)? {
        let owner = owners.get(&row.key.slot.to_hex()).copied();
        name(out, row.at, owner);
    }
    Ok(())
}
