//! Metadata of an authenticated record/document transport, not native admission.

mod history;
mod rebind;
mod retained;
pub(crate) use history::remove_history_in_txn;
pub(crate) use rebind::{
    PreparedRecordDocumentRebinding, persist_opened_rebindings, prepare_opened_rebindings,
};
pub(crate) use retained::{RetainedRecordDocumentSource, retained_in_txn};

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::entity_doc::{CarriedRecordDocument, RefinementOriginSource};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordDocumentPair {
    pub(crate) row: [u8; 32],
    pub(crate) head: [u8; 32],
    pub(crate) snapshot: [u8; 32],
    pub(crate) refinement: Option<[u8; 32]>,
}

impl RecordDocumentPair {
    pub(crate) fn of(
        raw: &[u8],
        head: &CarriedRecordDocument,
        snapshot: &[u8],
        refinement: Option<&RefinementOriginSource>,
    ) -> Result<Self> {
        let refinement = refinement.map(|source| {
            let mut digest = blake3::Hasher::new();
            digest.update(&source.revision().0);
            digest.update(source.raw());
            *digest.finalize().as_bytes()
        });
        Ok(Self {
            row: *blake3::hash(raw).as_bytes(),
            head: *blake3::hash(&head.encode()?).as_bytes(),
            snapshot: *blake3::hash(snapshot).as_bytes(),
            refinement,
        })
    }

    fn identity(&self) -> String {
        let mut digest = blake3::Hasher::new();
        digest.update(&self.row);
        digest.update(&self.head);
        digest.update(&self.snapshot);
        match self.refinement {
            Some(refinement) => {
                digest.update(&[1]);
                digest.update(&refinement);
            }
            None => {
                digest.update(&[0]);
            }
        }
        digest.finalize().to_hex().to_string()
    }
}

/// Data selected by the closed import's same-writer durable reconstruction.
/// The canonical head holds ids, versions and digests, not row or document bodies.
pub(crate) struct RecordDocumentSource {
    pub(crate) entity: EntityId,
    pub(crate) pair: RecordDocumentPair,
    pub(crate) head: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSource {
    machine: [u8; 16],
    pair: RecordDocumentPair,
    head: Vec<u8>,
}

const SOURCES: SideTable<String, StoredSource, Named> =
    SideTable::new(&side_table::SYNC_RECORD_DOCUMENT_SOURCE);

fn source_key(window: &str, entity: &EntityId, pair: &RecordDocumentPair) -> String {
    format!("{window}:{}:{}", entity.to_hex(), pair.identity())
}

/// Consume only the original import's closed same-transaction writer.
/// Arbitrary decoded rows or a caller's LoroDoc cannot construct this product.
pub(crate) fn persist_captured(
    source: crate::sync::ingest::RecordDocumentSources<'_, '_>,
) -> Result<()> {
    let (store, txn, window, machine, sources) = source.into_parts();
    for source in sources {
        SOURCES.put(
            store,
            txn,
            &source_key(window, &source.entity, &source.pair),
            &StoredSource {
                machine: *machine.as_bytes(),
                pair: source.pair,
                head: source.head,
            },
        )?;
    }
    Ok(())
}

/// Dropping a carrier removes its transport facts, not its members' documents.
pub(crate) fn remove_window_in_txn(store: &Store, txn: &mut RwTxn<'_>, window: &str) -> Result<()> {
    SOURCES.delete_from(store, txn, format!("{window}:").as_bytes())?;
    Ok(())
}

/// An erased entity or source MACHINE leaves no transport facts naming it.
pub(crate) fn remove_entity_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (key, source) in SOURCES.scan_from(store, txn, &[])? {
        let owner = key
            .rsplitn(3, ':')
            .nth(1)
            .and_then(|id| EntityId::from_hex(id).ok());
        if owner == Some(*entity) || source.machine == *entity.as_bytes() {
            SOURCES.delete(store, txn, &key)?;
        }
    }
    Ok(())
}

fn decode_source_from_row(
    key: &[u8],
    value: &[u8],
) -> Option<(EntityId, EntityId, StoredSource, CarriedRecordDocument)> {
    let key = key
        .strip_prefix(side_table::SYNC_RECORD_DOCUMENT_SOURCE.prefix)
        .and_then(|key| std::str::from_utf8(key).ok())?;
    let mut parts = key.rsplitn(3, ':');
    let _identity = parts.next()?;
    let entity_hex = parts.next()?;
    let window = parts.next()?;
    let entity = EntityId::from_hex(entity_hex).ok()?;
    let source: StoredSource = rmp_serde::from_slice(value).ok()?;
    let head = CarriedRecordDocument::decode(&source.head).ok()?;
    let window_key = crate::window_key::WindowKey::try_new(window)?;
    if window_key.world().is_some()
        || entity.to_hex() != entity_hex
        || head.entity().ok()? != entity
        || head.row_digest() != &source.pair.row
        || blake3::hash(&source.head).as_bytes() != &source.pair.head
        || source_key(window, &entity, &source.pair) != key
        || rmp_serde::to_vec_named(&source).ok()?.as_slice() != value
    {
        return None;
    }
    let machine = EntityId::from_bytes(source.machine).ok()?;
    Some((entity, machine, source, head))
}

fn source_from_row(key: &[u8], value: &[u8]) -> Option<(EntityId, EntityId)> {
    decode_source_from_row(key, value).map(|(entity, machine, _, _)| (entity, machine))
}

/// Invalid or mismatched data is not silently treated as metadata-only structure.
pub(crate) fn valid_row(key: &[u8], value: &[u8]) -> bool {
    source_from_row(key, value).is_some()
}

/// The exact entity and sender whose erasures must also remove this image row.
pub(crate) fn linked_entities(key: &[u8], value: &[u8]) -> Vec<EntityId> {
    source_from_row(key, value)
        .map(|(entity, machine)| vec![entity, machine])
        .unwrap_or_default()
}
