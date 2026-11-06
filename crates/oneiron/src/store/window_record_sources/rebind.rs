//! Rebind only an authenticated opened source's existing transport fact.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use loro::LoroDoc;

use super::{RecordDocumentPair, SOURCES, StoredSource, decode_source_from_row, source_key};
use crate::EntityId;
use crate::entity_doc::CarriedRecordDocument;
use crate::error::Result;
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::store::Store;
use crate::store::checkpoint_payload::rows::bad_part;
use crate::sync::checkpoint_payload::record_documents::opened::OpenedWindowRecordSources;
use crate::sync::loro_support::{doc_from_snapshot, import_doc, map_get_bytes};
use crate::sync::skill_docs::selected_record_document;

/// Exact proposed row plus the original fact the applying writer must still
/// hold. Only preparation from an authenticated open constructs this value.
pub(crate) struct PreparedRecordDocumentRebinding {
    window: String,
    entity: EntityId,
    original_key: String,
    original_bytes: Vec<u8>,
    key: String,
    source: StoredSource,
    value_len: u64,
}

impl PreparedRecordDocumentRebinding {
    pub(crate) fn row_lengths(&self) -> (u64, u64) {
        (SOURCES.key_bytes(&self.key).len() as u64, self.value_len)
    }
}

/// The original image supplies a source fact only for the exact old pair
/// that this native content authenticated. Sender identity is never inferred
/// from a rebuilt row, its holder, or the current MACHINE table.
pub(crate) fn prepare_opened_rebindings(
    opened: Vec<OpenedWindowRecordSources>,
    image_rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<PreparedRecordDocumentRebinding>> {
    let rows: BTreeMap<_, _> = image_rows
        .iter()
        .filter(|(key, _)| key.starts_with(SOURCES.decl().prefix))
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();
    let mut prepared = BTreeMap::new();
    for opened in opened {
        let (window, sources) = opened.into_parts();
        for source in sources {
            if source.original == source.rebuilt {
                continue;
            }
            let head = CarriedRecordDocument::decode(&source.head)?;
            let entity = head.entity()?;
            let original_key = source_key(&window, &entity, &source.original);
            let full_key = SOURCES.key_bytes(&original_key);
            let Some(&bytes) = rows.get(full_key.as_slice()) else {
                continue;
            };
            let Some((owner, _, stored, _)) = decode_source_from_row(&full_key, bytes) else {
                continue;
            };
            if owner != entity || stored.pair != source.original || stored.head != source.head {
                continue;
            }
            let key = source_key(&window, &entity, &source.rebuilt);
            let replacement = StoredSource {
                machine: stored.machine,
                pair: source.rebuilt,
                head: source.head,
            };
            let value = rmp_serde::to_vec_named(&replacement).map_err(|_| bad_part())?;
            let identity = (original_key.clone(), key.clone());
            if let Some(old) = prepared.get(&identity) {
                let old: &PreparedRecordDocumentRebinding = old;
                if old.original_key != original_key
                    || old.original_bytes != bytes
                    || rmp_serde::to_vec_named(&old.source).map_err(|_| bad_part())? != value
                {
                    return Err(bad_part());
                }
                continue;
            }
            prepared.insert(
                identity,
                PreparedRecordDocumentRebinding {
                    window: window.clone(),
                    entity,
                    original_key,
                    original_bytes: bytes.to_vec(),
                    key,
                    source: replacement,
                    value_len: value.len() as u64,
                },
            );
        }
    }
    Ok(prepared.into_values().collect())
}

/// Reconstructs the actual stored snapshot and ALL pending updates through
/// this transaction, using the native snapshot/import codecs and Store ports.
fn durable_window_in_txn(store: &Store, txn: &RoTxn<'_>, window: &str) -> Result<LoroDoc> {
    let address = WindowAddress::new(window);
    let snapshot = store.port_window_doc_with_raw(txn, address, |raw| Ok(raw.to_vec()))?;
    let doc = match snapshot {
        Some(snapshot) => doc_from_snapshot(&snapshot)?,
        None => LoroDoc::new(),
    };
    for update in store.port_window_updates(txn, address, |_, raw| import_doc(&doc, raw))? {
        update??;
    }
    Ok(doc)
}

/// Called after the restored rows in their SAME original writer. Rebinding
/// preserves an existing fact's machine; every ordinary native admission and
/// retained-source check still runs when a later replay consumes the pair.
pub(crate) fn persist_opened_rebindings(
    store: &Store,
    txn: &mut RwTxn<'_>,
    prepared: Vec<PreparedRecordDocumentRebinding>,
) -> Result<()> {
    for binding in prepared {
        if SOURCES
            .get_bytes(store, txn, &binding.original_key)?
            .as_deref()
            != Some(binding.original_bytes.as_slice())
            || crate::ports::removed_in_txn(store, txn, &binding.entity)?
        {
            continue;
        }
        let machine = EntityId::from_bytes(binding.source.machine)?;
        if crate::ports::removed_in_txn(store, txn, &machine)? {
            continue;
        }
        let doc = durable_window_in_txn(store, txn, &binding.window)?;
        let Some(raw) = map_get_bytes(&doc.get_map("entities"), &binding.entity.to_hex()) else {
            continue;
        };
        let Some((head, snapshot, refinement)) =
            selected_record_document(&doc, &binding.entity, &raw)?
        else {
            continue;
        };
        if head.encode()? != binding.source.head
            || RecordDocumentPair::of(&raw, &head, &snapshot, refinement.as_ref())?
                != binding.source.pair
            || crate::sync::ingest::record_document_peer_source_in_txn(
                store,
                txn,
                &doc,
                &binding.window,
                &binding.entity,
                &raw,
            )?
        {
            continue;
        }
        // A live fact already naming this rebuilt pair keeps its sender.
        if super::retained_in_txn(
            store,
            txn,
            &binding.window,
            &binding.entity,
            &binding.source.pair,
        )?
        .is_some()
        {
            continue;
        }
        SOURCES.put(store, txn, &binding.key, &binding.source)?;
    }
    Ok(())
}
