//! Selection of an exact transport fact from its actual durable Store row.

use std::path::PathBuf;

use heed::RoTxn;

use super::{RecordDocumentPair, SOURCES, decode_source_from_row, source_key};
use crate::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Only the Store reader constructs this selection. It is a transport source,
/// not native admission, current MACHINE standing, or a commit receipt.
pub(crate) struct RetainedRecordDocumentSource {
    vault: PathBuf,
    key: String,
    bytes: Vec<u8>,
    machine: EntityId,
}

impl RetainedRecordDocumentSource {
    pub(crate) fn machine(&self) -> EntityId {
        self.machine
    }

    pub(crate) fn recheck_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        window: &str,
        entity: &EntityId,
        pair: &RecordDocumentPair,
    ) -> Result<bool> {
        Ok(self.vault == store.env.path()
            && source_key(window, entity, pair) == self.key
            && SOURCES.get_bytes(store, txn, &self.key)?.as_deref() == Some(self.bytes.as_slice())
            && !crate::ports::removed_in_txn(store, txn, entity)?
            && !crate::ports::removed_in_txn(store, txn, &self.machine)?)
    }
}

/// Decoded metadata or a caller's LoroDoc cannot construct this selection.
/// The sync owner must still reconstruct and bind the exact durable carrier.
pub(crate) fn retained_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    window: &str,
    entity: &EntityId,
    pair: &RecordDocumentPair,
) -> Result<Option<RetainedRecordDocumentSource>> {
    let key = source_key(window, entity, pair);
    let Some(bytes) = SOURCES.get_bytes(store, txn, &key)? else {
        return Ok(None);
    };
    let Some((owner, machine, stored, _)) =
        decode_source_from_row(&SOURCES.key_bytes(&key), &bytes)
    else {
        return Ok(None);
    };
    if owner != *entity
        || stored.pair != *pair
        || crate::ports::removed_in_txn(store, txn, entity)?
        || crate::ports::removed_in_txn(store, txn, &machine)?
    {
        return Ok(None);
    }
    Ok(Some(RetainedRecordDocumentSource {
        vault: store.env.path().to_path_buf(),
        key,
        bytes,
        machine,
    }))
}
