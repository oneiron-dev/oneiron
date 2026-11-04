//! Loro-native helpers for the sync layer.
//!
//! ARCH-0023b makes Loro the production CRDT engine. These helpers keep the
//! repeated binary-value and encoding error handling in one place while all
//! call sites still use native `LoroDoc` / `LoroMap` handles.

#[cfg(test)]
use loro::{ExportMode, LoroDoc, LoroValue};

#[cfg(test)]
use crate::error::{Error, Result, SyncEngineContext};

pub(crate) use crate::store::loro_document::{
    copy_binary_root_map, map_contains_binary, map_delete, map_get_bytes, map_insert_bytes,
};

#[cfg(test)]
pub(crate) use crate::store::loro_tombstones::TOMBSTONE_KEY_PARSES;
pub(crate) use crate::store::loro_tombstones::{
    TombstoneIndex, tombstone_map_contains_id, tombstone_values_for_id,
};

pub(super) use crate::store::loro_document::{
    map_for_each_value_bytes, map_for_each_value_bytes_deferring,
};

pub(crate) use crate::store::loro_document::{map_for_each_bytes, map_for_each_tombstone_value};

#[cfg(test)]
pub(crate) fn export_all_updates(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))
}

pub(crate) use crate::store::loro_document::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_from, import_doc,
    json_covers_blob,
};

pub use crate::store::loro_document::export_updates_since;

/// Deep value without empty root maps: `get_map` registers a root on the
/// local doc at first read, so an empty root is not replicated state.
#[cfg(test)]
pub(crate) fn replicated_deep_value(doc: &LoroDoc) -> LoroValue {
    match doc.get_deep_value() {
        LoroValue::Map(roots) => LoroValue::Map(
            roots
                .iter()
                .filter(|(_, value)| !matches!(value, LoroValue::Map(map) if map.is_empty()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        ),
        other => other,
    }
}
