//! Core half of `entity_doc::recovery::summary_meta`: its store-layer items live in `oneiron_store::entity_doc::recovery::summary_meta` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::recovery::summary_meta::*;

use super::super::document::{map_get_bytes, map_insert_bytes};
use super::invalid;
use crate::Result;
use loro::LoroDoc;
use std::collections::BTreeMap;

/// The summary meta `doc` holds, by key: empty for any other document.
pub(super) fn bytes(doc: &LoroDoc) -> BTreeMap<String, Vec<u8>> {
    let meta = doc.get_map("meta");
    SUMMARY_META
        .iter()
        .filter_map(|key| map_get_bytes(&meta, key).map(|bytes| ((*key).to_owned(), bytes)))
        .collect()
}

/// Puts `summary` in `doc`'s meta map: each key it names written as it is,
/// every other summary key removed.
pub(super) fn write(doc: &LoroDoc, summary: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let meta = doc.get_map("meta");
    for key in SUMMARY_META {
        match summary.get(key) {
            Some(bytes) => map_insert_bytes(&meta, key, bytes)?,
            None if map_get_bytes(&meta, key).is_some() => {
                meta.delete(key)
                    .map_err(|_| invalid("summary meta removal"))?;
            }
            None => {}
        }
    }
    Ok(())
}
