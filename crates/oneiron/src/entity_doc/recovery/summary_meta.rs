//! The scope-summary meta a canonical EntityDoc row carries beside its
//! editable metadata (FIX 756): a SUMMARY document's purpose and derivation,
//! the typed values its meta map keeps as encoded bytes. Neither is an
//! editable field (`ports::document_fields` names neither), so they ride a
//! field of their own and are written back as they were captured.

use std::collections::BTreeMap;

use loro::LoroDoc;

use super::super::document::{map_get_bytes, map_insert_bytes};
use super::invalid;
use crate::Result;

/// The meta keys a summary document keeps its typed values under.
const SUMMARY_META: [&str; 2] = ["purpose", "derivation"];

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
