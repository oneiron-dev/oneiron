//! Declared entity identity hints and their lookup index.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;

pub use oneiron_store::identity_hints::identity_fields_for_kind;

pub(crate) fn identity_hint_body(kind: u8, bytes: &[u8]) -> Option<serde_json::Value> {
    // Checked before the decode: a kind without identity fields, a custody
    // record among them, is never decoded into an unwiped copy.
    if identity_fields_for_kind(kind).is_empty() {
        return None;
    }
    let mut cursor = std::io::Cursor::new(bytes);
    if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        Some(crate::serialize::msgpack_value_to_json(&value))
    } else {
        serde_json::from_slice(bytes).ok()
    }
}

pub(crate) fn hints(kind: u8, bytes: &[u8]) -> BTreeSet<String> {
    let Some(value) = identity_hint_body(kind, bytes) else {
        return BTreeSet::new();
    };
    let mut hints = BTreeSet::new();
    for field in identity_fields_for_kind(kind) {
        let Some(value) = value.get(*field) else {
            continue;
        };
        let values: Vec<_> = match value {
            serde_json::Value::Array(values) => values.iter().collect(),
            value => vec![value],
        };
        for value in values {
            if let Some(value) = value.as_str() {
                let value = value.trim().to_lowercase();
                if !value.is_empty() {
                    hints.insert(value);
                }
            }
        }
    }
    hints
}

/// Per-kind identity hint lookup index. Key: kind byte + `blake3(hint)` +
/// entity id; value: an empty presence marker.
pub(crate) const IDENTITY_HINT: SideTable<([u8; 1], [u8; 32], EntityId), (), Raw> =
    SideTable::new(&side_table::INGEST_IDENTITY_HINT);

/// The digest an identity hint is indexed under: the hint trimmed and
/// lowercased, hashed. A local index of hints keys them the same way.
pub(crate) fn identity_hint_digest(hint: &str) -> [u8; 32] {
    *blake3::hash(hint.trim().to_lowercase().as_bytes()).as_bytes()
}
pub(crate) fn hint_prefix(kind: u8, hint: &str) -> Vec<u8> {
    let mut key = vec![kind];
    key.extend_from_slice(&identity_hint_digest(hint));
    key
}
fn hint_key(kind: u8, hint: &str, id: &EntityId) -> ([u8; 1], [u8; 32], EntityId) {
    ([kind], identity_hint_digest(hint), *id)
}

pub(crate) fn reindex_identity_hints(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        for hint in hints(
            header.entity_type,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        ) {
            IDENTITY_HINT.delete(store, txn, &hint_key(header.entity_type, &hint, id))?;
        }
    }
    if let Some((kind, body)) = replacement {
        for hint in hints(kind, body) {
            IDENTITY_HINT.put(store, txn, &hint_key(kind, &hint, id), &())?;
        }
    }
    Ok(())
}
