//! Room row part codecs without the sync feature (FIX 12405).
//!
//! The carrier and room-row part codecs, mounted here from their one source
//! so canonical recovery rebuilds them with or without `sync`. `sync`
//! re-exports both modules, so every old path keeps resolving and the codec
//! compiles once. The same codec and wire formats run with either feature
//! setting; only the Loro byte-map import below differs.

#[path = "sync/carrier_parts.rs"]
pub(crate) mod carrier_parts;

pub(crate) mod offer_parts;

#[path = "sync/room_parts.rs"]
pub(crate) mod room_parts;

/// The Loro byte-map operations the part codecs call.
#[cfg(feature = "sync")]
pub(crate) mod loro_bytes {
    //! With `sync`, the `store::loro_document` originals, re-exported
    //! unchanged: sync behavior is identical.
    pub(crate) use crate::store::loro_document::{
        map_contains_binary, map_delete, map_get_bytes, map_insert_bytes,
    };
}

/// The Loro byte-map operations the part codecs call.
#[cfg(not(feature = "sync"))]
pub(crate) mod loro_bytes {
    //! Without `sync`, the same four operations over the same Loro calls,
    //! refused with the canonical-insert error: no sync-gated source here.
    use loro::{LoroMap, LoroValue, ValueOrContainer};

    use crate::error::Result;
    use crate::store::canonical_document::invalid;

    pub(crate) fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) -> Result<()> {
        map.insert(key, value)
            .map_err(|_| invalid("room row map insert"))
    }

    pub(crate) fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
        match map.get(key)? {
            ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn map_delete(map: &LoroMap, key: &str) -> Result<()> {
        map.delete(key).map_err(|_| invalid("room row map delete"))
    }

    pub(crate) fn map_contains_binary(map: &LoroMap, key: &str) -> bool {
        matches!(
            map.get(key),
            Some(ValueOrContainer::Value(LoroValue::Binary(_)))
        )
    }
}
