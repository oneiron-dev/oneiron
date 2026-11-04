//! Stable queued-attempt identifiers: defined in `oneiron-store`, with the
//! side-table raw codec the engine binds to them.

pub use oneiron_store::attempt_id::AttemptId;

/// `AttemptId` is a foreign (same-crate) value type to any side table that
/// stores a bare attempt reference as its row's raw 16 bytes (as opposed to
/// keying on it, which `llm::step::types` already binds via `SideKey`).
impl crate::side_table::RawValue for AttemptId {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::CodecError> {
        Ok(self.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::CodecError> {
        Ok(Self::from_bytes(bytes)?)
    }
}
