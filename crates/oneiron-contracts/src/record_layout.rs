//! Byte layout of the entity metadata header that starts every stored entity row: the type
//! byte, the occurred interval and the learned-at stamp, then the msgpack body.
//!
//! `pub` so the engine's row codecs and retrieval's fusion (which reads salience and
//! confidence out of the body) agree on one layout across the crate line. Offsets only;
//! nothing here reads or writes a row.

/// Offset of the entity type byte.
pub const ENTITY_TYPE_OFFSET: usize = 0;
/// Offset of the big-endian `occurred` interval start.
pub const ENTITY_OCCURRED_START_OFFSET: usize = 1;
/// Offset of the big-endian `occurred` interval end.
pub const ENTITY_OCCURRED_END_OFFSET: usize = 9;
/// Offset of the big-endian `learned_at` stamp.
pub const ENTITY_LEARNED_AT_OFFSET: usize = 17;
/// Offset of the msgpack body.
pub const ENTITY_BODY_OFFSET: usize = 25;
/// Length of the metadata header: everything before the body.
pub const ENTITY_METADATA_HEADER_LEN: usize = ENTITY_BODY_OFFSET;
