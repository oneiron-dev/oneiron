//! Byte layout of the entity metadata header that starts every stored entity row: the type
//! byte, the occurred interval, learned-at stamp and row version, then the msgpack body.
//!
//! `pub` so the engine's row codecs and retrieval's fusion (which reads salience and
//! confidence out of the body) agree on one layout across the crate line. Offsets and the
//! header parse only; nothing here reads or writes a row.

/// Offset of the entity type byte.
pub const ENTITY_TYPE_OFFSET: usize = 0;
/// Offset of the big-endian `occurred` interval start.
pub const ENTITY_OCCURRED_START_OFFSET: usize = 1;
/// Offset of the big-endian `occurred` interval end.
pub const ENTITY_OCCURRED_END_OFFSET: usize = 9;
/// Offset of the big-endian `learned_at` stamp.
pub const ENTITY_LEARNED_AT_OFFSET: usize = 17;
/// Offset of the big-endian row version.
pub const ENTITY_ROW_VERSION_OFFSET: usize = 25;
/// Offset of the msgpack body.
pub const ENTITY_BODY_OFFSET: usize = 33;
/// Length of the metadata header: everything before the body.
pub const ENTITY_METADATA_HEADER_LEN: usize = ENTITY_BODY_OFFSET;

/// The metadata header of one stored entity row.
#[derive(Debug, Clone, Copy)]
pub struct EntityMetadataHeader {
    /// The entity type byte.
    pub entity_type: u8,
    /// The `occurred` interval start.
    pub occurred_start: u64,
    /// The `occurred` interval end.
    pub occurred_end: u64,
    /// The `learned_at` stamp.
    pub learned_at: u64,
    /// The origin-write version of a CLAIM; zero on other native entity kinds.
    pub row_version: u64,
}

impl EntityMetadataHeader {
    /// The header at the start of `raw`; `None` when `raw` is shorter than
    /// the header.
    #[must_use]
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return None;
        }

        let entity_type = raw[ENTITY_TYPE_OFFSET];
        let occurred_start = u64::from_be_bytes(
            raw[ENTITY_OCCURRED_START_OFFSET..ENTITY_OCCURRED_END_OFFSET]
                .try_into()
                .ok()?,
        );
        let occurred_end = u64::from_be_bytes(
            raw[ENTITY_OCCURRED_END_OFFSET..ENTITY_LEARNED_AT_OFFSET]
                .try_into()
                .ok()?,
        );
        let learned_at = u64::from_be_bytes(
            raw[ENTITY_LEARNED_AT_OFFSET..ENTITY_ROW_VERSION_OFFSET]
                .try_into()
                .ok()?,
        );

        let row_version = u64::from_be_bytes(
            raw[ENTITY_ROW_VERSION_OFFSET..ENTITY_BODY_OFFSET]
                .try_into()
                .ok()?,
        );

        Some(Self {
            entity_type,
            occurred_start,
            occurred_end,
            learned_at,
            row_version,
        })
    }
}
