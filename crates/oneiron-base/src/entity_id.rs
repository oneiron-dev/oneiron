//! Entity ids, world ids and the presentation-id grammar, defined in
//! `oneiron-contracts`. The modules of this crate name them through this path.
//! `oneiron::entity_id` re-exports the same items (and keeps the
//! `ForeignWorldId` doctest, which needs `oneiron::sync`).
pub use oneiron_contracts::entity_id::{
    ENTITY_ID_LEN, bytes_to_hex_lower, derived_domains, parse_entity_id, serde_hex,
};
pub use oneiron_contracts::entity_id::{
    EntityId, FOREIGN_WORLD_ID_RANGE_START_BYTE, ForeignWorldId, LocalWorldId,
    MIN_PRESENTATION_PREFIX_LEN, ParsedPresentationId, is_foreign_world_id_range,
    parse_presentation_id, parse_short_ref_syntax,
};
