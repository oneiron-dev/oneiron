//! Entity ids, world ids and the presentation-id grammar. Defined in
//! `oneiron-contracts`; every `oneiron::entity_id` path is unchanged.
//!
//! A [`ForeignWorldId`] (a WORLD id received from a foreign vault) never converts into a
//! [`LocalWorldId`], which keeps A->B->C re-share out of outbound selector construction:
//!
//! ```compile_fail
//! use oneiron::sync::SyncSelectorWorld;
//! use oneiron::entity_id::{EntityId, ForeignWorldId};
//!
//! let foreign = ForeignWorldId::from_entity_id(
//!     EntityId::from_bytes([0xF1; 16]).unwrap(),
//! )
//! .unwrap();
//! let _cannot_reshare = SyncSelectorWorld::World(foreign);
//! ```

pub(crate) use oneiron_contracts::entity_id::{
    ENTITY_ID_LEN, bytes_to_hex_lower, derived_domains, parse_entity_id, serde_hex,
};
pub use oneiron_contracts::entity_id::{
    EntityId, FOREIGN_WORLD_ID_RANGE_START_BYTE, ForeignWorldId, LocalWorldId,
    MIN_PRESENTATION_PREFIX_LEN, ParsedPresentationId, is_foreign_world_id_range,
    parse_presentation_id, parse_short_ref_syntax,
};
