//! The retired companion-register identity, reserved in the type registry.
//! `oneiron::companion` re-exports both constants.

/// Retired companion-register byte; every new put and replay refuses it.
/// It remains reserved so unrelated entities cannot reuse the old identity byte.
pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = 115;

/// Short-id prefix for companion-register rows.
pub const COMPANION_REGISTER_SHORT_ID_PREFIX: &str = "cr";
