//! Field projections of federation grant records.

pub const FEDERATION_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "role", "preset"];

pub const FEDERATION_GRANT_FIELDS_STANDARD: &[&str] = &["scope", "member_ref", "role", "preset"];

// Explicit, NOT an alias of the on-disk key set: the body grew to seven keys,
// context-pack hydration deliberately did not. Delegate expiry and parentage
// are authorization facts read at the selector door, not pack content.
pub const FEDERATION_GRANT_FIELDS_FULL: &[&str] =
    &["schema_version", "scope", "member_ref", "role", "preset"];
