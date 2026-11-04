//! Access-grant body fields used by context-pack serialization.

/// Pinned on-disk MessagePack key set for AccessGrant bodies.
pub const ACCESS_GRANT_BODY_KEYS: [&str; 11] = [
    "schema_version",
    "principal_ref",
    "scope",
    "capability",
    "status",
    "created_at",
    "revoked_at",
    "expires_at",
    "authority_scope",
    "companion_bounds",
    "witness_read_history",
];

pub(crate) const ACCESS_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "capability", "status"];

pub(crate) const ACCESS_GRANT_FIELDS_STANDARD: &[&str] =
    &["principal_ref", "scope", "capability", "status"];

// Lifecycle audit metadata is read through receipts, not authority context packs.
pub(crate) const ACCESS_GRANT_FIELDS_FULL: &[&str] = &[
    "schema_version",
    "principal_ref",
    "scope",
    "capability",
    "status",
    "created_at",
    "revoked_at",
    "expires_at",
    "authority_scope",
    "companion_bounds",
];
