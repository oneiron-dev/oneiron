//! Access-grant body fields used by context-pack serialization.

/// Pinned on-disk MessagePack key set for AccessGrant bodies.
pub const ACCESS_GRANT_BODY_KEYS: [&str; 10] = [
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

pub(crate) const ACCESS_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "capability", "status"];

pub(crate) const ACCESS_GRANT_FIELDS_STANDARD: &[&str] =
    &["principal_ref", "scope", "capability", "status"];

pub(crate) const ACCESS_GRANT_FIELDS_FULL: &[&str] = &ACCESS_GRANT_BODY_KEYS;
