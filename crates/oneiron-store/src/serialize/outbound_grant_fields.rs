//! Standing outbound grant schema keys and serialization field profiles.

/// Current StandingOutboundGrant body schema version.
pub const OUTBOUND_GRANT_SCHEMA_VERSION: u64 = 3;

/// Pinned recursive MessagePack key vocabulary for StandingOutboundGrant
/// bodies. Existing top-level positions remain stable; scoped-tool keys are
/// appended and encoded inside the `scope` map.
pub const OUTBOUND_GRANT_BODY_KEYS: [&str; 17] = [
    "schema_version",
    "principal_ref",
    "origin_component_id",
    "origin_action_id",
    "origin_receipt_ref",
    "scope",
    "status",
    "created_at",
    "revoked_at",
    "last_used_at",
    "binding_diff_handle",
    "read_frontier_hash",
    "server",
    "tool",
    "data_class_ceiling",
    "endpoint_allowlist",
    "authority_scope",
];

pub const OUTBOUND_GRANT_TOP_LEVEL_KEYS: [&str; 13] = [
    OUTBOUND_GRANT_BODY_KEYS[0],
    OUTBOUND_GRANT_BODY_KEYS[1],
    OUTBOUND_GRANT_BODY_KEYS[2],
    OUTBOUND_GRANT_BODY_KEYS[3],
    OUTBOUND_GRANT_BODY_KEYS[4],
    OUTBOUND_GRANT_BODY_KEYS[5],
    OUTBOUND_GRANT_BODY_KEYS[6],
    OUTBOUND_GRANT_BODY_KEYS[7],
    OUTBOUND_GRANT_BODY_KEYS[8],
    OUTBOUND_GRANT_BODY_KEYS[9],
    OUTBOUND_GRANT_BODY_KEYS[10],
    OUTBOUND_GRANT_BODY_KEYS[11],
    OUTBOUND_GRANT_BODY_KEYS[16],
];

pub const OUTBOUND_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "status", "last_used_at"];

pub const OUTBOUND_GRANT_FIELDS_STANDARD: &[&str] = &[
    "principal_ref",
    "origin_component_id",
    "origin_action_id",
    "scope",
    "status",
    "last_used_at",
];

pub const OUTBOUND_GRANT_FIELDS_FULL: &[&str] = &OUTBOUND_GRANT_TOP_LEVEL_KEYS;
