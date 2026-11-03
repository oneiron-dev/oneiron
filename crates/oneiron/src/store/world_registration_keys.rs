//! Storage keys for foreign-world registration and stale markers.

/// LMDB `sync_state` key prefix for per-world stale stamps.
pub const FEDERATION_STALE_KEY_PREFIX: &str = "fedstale:";

/// LMDB `sync_state` key prefix for pact-to-world registrations.
pub const FEDERATION_WORLD_KEY_PREFIX: &str = "fedworld:";
