//! Moved from `crates/oneiron/src/origin/lfs/store.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Domain separator for deterministic LFS ASSET ids.
pub const VAULT_LFS_ASSET_ID_DOMAIN: &[u8] = b"oneiron:origin-lfs-asset:v1";
