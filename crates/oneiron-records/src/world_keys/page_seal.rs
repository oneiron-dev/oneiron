//! Moved from `crates/oneiron/src/world_keys/page_seal.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::vault_page_seal::VaultPageSeal;

pub const MIRROR_VERSION: u32 = 2;
pub mod creation;
