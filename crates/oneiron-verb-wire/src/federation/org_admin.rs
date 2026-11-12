//! Moved from `crates/oneiron/src/federation/org_admin.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::batch::shared_vault_write::OrgAdminPower;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A failed setup or power check; failures never fall back to owner authority.
#[derive(Debug, thiserror::Error)]
pub enum OrgAdminError {
    /// Setup is one-time, including attempts to widen it.
    #[error("organization administration is already configured")]
    AlreadyConfigured,
    /// The named actor or power has not been granted.
    #[error("organization administration power denied")]
    Denied,
    /// Store access or malformed persisted state.
    #[error(transparent)]
    Engine(#[from] oneiron_base::error::Error),
}
