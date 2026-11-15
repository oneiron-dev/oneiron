//! Moved from `crates/oneiron/src/federation/org_admin.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::batch::shared_vault_write::OrgAdminPower;

/// A failed setup or power check; failures never fall back to owner authority.
#[derive(Debug, thiserror::Error)]
pub enum OrgAdminError {
    /// Setup is stored once; a second setup is refused. Only the owner's
    /// amend changes a stored setup.
    #[error("organization administration is already configured")]
    AlreadyConfigured,
    /// An amend names an organization with no stored setup; the setup door
    /// stores the first one.
    #[error("organization administration is not configured")]
    NotConfigured,
    /// An amend names a power the stored setup lacks (canon vault:18: no one
    /// can grant missing powers).
    #[error("an amend cannot add a named power the organization's setup lacks")]
    PowerOutsideSetup,
    /// The named actor or power has not been granted.
    #[error("organization administration power denied")]
    Denied,
    /// Store access or malformed persisted state.
    #[error(transparent)]
    Engine(#[from] oneiron_base::error::Error),
}
