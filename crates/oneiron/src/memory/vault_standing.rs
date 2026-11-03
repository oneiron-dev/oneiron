//! The owner or administrator standing a room reader presents.

/// What `actor` is to the vault, through the PERSON a pen is anchored to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultStanding {
    /// A live PERSON among the vault's owners.
    Owner,
    /// A live PERSON holding an Admin grant over the shared vault, and no
    /// owner.
    Admin,
}
