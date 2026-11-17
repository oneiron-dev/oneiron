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

impl VaultStanding {
    /// The role's name, as a private thread's walk-in notice names the role
    /// an agent walked in as (OF-529).
    pub(crate) const fn role_name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
        }
    }
}
