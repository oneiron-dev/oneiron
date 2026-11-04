//! The role an archive delete was admitted under, as a delete's receipts and
//! gate reason codes name it. `federation::archive_delete` re-exports
//! [`ArchiveDeleteRole`] at its old path; who holds which role stays there.

/// The role an archive delete was admitted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveDeleteRole {
    /// A live owner of the vault, co-owners included.
    Owner,
    /// A live Admin whose grant's resource axes hold the record.
    Admin,
    /// A live Admin or Member who provably owns the record.
    Member,
    /// An agent under one Grant that names `delete`.
    Agent,
}

impl ArchiveDeleteRole {
    /// The role's pinned name in receipts and gate reason codes.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Agent => "agent",
        }
    }
}
