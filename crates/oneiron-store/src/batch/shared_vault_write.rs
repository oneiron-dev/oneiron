//! A requested shared-vault mutation and the closed organization-administration
//! vocabulary it names. `federation` re-exports both at their old paths;
//! whether a writer may make one is judged there.

use oneiron_authority::federation::Scope;
use serde::{Deserialize, Serialize};

/// The complete administration vocabulary, fixed by the engine.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OrgAdminPower {
    /// Enroll a member's public identity, never their private key.
    AddMember,
    /// Remove an organization membership.
    RemoveMember,
    /// Assign a non-root organization role.
    AssignRole,
    /// Reset access to a shared project, not a member vault.
    ResetSharedProjectAccess,
}
impl OrgAdminPower {
    /// Closed wire token used by Console routes and rendered actions.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddMember => "org:add-member",
            Self::RemoveMember => "org:remove-member",
            Self::AssignRole => "org:assign-role",
            Self::ResetSharedProjectAccess => "org:reset-shared-project-access",
        }
    }
    /// Parses only named administrative powers. Root and private reads do not exist here.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "org:add-member" => Some(Self::AddMember),
            "org:remove-member" => Some(Self::RemoveMember),
            "org:assign-role" => Some(Self::AssignRole),
            "org:reset-shared-project-access" => Some(Self::ResetSharedProjectAccess),
            _ => None,
        }
    }
}

/// A requested shared-vault mutation. Personal roots never inherit shared authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedVaultWrite {
    /// Content with its resolved six-axis record scope; a missing axis is bottom.
    Content(Scope),
    /// One named organization-administration power.
    Admin(OrgAdminPower),
    /// A conflict review ruling in this shared vault.
    RuleConflict,
    /// Change a shared workspace setting; enrollment authority alone does not confer it.
    WorkspaceSettings,
    /// Mutate the organization root.
    OrgRoot,
    /// Mutate a member's separate personal root.
    PersonalVault,
    /// Object during a catastrophic-act veto window.
    Veto,
}
