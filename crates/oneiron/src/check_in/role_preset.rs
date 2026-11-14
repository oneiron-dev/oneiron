//! The seven role presets and their default check-in mode per act class
//! (ARCH-0082 #role-defaults; ARCH-0043 #shared-vault-authority).

use serde::{Deserialize, Serialize};

use super::act_class::ActClass;
use super::mode::CheckInMode;
use crate::federation::{FederationGrantPreset, FederationGrantRole};

/// A role is a preset, never a rank: a set of powers plus a default mode per
/// act class. One role per actor per vault link. Viewer is not a role: it is
/// the label for a Member whose grant is narrowed to read (R4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolePreset {
    /// Every power in the vault. The holder may be a person or an agent.
    Owner,
    /// Admin's powers plus a Grant for delegated Owner powers, each Owner act
    /// carrying a check-in mode. Never holds the org root.
    Deputy,
    /// The fixed administrative allowlist.
    Admin,
    /// Reads and organises everything in this vault; proposes member changes.
    Steward,
    /// Works inside its scopes.
    Member,
    /// Works under a narrow Grant that expires.
    Delegate,
    /// Reads a scoped WORLD copy, or proposes back. Never a roster member.
    Guest,
}

impl RolePreset {
    /// Every preset, in table order (the column order of ARCH-0082's table).
    pub const ALL: [Self; 7] = [
        Self::Owner,
        Self::Deputy,
        Self::Admin,
        Self::Steward,
        Self::Member,
        Self::Delegate,
        Self::Guest,
    ];

    /// The stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Deputy => "deputy",
            Self::Admin => "admin",
            Self::Steward => "steward",
            Self::Member => "member",
            Self::Delegate => "delegate",
            Self::Guest => "guest",
        }
    }

    /// The preset a grant role reads its defaults from. Viewer reads the
    /// Member column; its grant narrows the powers.
    #[must_use]
    pub const fn of_grant_role(role: FederationGrantRole) -> Self {
        match role {
            FederationGrantRole::Owner => Self::Owner,
            FederationGrantRole::Deputy => Self::Deputy,
            FederationGrantRole::Admin => Self::Admin,
            FederationGrantRole::Steward => Self::Steward,
            FederationGrantRole::Member | FederationGrantRole::Viewer => Self::Member,
            FederationGrantRole::Delegate => Self::Delegate,
            FederationGrantRole::Guest => Self::Guest,
        }
    }

    /// This role's default for `act`.
    #[must_use]
    pub fn default_for(self, act: ActClass) -> RoleDefault {
        ROLE_DEFAULTS[act as usize][self as usize]
    }
}

#[doc(hidden)]
pub use oneiron_records::check_in::role_preset::RoleDefault;
#[doc(hidden)]
use oneiron_records::check_in::role_preset::{
    ASK, GO, NA, NAMED_ASK, NAMED_GO, NAMED_UNSURE, NO_VERB, OWN, OWN_VETO, PROPOSE, ROLE_DEFAULTS,
    UNSURE,
};

/// One row of [`ROLE_PRESET`]: the role and the grant preset that carries
/// its powers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RolePresetRow {
    pub role: RolePreset,
    /// The capability envelope of the role's grant. The Deputy rides the
    /// Admin envelope; its delegated Owner powers are the Owner-issued agent
    /// Grant it holds beside its membership (P24-SHAPE Q1 = A).
    pub powers: FederationGrantPreset,
}

/// The seven presets, in [`RolePreset::ALL`] order.
pub static ROLE_PRESET: [RolePresetRow; 7] = [
    RolePresetRow {
        role: RolePreset::Owner,
        powers: FederationGrantPreset::Owner,
    },
    RolePresetRow {
        role: RolePreset::Deputy,
        powers: FederationGrantPreset::Admin,
    },
    RolePresetRow {
        role: RolePreset::Admin,
        powers: FederationGrantPreset::Admin,
    },
    RolePresetRow {
        role: RolePreset::Steward,
        powers: FederationGrantPreset::Steward,
    },
    RolePresetRow {
        role: RolePreset::Member,
        powers: FederationGrantPreset::Member,
    },
    RolePresetRow {
        role: RolePreset::Delegate,
        powers: FederationGrantPreset::Delegate,
    },
    RolePresetRow {
        role: RolePreset::Guest,
        powers: FederationGrantPreset::Guest,
    },
];
