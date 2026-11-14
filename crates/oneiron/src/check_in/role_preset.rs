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

/// One cell of the role table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleDefault {
    /// The role holds the power; this is its default mode.
    Mode(CheckInMode),
    /// The role holds the power only when its Grant names it; then this mode.
    IfNamed(CheckInMode),
    /// The role acts on its own proof (the Owner on a catastrophe row).
    OwnProof,
    /// As [`Self::OwnProof`], with the veto window as the delay-window proof
    /// when the vault has two or more Owners.
    OwnProofWithVetoWindow,
    /// No power; the role may open a proposal to a holder.
    Propose,
    /// No verb.
    NoVerb,
    /// Not applicable: the Owner already holds every power.
    NotApplicable,
}

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

const GO: RoleDefault = RoleDefault::Mode(CheckInMode::NeverAsk);
const UNSURE: RoleDefault = RoleDefault::Mode(CheckInMode::AskWhenUnsure);
const ASK: RoleDefault = RoleDefault::Mode(CheckInMode::AlwaysAsk);
const NAMED_GO: RoleDefault = RoleDefault::IfNamed(CheckInMode::NeverAsk);
const NAMED_ASK: RoleDefault = RoleDefault::IfNamed(CheckInMode::AlwaysAsk);
const NAMED_UNSURE: RoleDefault = RoleDefault::IfNamed(CheckInMode::AskWhenUnsure);
const OWN: RoleDefault = RoleDefault::OwnProof;
const OWN_VETO: RoleDefault = RoleDefault::OwnProofWithVetoWindow;
const PROPOSE: RoleDefault = RoleDefault::Propose;
const NO_VERB: RoleDefault = RoleDefault::NoVerb;
const NA: RoleDefault = RoleDefault::NotApplicable;

/// ARCH-0082's role table: one row per act class in [`ActClass::ALL`] order,
/// one column per role in [`RolePreset::ALL`] order. Qualifiers the cells
/// carry in canon ("with step-up", "in scope", "own items", "named powers
/// only") are grant-scope and proof facts, not modes.
///
/// Rows canon leaves out: `Spawn` carries the shipped fan-out default (ask
/// when unsure) for every role but Guest; `RoomAdd` is ask when unsure for
/// every role that adds to rooms, as canon says of an agent's add (a Delegate
/// only when its Grant names it; a closed room's own ask is a room rule, not
/// a default); the four floor rows outside the main table, and the protected
/// ref's rewrite or delete (L8-51), follow the C rule (`AlwaysAsk` for every
/// role but Owner).
#[rustfmt::skip]
static ROLE_DEFAULTS: [[RoleDefault; 7]; 21] = [
    // Columns: Owner, Deputy, Admin, Steward, Member, Delegate, Guest.
    [GO, GO, GO, GO, GO, GO, PROPOSE],                    // ReversibleWork
    [UNSURE, UNSURE, UNSURE, UNSURE, UNSURE, UNSURE, NO_VERB], // Spawn
    [GO, UNSURE, PROPOSE, PROPOSE, PROPOSE, PROPOSE, NO_VERB], // SpendOverCap
    [GO, UNSURE, ASK, NO_VERB, ASK, NAMED_ASK, NO_VERB],  // OutboundSend
    [UNSURE, UNSURE, UNSURE, UNSURE, UNSURE, NAMED_UNSURE, NO_VERB], // RoomAdd
    [GO, UNSURE, GO, PROPOSE, NO_VERB, NO_VERB, NO_VERB], // MemberAdd
    [GO, ASK, GO, PROPOSE, NO_VERB, NO_VERB, NO_VERB],    // MemberRemove
    [GO, UNSURE, PROPOSE, NO_VERB, NO_VERB, NAMED_ASK, NO_VERB], // LegalSend
    [OWN, ASK, NO_VERB, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // Sign
    [GO, UNSURE, PROPOSE, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // Billing
    [GO, UNSURE, GO, PROPOSE, GO, NAMED_GO, NO_VERB],     // Delete
    [OWN_VETO, ASK, NO_VERB, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // VaultDelete
    [OWN_VETO, ASK, PROPOSE, PROPOSE, PROPOSE, PROPOSE, PROPOSE], // Erase
    [OWN, ASK, NO_VERB, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // OwnershipTransfer
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // KeyRecovery
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // SecurityControlDisable
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // MassSecretExport
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // WorldWiden
    [GO, UNSURE, GO, PROPOSE, PROPOSE, NO_VERB, NO_VERB], // GrantWiden
    [NA, ASK, ASK, ASK, ASK, NO_VERB, NO_VERB],           // GrantWidenOwn
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // ProtectedRefRewriteOrDelete
];
