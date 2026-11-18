//! Moved from `crates/oneiron/src/workspace_roster/records.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// Stable refs a completed onboarding produced.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct MemberOnboardingOutcome {
    /// Echo of the idempotency key.
    pub onboarding_id: String,
    /// The member `PERSON`.
    pub person_ref: EntityId,
    /// The member's `AGENT_DEF` actor.
    pub actor_ref: EntityId,
    /// The `(Member, Member)` federation grant.
    pub federation_grant_ref: EntityId,
    /// The companion `PERSON`, born here or brought.
    pub companion_person_ref: Option<EntityId>,
    /// The companion's `AGENT_DEF` actor, born here or brought.
    pub companion_actor_ref: Option<EntityId>,
    /// The workspace's policy is `suggest` and this member brought her own
    /// companion: a work companion is recommended. Advisory, never a refusal;
    /// read from the policy in force when the outcome is answered.
    pub work_companion_suggested: bool,
    /// The delegated mailbox identity, when one was bound.
    pub delegated_identity_ref: Option<EntityId>,
    /// The member's personal vault this onboarding linked on her roster
    /// row, when the host passed one in.
    pub personal_vault: Option<PersonalVaultLinkView>,
    /// Time the journal first reached [`MemberOnboardingStep::Complete`].
    pub completed_at: u64,
}

/// Where a member's linked personal vault came from (ARCH-0063:359
/// [INB-07]; Engine RULING INB-07-VAULT-LINK = A). The engine mints no vault
/// and holds no account: the host passes either kind in.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PersonalVaultOrigin {
    /// The member's own vault, which she brings (an Eiri user's).
    Brought,
    /// The vault the host minted for her under the org account.
    Minted,
}

impl PersonalVaultOrigin {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brought => "brought",
            Self::Minted => "minted",
        }
    }

    /// The origin `text` spells, if any.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "brought" => Some(Self::Brought),
            "minted" => Some(Self::Minted),
            _ => None,
        }
    }
}

/// A member's linked personal vault on the wire: the vault's durable id
/// (its genesis hash) as 64 lowercase hex, and where it came from.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PersonalVaultLinkView {
    pub vault: String,
    pub origin: PersonalVaultOrigin,
}

/// What a roster row is in the workplace.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WorkspaceRosterRole {
    /// The org given a pen.
    HouseMind,
    /// One principal's own companion.
    PrincipalCompanion,
}

impl WorkspaceRosterRole {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HouseMind => "house_mind",
            Self::PrincipalCompanion => "principal_companion",
        }
    }
}

/// One named persona visible in a workspace.
///
/// Memory scope is carried by `actor_ref` / `subject_ref` / `facet_ref` and the
/// grants around them. `display_name` is presentation only and never selects
/// what a persona can read.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct WorkspaceRosterEntry {
    /// Workspace this persona appears in.
    pub workspace_ref: String,
    /// House mind or principal companion.
    pub role: WorkspaceRosterRole,
    /// The principal this companion belongs to; `None` for the house mind.
    pub principal_ref: Option<EntityId>,
    /// The `AGENT_DEF` that speaks.
    pub actor_ref: EntityId,
    /// The `PERSON`/`ORG` standing behind `actor_ref`.
    pub subject_ref: EntityId,
    /// Work facet this persona wears, when it has one.
    pub facet_ref: Option<EntityId>,
    /// Channel identity this persona speaks through, when it has one.
    pub identity_ref: Option<EntityId>,
    /// Runtime display name. Never an engine constant.
    pub display_name: String,
}
