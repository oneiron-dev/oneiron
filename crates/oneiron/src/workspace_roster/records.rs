//! Pinned vault-meta prefixes, the step ladder, and stored roster/journal records.

use super::*;

/// Body schema version for every record this module writes.
pub const WORKSPACE_ROSTER_SCHEMA_VERSION: u64 = 1;

/// `vault_meta` prefix owned by the onboarding journal.
pub const WORKSPACE_ONBOARDING_KEY_PREFIX: &[u8] = b"workspace_roster:onboarding:v1:";

/// `vault_meta` prefix owned by the per-workspace preset row.
pub const WORKSPACE_ROSTER_PRESET_KEY_PREFIX: &[u8] = b"workspace_roster:preset:v1:";

/// `vault_meta` prefix owned by the per-member roster row.
///
/// Full key is `prefix ++ workspace_ref ++ 0x00 ++ member_person_hex`. The NUL
/// separator is unambiguous because `WorkspaceRosterPreset::validate` refuses
/// a `workspace_ref` containing one.
pub const WORKSPACE_ROSTER_MEMBER_KEY_PREFIX: &[u8] = b"workspace_roster:member:v1:";

/// Upper bound on every caller-supplied name/reference string in this module.
pub(super) const MAX_NAME_BYTES: usize = 256;

/// Byte that separates `workspace_ref` from the member id in a roster key.
pub(super) const ROSTER_KEY_SEPARATOR: u8 = 0x00;

/// Ordered onboarding progress marker.
///
/// The rank order is the pinned step order; a journal never moves backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberOnboardingStep {
    /// Inputs reserved before the first write door; no step is complete yet.
    Started,
    /// Entity kinds checked, house mind anchored, preset row settled.
    Validated,
    /// Member actor defined and anchored to the member `PERSON`.
    ActorLinked,
    /// `(Member, Member)` federation grant written.
    MemberGranted,
    /// Required companion person/actor/facet/record/grant written.
    CompanionBorn,
    /// Delegated mailbox bound and its exact autonomy verified, when requested.
    MailboxBound,
    /// Roster row written; the outcome is final.
    Complete,
}

impl MemberOnboardingStep {
    /// Pinned on-disk step spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Validated => "validated",
            Self::ActorLinked => "actor_linked",
            Self::MemberGranted => "member_granted",
            Self::CompanionBorn => "companion_born",
            Self::MailboxBound => "mailbox_bound",
            Self::Complete => "complete",
        }
    }

    /// Parses a pinned step spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "started" => Some(Self::Started),
            "validated" => Some(Self::Validated),
            "actor_linked" => Some(Self::ActorLinked),
            "member_granted" => Some(Self::MemberGranted),
            "companion_born" => Some(Self::CompanionBorn),
            "mailbox_bound" => Some(Self::MailboxBound),
            "complete" => Some(Self::Complete),
            _ => None,
        }
    }

    /// Position in the pinned order, counting from 1.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Started => 0,
            Self::Validated => 1,
            Self::ActorLinked => 2,
            Self::MemberGranted => 3,
            Self::CompanionBorn => 4,
            Self::MailboxBound => 5,
            Self::Complete => 6,
        }
    }
}

/// The pinned step order the runner walks.
pub(super) const ONBOARDING_STEPS: [MemberOnboardingStep; 6] = [
    MemberOnboardingStep::Validated,
    MemberOnboardingStep::ActorLinked,
    MemberOnboardingStep::MemberGranted,
    MemberOnboardingStep::CompanionBorn,
    MemberOnboardingStep::MailboxBound,
    MemberOnboardingStep::Complete,
];

/// Stable refs a completed onboarding produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberOnboardingOutcome {
    /// Echo of the idempotency key.
    pub onboarding_id: String,
    /// The member `PERSON`.
    pub person_ref: EntityId,
    /// The member's `AGENT_DEF` actor.
    pub actor_ref: EntityId,
    /// The `(Member, Member)` federation grant.
    pub federation_grant_ref: EntityId,
    /// The companion `PERSON`, when one was born.
    pub companion_person_ref: Option<EntityId>,
    /// The companion's `AGENT_DEF` actor, when one was born.
    pub companion_actor_ref: Option<EntityId>,
    /// The delegated mailbox identity, when one was bound.
    pub delegated_identity_ref: Option<EntityId>,
    /// Time the journal first reached [`MemberOnboardingStep::Complete`].
    pub completed_at: u64,
}

/// What a roster row is in the workplace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A member roster row as stored under [`WORKSPACE_ROSTER_MEMBER_KEY_PREFIX`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RosterMemberRow {
    pub(super) person_ref: EntityId,
    pub(super) actor_ref: EntityId,
    pub(super) companion_person_ref: Option<EntityId>,
    pub(super) companion_actor_ref: Option<EntityId>,
    pub(super) companion_facet_ref: Option<EntityId>,
    pub(super) identity_ref: Option<EntityId>,
}

/// A journal record as stored under [`WORKSPACE_ONBOARDING_KEY_PREFIX`].
///
/// Deliberately does NOT store outcome refs: every ref is caller-supplied, so
/// the outcome is derivable from the intent whose digest this record pins. Two
/// copies of the same refs could disagree; one cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OnboardingJournal {
    pub(super) intent_digest: [u8; 32],
    pub(super) step: MemberOnboardingStep,
    pub(super) completed_at: Option<u64>,
}
