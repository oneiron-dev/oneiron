//! Pinned vault-meta prefixes, the step ladder, and stored roster/journal records.

use super::*;

/// Body schema version for every record this module writes.
pub const WORKSPACE_ROSTER_SCHEMA_VERSION: u64 = 1;

/// Idempotency journal tracking one member-onboarding request's progress
/// through the pinned step ladder. Key: caller-supplied onboarding id.
pub(super) const ONBOARDING: SideTable<String, OnboardingJournalRow, Raw> =
    SideTable::new(&side_table::WORKSPACE_ONBOARDING);

/// Per-workspace roster preset (org, venture name, house actor/identity, house
/// display name). Key: workspace_ref.
pub(super) const PRESET: SideTable<String, WorkspaceRosterPreset, Raw> =
    SideTable::new(&side_table::WORKSPACE_ROSTER_PRESET);

/// One onboarded member's roster row (actor, optional companion
/// person/actor/facet, identity). Key: [`RosterMemberKey`].
pub(super) const MEMBER: SideTable<RosterMemberKey, RosterMemberRow, Raw> =
    SideTable::new(&side_table::WORKSPACE_ROSTER_MEMBER);

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

/// A member roster row as stored under [`MEMBER`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RosterMemberRow {
    pub(super) person_ref: EntityId,
    pub(super) actor_ref: EntityId,
    pub(super) companion_person_ref: Option<EntityId>,
    pub(super) companion_actor_ref: Option<EntityId>,
    pub(super) companion_facet_ref: Option<EntityId>,
    pub(super) identity_ref: Option<EntityId>,
}

impl RawValue for RosterMemberRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_value(&roster_member_value(self))?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_roster_member_row(bytes)?)
    }
}

/// The bytes after [`MEMBER`]'s declared prefix: `workspace_ref` then a NUL separator then the
/// member person id as 32 lower-case hex characters. The NUL is unambiguous because
/// [`WorkspaceRosterPreset::validate`] refuses a `workspace_ref` containing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RosterMemberKey {
    pub(super) workspace_ref: String,
    pub(super) person_ref: EntityId,
}

impl SideKey for RosterMemberKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.workspace_ref.as_bytes());
        out.push(ROSTER_KEY_SEPARATOR);
        out.extend_from_slice(self.person_ref.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let separator = bytes
            .iter()
            .position(|&byte| byte == ROSTER_KEY_SEPARATOR)?;
        let workspace_ref = String::from_utf8(bytes[..separator].to_vec()).ok()?;
        let HexId(person_ref) = HexId::decode_key(&bytes[separator + 1..])?;
        Some(Self {
            workspace_ref,
            person_ref,
        })
    }
}

/// A journal record as stored under [`ONBOARDING`].
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

/// The on-disk shape of one [`ONBOARDING`] row: the journal plus the
/// caller-supplied onboarding id it was written under. Every row this module
/// has ever written carries the id, so it stays on the wire type; the
/// in-memory [`OnboardingJournal`] a caller reads back never needs to
/// re-derive its own lookup key, so it stays off that struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OnboardingJournalRow {
    pub(super) onboarding_id: String,
    pub(super) intent_digest: [u8; 32],
    pub(super) step: MemberOnboardingStep,
    pub(super) completed_at: Option<u64>,
}

impl OnboardingJournalRow {
    pub(super) fn into_journal(self) -> OnboardingJournal {
        OnboardingJournal {
            intent_digest: self.intent_digest,
            step: self.step,
            completed_at: self.completed_at,
        }
    }
}

impl RawValue for OnboardingJournalRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_value(&Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
            ),
            (
                Value::from("onboarding_id"),
                Value::from(self.onboarding_id.as_str()),
            ),
            (
                Value::from("intent_digest"),
                Value::Binary(self.intent_digest.to_vec()),
            ),
            (Value::from("step"), Value::from(self.step.as_str())),
            (
                Value::from("completed_at"),
                self.completed_at.map_or(Value::Nil, Value::from),
            ),
        ]))?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let entries = decode_map(bytes)?;
        if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
            return Err(invalid("onboarding journal schema_version is unsupported").into());
        }
        let onboarding_id = required_str(&entries, "onboarding_id")?;
        let digest_bytes = match required(&entries, "intent_digest")? {
            Value::Binary(bytes) => bytes.clone(),
            _ => return Err(invalid("onboarding journal intent_digest must be binary").into()),
        };
        let intent_digest: [u8; 32] = digest_bytes
            .try_into()
            .map_err(|_| invalid("onboarding journal intent_digest must be 32 bytes"))?;
        let step = required(&entries, "step")?
            .as_str()
            .and_then(MemberOnboardingStep::parse)
            .ok_or_else(|| invalid("onboarding journal step is unrecognized"))?;
        let completed_at = match required(&entries, "completed_at")? {
            Value::Nil => None,
            value => Some(
                value
                    .as_u64()
                    .ok_or_else(|| invalid("onboarding journal completed_at must be a u64"))?,
            ),
        };
        if (step == MemberOnboardingStep::Complete) != completed_at.is_some() {
            return Err(invalid("onboarding journal completion fields disagree").into());
        }
        Ok(Self {
            onboarding_id,
            intent_digest,
            step,
            completed_at,
        })
    }
}
