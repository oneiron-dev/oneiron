//! Stable token vocabulary for channel-identity selection law.

/// Version of the persisted selection rule-set record.
pub const CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION: u16 = 1;

/// `vault_meta` key holding the one selection rule set.
pub const CHANNEL_IDENTITY_SELECTION_KEY: &[u8] = b"channel_identity_selection:v1:rules";

/// Longest accepted `rule_id`, brief ref, or space ref.
const SELECTION_REF_MAX_BYTES: usize = 128;

/// The relationship context a message is being sent in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelationshipContext {
    WorkDeal,
    SchedulingLogistics,
    CampaignOutreach,
    TransactionalSystem,
    PersonalFriends,
    GroupSpace,
}

impl RelationshipContext {
    /// Every context, in the canonical order the builtins are compiled in.
    pub const ALL: [Self; 6] = [
        Self::WorkDeal,
        Self::SchedulingLogistics,
        Self::CampaignOutreach,
        Self::TransactionalSystem,
        Self::PersonalFriends,
        Self::GroupSpace,
    ];

    /// Stable on-disk spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkDeal => "work_deal",
            Self::SchedulingLogistics => "scheduling_logistics",
            Self::CampaignOutreach => "campaign_outreach",
            Self::TransactionalSystem => "transactional_system",
            Self::PersonalFriends => "personal_friends",
            Self::GroupSpace => "group_space",
        }
    }

    /// Parses the stable on-disk spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "work_deal" => Some(Self::WorkDeal),
            "scheduling_logistics" => Some(Self::SchedulingLogistics),
            "campaign_outreach" => Some(Self::CampaignOutreach),
            "transactional_system" => Some(Self::TransactionalSystem),
            "personal_friends" => Some(Self::PersonalFriends),
            "group_space" => Some(Self::GroupSpace),
            _ => None,
        }
    }
}

/// The semantic face a rule selects.
///
/// A face is a ROLE, not an addressing shape: several
/// [`ChannelIdentityShape`]s can wear one face, and the host classifies its own
/// identities into faces before asking for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelIdentityFace {
    DelegatedOwnerAccount,
    AgentNamedAddress,
    SideDomainAddress,
    HouseIdentity,
    CompanionIdentity,
    NamedGroupParticipant,
}

impl ChannelIdentityFace {
    /// Stable on-disk spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DelegatedOwnerAccount => "delegated_owner_account",
            Self::AgentNamedAddress => "agent_named_address",
            Self::SideDomainAddress => "side_domain_address",
            Self::HouseIdentity => "house_identity",
            Self::CompanionIdentity => "companion_identity",
            Self::NamedGroupParticipant => "named_group_participant",
        }
    }

    /// Parses the stable on-disk spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "delegated_owner_account" => Some(Self::DelegatedOwnerAccount),
            "agent_named_address" => Some(Self::AgentNamedAddress),
            "side_domain_address" => Some(Self::SideDomainAddress),
            "house_identity" => Some(Self::HouseIdentity),
            "companion_identity" => Some(Self::CompanionIdentity),
            "named_group_participant" => Some(Self::NamedGroupParticipant),
            _ => None,
        }
    }
}

/// Provenance class of whoever last wrote a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectionRuleWriterKind {
    /// Compiled vault law; never produced by a caller write.
    SystemDefault,
    Owner,
    Agent,
}

impl SelectionRuleWriterKind {
    /// Stable on-disk spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemDefault => "system_default",
            Self::Owner => "owner",
            Self::Agent => "agent",
        }
    }

    /// Parses the stable on-disk spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "system_default" => Some(Self::SystemDefault),
            "owner" => Some(Self::Owner),
            "agent" => Some(Self::Agent),
            _ => None,
        }
    }
}

pub(super) fn is_valid_ref_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SELECTION_REF_MAX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
