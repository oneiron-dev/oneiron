//! Stable token vocabulary for channel-identity selection law.

use oneiron_contracts::register::Register;

/// Version of the persisted selection rule-set record.
pub const CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION: u16 = 1;

/// `vault_meta` key holding the one selection rule set.
pub const CHANNEL_IDENTITY_SELECTION_KEY: &[u8] = b"channel_identity_selection:v1:rules";

/// Longest accepted `rule_id`, brief ref, or space ref.
const SELECTION_REF_MAX_BYTES: usize = 128;

/// The relationship context a message is being sent in.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("relationship.context")]
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

    /// Parses the stable on-disk spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}

/// The semantic face a rule selects.
///
/// A face is a ROLE, not an addressing shape: several
/// [`ChannelIdentityShape`](crate::channel_identity_shape::ChannelIdentityShape)s can wear one face, and the host classifies its own
/// identities into faces before asking for a decision.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("channel.identity.face")]
pub enum ChannelIdentityFace {
    DelegatedOwnerAccount,
    AgentNamedAddress,
    SideDomainAddress,
    HouseIdentity,
    CompanionIdentity,
    NamedGroupParticipant,
}

impl ChannelIdentityFace {
    /// Parses the stable on-disk spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}

/// Provenance class of whoever last wrote a row.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("selection.rule.writer.kind")]
pub enum SelectionRuleWriterKind {
    /// Compiled vault law; never produced by a caller write.
    SystemDefault,
    Owner,
    Agent,
}

impl SelectionRuleWriterKind {
    /// Parses the stable on-disk spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}

pub fn is_valid_ref_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SELECTION_REF_MAX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
