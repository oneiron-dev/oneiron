//! Moved from `crates/oneiron/src/channel_identity_selection/selection_resolution.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity_selection::selection_rules::ChannelIdentitySelectionRule;
use crate::channel_identity_selection::selection_rules::ChannelIdentitySelectionRuleSet;
use oneiron_authority::channel_identity_shape::ChannelIdentityShape;
use oneiron_authority::channel_selection_vocabulary::CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION;
use oneiron_authority::channel_selection_vocabulary::ChannelIdentityFace;
use oneiron_authority::channel_selection_vocabulary::RelationshipContext;
use oneiron_authority::channel_selection_vocabulary::SelectionRuleWriterKind;
use oneiron_authority::channel_selection_vocabulary::is_valid_ref_token;
use oneiron_contracts::entity_id::EntityId;

/// The resolved presentation identity.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentitySelectionDecision {
    pub identity_ref: EntityId,
    pub facet_ref: Option<EntityId>,
    pub face: ChannelIdentityFace,
    /// The chosen candidate's shape, carried through unchanged.
    ///
    /// Beyond the blueprint skeleton on purpose: ONE-1827 records thread
    /// continuity against the identity this decision names, and without the
    /// shape it would have to re-read the `ChannelIdentity` record to learn
    /// whether the thread is anchored to a self-held mailbox or a
    /// [`ChannelIdentityShape::DelegatedGrant`] the product does not own.
    pub shape: ChannelIdentityShape,
    /// `None` exactly when the decision came from a thread pin.
    pub rule_id: Option<String>,
    pub used_thread_pin: bool,
}

/// Result alias for the selection law.
pub type ChannelIdentitySelectionResult<T> = std::result::Result<T, ChannelIdentitySelectionError>;

/// Typed failure surface. There is no silent-fallback branch anywhere below.
#[derive(Debug, thiserror::Error)]
pub enum ChannelIdentitySelectionError {
    #[error(transparent)]
    Storage(#[from] oneiron_base::error::Error),

    #[error("channel identity selection rule set is malformed: {0}")]
    MalformedRuleSet(&'static str),

    #[error("channel identity selection rule is invalid: {0}")]
    InvalidRule(&'static str),

    #[error("channel identity selection scope is malformed")]
    MalformedScope,

    #[error("channel identity selection entity reference is invalid")]
    InvalidEntityRef,

    #[error(
        "channel identity selection schema version mismatch: expected {expected}, stored {stored}"
    )]
    SchemaVersionMismatch { expected: u16, stored: u16 },

    #[error("channel identity selection rule ids are not unique")]
    DuplicateRuleId,

    #[error("two vault-default channel identity selection rules claim one relationship context")]
    DuplicateCanonicalWinner,

    #[error("channel identity selection revision conflict: expected {expected}, stored {stored}")]
    RevisionConflict { expected: u64, stored: u64 },

    #[error("channel identity selection revision {stored} regressed below {floor}")]
    RevisionRegressed { stored: u64, floor: u64 },

    #[error("channel identity selection revision would overflow")]
    RevisionOverflow,

    #[error("this actor class cannot amend channel identity selection rules")]
    WriterClassNotAmendable,

    #[error("the owner amends channel identity selection rules only with an owner proof")]
    OwnerWriterNeedsOwnerProof,

    #[error("the channel identity selection writer is not a live actor of this vault")]
    WriterNotInVault,

    #[error("channel identity selection rule is not agent-amendable")]
    RuleNotAgentAmendable,

    #[error("an agent writer cannot lock a channel identity selection rule")]
    AgentCannotLockRule,

    #[error("channel identity selection rule not found")]
    RuleNotFound,

    #[error("a built-in channel identity selection rule cannot be removed")]
    BuiltinRuleNotRemovable,

    #[error("no channel identity selection rule matches this relationship context")]
    NoRuleForRelationship,

    #[error("no active candidate wears the selected channel identity face")]
    NoCandidateForFace,

    #[error("the pinned channel identity candidate is missing")]
    PinnedCandidateMissing,

    #[error("the pinned channel identity candidate is not active")]
    PinnedCandidateInactive,

    #[error("the pinned channel identity candidate does not wear the rule's face")]
    PinnedCandidateFaceMismatch,

    #[error("channel identity candidates are not unique")]
    DuplicateCandidate,

    #[error("the channel identity thread pin is malformed")]
    MalformedThreadPin,
}

/// Where a rule applies.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelectionRuleScope {
    /// Applies to every query for its relationship context.
    VaultDefault,
    World {
        world_ref: EntityId,
    },
    Relationship {
        relationship_ref: EntityId,
    },
    Brief {
        brief_ref: String,
    },
    Space {
        space_ref: String,
    },
}

impl SelectionRuleScope {
    /// Stable on-disk `kind` token.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::VaultDefault => "vault_default",
            Self::World { .. } => "world",
            Self::Relationship { .. } => "relationship",
            Self::Brief { .. } => "brief",
            Self::Space { .. } => "space",
        }
    }

    /// Specificity rank; a higher rank outranks a lower one.
    ///
    /// The ladder runs from the broadest container to the narrowest: the vault
    /// as a whole, then one world, then one space inside it, then one brief of
    /// work, then one counterparty relationship.
    #[must_use]
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::VaultDefault => 0,
            Self::World { .. } => 1,
            Self::Space { .. } => 2,
            Self::Brief { .. } => 3,
            Self::Relationship { .. } => 4,
        }
    }

    /// Whether this scope is the vault-wide default.
    #[must_use]
    pub const fn is_vault_default(&self) -> bool {
        matches!(self, Self::VaultDefault)
    }

    pub fn validate(&self) -> ChannelIdentitySelectionResult<()> {
        let text = match self {
            Self::VaultDefault | Self::World { .. } | Self::Relationship { .. } => return Ok(()),
            Self::Brief { brief_ref } => brief_ref,
            Self::Space { space_ref } => space_ref,
        };
        if is_valid_ref_token(text) {
            Ok(())
        } else {
            Err(ChannelIdentitySelectionError::MalformedScope)
        }
    }
}
