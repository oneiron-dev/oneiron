//! Resolution law for channel-identity selection: scope ladder, builtins, compile overlay, resolve query.

use crate::channel_identity::ChannelIdentityShape;
use crate::entity_id::EntityId;

use super::selection_rules::{ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet};
use super::selection_vocabulary::{
    CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION, ChannelIdentityFace, RelationshipContext,
    SelectionRuleWriterKind, is_valid_ref_token,
};

/// One host-classified identity the resolver may choose.
///
/// The host owns classification: it decides which of its `ChannelIdentity`
/// records wears which face, and this module never reads or writes those
/// records. `shape` is carried through untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityCandidate {
    pub identity_ref: EntityId,
    pub shape: ChannelIdentityShape,
    pub face: ChannelIdentityFace,
    pub active: bool,
}

/// A thread's already-established identity, supplied by ONE-1827.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityThreadPin {
    pub thread_ref: String,
    pub identity_ref: EntityId,
    pub facet_ref: Option<EntityId>,
}

/// One selection question.
pub struct ChannelIdentitySelectionQuery<'a> {
    pub relationship: RelationshipContext,
    /// Every scope key that applies right now. Order does not matter.
    pub applicable_scopes: &'a [SelectionRuleScope],
    pub candidates: &'a [ChannelIdentityCandidate],
    pub thread_pin: Option<&'a ChannelIdentityThreadPin>,
}

/// The resolved presentation identity.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// One amendment to the stored overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelIdentitySelectionPatch {
    Upsert(ChannelIdentitySelectionRule),
    Remove { rule_id: String },
}

/// Result alias for the selection law.
pub type ChannelIdentitySelectionResult<T> = std::result::Result<T, ChannelIdentitySelectionError>;

/// Typed failure surface. There is no silent-fallback branch anywhere below.
#[derive(Debug, thiserror::Error)]
pub enum ChannelIdentitySelectionError {
    #[error(transparent)]
    Storage(#[from] crate::error::Error),

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

/// The six compiled vault defaults, in canonical order.
///
/// The two rows that route to assets the owner cannot cheaply replace — the
/// owner's own delegated account and the companion face reserved for personal
/// ties — ship non-amendable, so an agent adds its own scoped rows instead of
/// quietly rewriting vault law. Nothing is banned: an owner may edit or unlock
/// every row, and an exact-identity override is always canonical.
#[must_use]
pub fn builtin_channel_identity_selection_rules() -> [ChannelIdentitySelectionRule; 6] {
    [
        builtin_rule(
            "builtin.work_deal",
            RelationshipContext::WorkDeal,
            ChannelIdentityFace::DelegatedOwnerAccount,
            false,
        ),
        builtin_rule(
            "builtin.scheduling_logistics",
            RelationshipContext::SchedulingLogistics,
            ChannelIdentityFace::AgentNamedAddress,
            true,
        ),
        builtin_rule(
            "builtin.campaign_outreach",
            RelationshipContext::CampaignOutreach,
            ChannelIdentityFace::SideDomainAddress,
            true,
        ),
        builtin_rule(
            "builtin.transactional_system",
            RelationshipContext::TransactionalSystem,
            ChannelIdentityFace::HouseIdentity,
            true,
        ),
        builtin_rule(
            "builtin.personal_friends",
            RelationshipContext::PersonalFriends,
            ChannelIdentityFace::CompanionIdentity,
            false,
        ),
        builtin_rule(
            "builtin.group_space",
            RelationshipContext::GroupSpace,
            ChannelIdentityFace::NamedGroupParticipant,
            true,
        ),
    ]
}

fn builtin_rule(
    rule_id: &str,
    relationship: RelationshipContext,
    face: ChannelIdentityFace,
    agent_amendable: bool,
) -> ChannelIdentitySelectionRule {
    ChannelIdentitySelectionRule {
        rule_id: rule_id.to_owned(),
        relationship,
        scope: SelectionRuleScope::VaultDefault,
        face,
        pinned_identity_ref: None,
        priority: 0,
        enabled: true,
        agent_amendable,
        updated_at: 0,
        updated_by: None,
        writer_kind: SelectionRuleWriterKind::SystemDefault,
    }
}

/// Lays a validated stored overlay over the compiled builtins.
///
/// `None` yields the six builtins at revision `0`.
pub fn compile_channel_identity_selection(
    stored: Option<&ChannelIdentitySelectionRuleSet>,
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
    let mut rows = builtin_channel_identity_selection_rules().to_vec();
    let Some(stored) = stored else {
        return Ok(ChannelIdentitySelectionRuleSet {
            schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
            revision: 0,
            rows,
        });
    };
    stored.validate_stored()?;
    for row in &stored.rows {
        match rows.iter().position(|seat| seat.rule_id == row.rule_id) {
            Some(index) => rows[index] = row.clone(),
            None => rows.push(row.clone()),
        }
    }
    let compiled = ChannelIdentitySelectionRuleSet {
        schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
        revision: stored.revision,
        rows,
    };
    compiled.validate()?;
    Ok(compiled)
}

/// Resolves one query against compiled law.
///
/// A valid thread pin wins before every mutable row. Otherwise the winning row
/// picks the face, and an active candidate wearing it is chosen by stable id
/// order — never by falling through to another face.
pub fn resolve_channel_identity_selection(
    compiled: &ChannelIdentitySelectionRuleSet,
    query: ChannelIdentitySelectionQuery<'_>,
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionDecision> {
    validate_candidates(query.candidates)?;
    for scope in query.applicable_scopes {
        scope.validate()?;
    }
    if let Some(pin) = query.thread_pin {
        return resolve_thread_pin(pin, query.candidates);
    }
    let winner = compiled
        .rows
        .iter()
        .filter(|row| row.applies_to(query.relationship, query.applicable_scopes))
        .max_by_key(|row| row.precedence())
        .ok_or(ChannelIdentitySelectionError::NoRuleForRelationship)?;
    let chosen = match winner.pinned_identity_ref {
        Some(pinned) => pinned_row_candidate(pinned, winner.face, query.candidates)?,
        None => face_candidate(winner.face, query.candidates)?,
    };
    Ok(ChannelIdentitySelectionDecision {
        identity_ref: chosen.identity_ref,
        facet_ref: None,
        face: chosen.face,
        shape: chosen.shape,
        rule_id: Some(winner.rule_id.clone()),
        used_thread_pin: false,
    })
}

fn validate_candidates(
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<()> {
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|earlier| earlier.identity_ref == candidate.identity_ref)
        {
            return Err(ChannelIdentitySelectionError::DuplicateCandidate);
        }
    }
    Ok(())
}

/// Honors an established thread identity verbatim.
fn resolve_thread_pin(
    pin: &ChannelIdentityThreadPin,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionDecision> {
    if !is_valid_ref_token(&pin.thread_ref) {
        return Err(ChannelIdentitySelectionError::MalformedThreadPin);
    }
    let candidate = active_candidate(pin.identity_ref, candidates)?;
    Ok(ChannelIdentitySelectionDecision {
        identity_ref: candidate.identity_ref,
        facet_ref: pin.facet_ref,
        face: candidate.face,
        shape: candidate.shape,
        rule_id: None,
        used_thread_pin: true,
    })
}

/// Resolves a row's exact-identity override.
///
/// The override names an identity, but the row still names a face; a candidate
/// that disagrees is a contradiction, not an invitation to switch faces.
fn pinned_row_candidate(
    pinned: EntityId,
    face: ChannelIdentityFace,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<&ChannelIdentityCandidate> {
    let candidate = active_candidate(pinned, candidates)?;
    if candidate.face == face {
        Ok(candidate)
    } else {
        Err(ChannelIdentitySelectionError::PinnedCandidateFaceMismatch)
    }
}

fn active_candidate(
    identity_ref: EntityId,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<&ChannelIdentityCandidate> {
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.identity_ref == identity_ref)
        .ok_or(ChannelIdentitySelectionError::PinnedCandidateMissing)?;
    if candidate.active {
        Ok(candidate)
    } else {
        Err(ChannelIdentitySelectionError::PinnedCandidateInactive)
    }
}

fn face_candidate(
    face: ChannelIdentityFace,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<&ChannelIdentityCandidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.active && candidate.face == face)
        .min_by_key(|candidate| candidate.identity_ref)
        .ok_or(ChannelIdentitySelectionError::NoCandidateForFace)
}

/// Where a rule applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    pub(super) fn validate(&self) -> ChannelIdentitySelectionResult<()> {
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
