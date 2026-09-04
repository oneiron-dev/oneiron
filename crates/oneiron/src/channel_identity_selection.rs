//! Relationship-context channel-identity selection law (ONE-1826).
//!
//! One generic, vault-resident policy: given a relationship context and a
//! roster of host-classified candidate identities, choose which FACE the vault
//! presents. The law lives in `vault_meta` under
//! [`CHANNEL_IDENTITY_SELECTION_KEY`] as one strict-MessagePack rule set with a
//! schema version, a monotonic revision, and owner/agent-editable rows.
//!
//! # What this module is not
//!
//! Selection never mutates a `ChannelIdentity` record, never mints another
//! identity kind, and never grants or checks egress authority — authority is
//! the Gate's policy zone. It is also not a customization preference blob: a
//! rule table that decides which mailbox speaks for the owner is audited law,
//! so every write is compare-and-swap by revision and carries a derived
//! provenance stamp. Consent posture is ONE-1829; thread continuity is
//! ONE-1827 (which consumes [`ChannelIdentityThreadPin`] defined here).
//!
//! # Two roles for one rule-set type
//!
//! [`ChannelIdentitySelectionRuleSet`] wears two hats:
//!
//! * the **stored overlay** — only the rows an owner or agent has written,
//!   persisted under [`CHANNEL_IDENTITY_SELECTION_KEY`] with `revision >= 1`;
//! * the **compiled law** — [`compile_channel_identity_selection`] laying that
//!   overlay over [`builtin_channel_identity_selection_rules`]. A fresh vault
//!   compiles to the six builtins at `revision == 0`, which is also the
//!   `expected_revision` a first write must present.
//!
//! An overlay row whose `rule_id` matches a builtin REPLACES that builtin in
//! place; every other overlay row is appended. That is what keeps a builtin
//! owner-editable without deleting compiled law: an owner disables a builtin by
//! upserting a shadow with `enabled = false`, never by removing it.
//!
//! # Fails typed, never falls through
//!
//! Missing, malformed, duplicate, or revision-regressed storage is an error,
//! not permission to pick an arbitrary identity. "No active candidate wears the
//! selected face" is likewise a typed unresolved decision for the caller to
//! surface — never a licence to reach for a more valuable owner identity.

use std::cmp::Reverse;
use std::io::Cursor;

use heed::RoTxn;
use rmpv::Value;

use crate::Vault;
use crate::channel_identity::ChannelIdentityShape;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::overlay_db::OverlayDb;
use crate::write_envelope::WriteActor;

/// Version of the persisted selection rule-set record.
pub const CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION: u16 = 1;

/// `vault_meta` key holding the one selection rule set.
pub const CHANNEL_IDENTITY_SELECTION_KEY: &[u8] = b"channel_identity_selection:v1:rules";

/// Longest accepted `rule_id`, brief ref, or space ref.
const SELECTION_REF_MAX_BYTES: usize = 128;

/// Canonical field order of the persisted rule-set map.
const RULE_SET_KEYS: [&str; 3] = ["schema_version", "revision", "rows"];

/// Canonical field order of one persisted rule map.
const RULE_KEYS: [&str; 11] = [
    "rule_id",
    "relationship",
    "scope",
    "face",
    "pinned_identity_ref",
    "priority",
    "enabled",
    "agent_amendable",
    "updated_at",
    "updated_by",
    "writer_kind",
];

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

    fn validate(&self) -> ChannelIdentitySelectionResult<()> {
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

/// An authenticated writer of selection rules.
///
/// The only constructor is [`Self::from_authenticated_write`], so a writer kind
/// is always DERIVED from an authenticated [`WriteActor`] and can never arrive
/// as caller-supplied data. There is deliberately no way to mint a
/// [`SelectionRuleWriterKind::SystemDefault`] writer: compiled law is not
/// something a caller writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentitySelectionWriter {
    actor_ref: EntityId,
    kind: SelectionRuleWriterKind,
}

impl ChannelIdentitySelectionWriter {
    /// Derives a writer from an authenticated write actor.
    ///
    /// `Human` writes as the owner, `Agent` writes as an agent, and `System`
    /// is refused: an unattended process has no standing to rewrite the law
    /// that decides which face the vault wears.
    pub fn from_authenticated_write(actor: &WriteActor) -> ChannelIdentitySelectionResult<Self> {
        let kind = match actor.actor_class() {
            EdgeActorClass::Human => SelectionRuleWriterKind::Owner,
            EdgeActorClass::Agent => SelectionRuleWriterKind::Agent,
            EdgeActorClass::System => {
                return Err(ChannelIdentitySelectionError::WriterClassNotAmendable);
            }
        };
        Ok(Self {
            actor_ref: actor.entity_ref(),
            kind,
        })
    }

    /// Entity stamped into every row this writer touches.
    #[must_use]
    pub const fn actor_ref(&self) -> EntityId {
        self.actor_ref
    }

    /// Derived provenance class.
    #[must_use]
    pub const fn kind(&self) -> SelectionRuleWriterKind {
        self.kind
    }
}

/// One selection row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentitySelectionRule {
    pub rule_id: String,
    pub relationship: RelationshipContext,
    pub scope: SelectionRuleScope,
    pub face: ChannelIdentityFace,
    /// Scoped override: an exact identity that must wear `face`.
    pub pinned_identity_ref: Option<EntityId>,
    pub priority: i32,
    /// A disabled row is inert: it never wins and never counts as a canonical
    /// winner, which is how an owner retires a builtin without deleting it.
    pub enabled: bool,
    pub agent_amendable: bool,
    pub updated_at: u64,
    /// `None` exactly when `writer_kind` is
    /// [`SelectionRuleWriterKind::SystemDefault`].
    pub updated_by: Option<EntityId>,
    pub writer_kind: SelectionRuleWriterKind,
}

impl ChannelIdentitySelectionRule {
    fn validate(&self) -> ChannelIdentitySelectionResult<()> {
        if !is_valid_ref_token(&self.rule_id) {
            return Err(ChannelIdentitySelectionError::InvalidRule(
                "rule_id must be a non-empty bounded ASCII token",
            ));
        }
        self.scope.validate()?;
        let system_default = self.writer_kind == SelectionRuleWriterKind::SystemDefault;
        if system_default != self.updated_by.is_none() {
            return Err(ChannelIdentitySelectionError::InvalidRule(
                "only a system-default row may omit updated_by",
            ));
        }
        Ok(())
    }

    /// Whether this row can win a query carrying `scopes`.
    fn applies_to(&self, relationship: RelationshipContext, scopes: &[SelectionRuleScope]) -> bool {
        self.enabled
            && self.relationship == relationship
            && (self.scope.is_vault_default() || scopes.contains(&self.scope))
    }

    /// Total precedence key: specificity, then priority, then recency, then
    /// the lexically smallest `rule_id`. Row ids are unique in a validated
    /// set, so the key is unique and the winner is order-independent.
    fn precedence(&self) -> (u8, i32, u64, Reverse<&str>) {
        (
            self.scope.specificity(),
            self.priority,
            self.updated_at,
            Reverse(self.rule_id.as_str()),
        )
    }
}

/// The persisted overlay, or the compiled law. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentitySelectionRuleSet {
    pub schema_version: u16,
    pub revision: u64,
    pub rows: Vec<ChannelIdentitySelectionRule>,
}

impl ChannelIdentitySelectionRuleSet {
    /// Structural validation shared by the stored overlay and the compiled law.
    fn validate(&self) -> ChannelIdentitySelectionResult<()> {
        if self.schema_version != CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION {
            return Err(ChannelIdentitySelectionError::SchemaVersionMismatch {
                expected: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
                stored: self.schema_version,
            });
        }
        for (index, row) in self.rows.iter().enumerate() {
            row.validate()?;
            if self.rows[..index]
                .iter()
                .any(|earlier| earlier.rule_id == row.rule_id)
            {
                return Err(ChannelIdentitySelectionError::DuplicateRuleId);
            }
        }
        self.validate_canonical_winners()
    }

    /// Exactly one enabled vault-default row may claim each relationship
    /// context. Exact-scope rows may stack; precedence orders them.
    fn validate_canonical_winners(&self) -> ChannelIdentitySelectionResult<()> {
        for context in RelationshipContext::ALL {
            let winners = self
                .rows
                .iter()
                .filter(|row| {
                    row.enabled && row.relationship == context && row.scope.is_vault_default()
                })
                .count();
            if winners > 1 {
                return Err(ChannelIdentitySelectionError::DuplicateCanonicalWinner);
            }
        }
        Ok(())
    }

    /// Validation for a record that claims to have been persisted.
    ///
    /// Revision `0` means "never amended" and is reserved for the compiled
    /// defaults, so a stored record at `0` has regressed below the baseline it
    /// was written above.
    fn validate_stored(&self) -> ChannelIdentitySelectionResult<()> {
        if self.revision < FIRST_STORED_REVISION {
            return Err(ChannelIdentitySelectionError::RevisionRegressed {
                stored: self.revision,
                floor: FIRST_STORED_REVISION,
            });
        }
        self.validate()
    }
}

/// Revision of the first persisted overlay; the compiled defaults sit at `0`.
const FIRST_STORED_REVISION: u64 = 1;

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

fn is_valid_ref_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SELECTION_REF_MAX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

// ---------------------------------------------------------------------------
// Strict MessagePack codec
// ---------------------------------------------------------------------------

/// Encodes the stored overlay in canonical field order.
fn encode_rule_set(
    set: &ChannelIdentitySelectionRuleSet,
) -> ChannelIdentitySelectionResult<Vec<u8>> {
    set.validate_stored()?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rule_set_value(set)).map_err(|_| {
        ChannelIdentitySelectionError::MalformedRuleSet("rule set could not be encoded")
    })?;
    Ok(bytes)
}

fn rule_set_value(set: &ChannelIdentitySelectionRuleSet) -> Value {
    Value::Map(vec![
        (
            Value::from(RULE_SET_KEYS[0]),
            Value::from(u64::from(set.schema_version)),
        ),
        (Value::from(RULE_SET_KEYS[1]), Value::from(set.revision)),
        (
            Value::from(RULE_SET_KEYS[2]),
            Value::Array(set.rows.iter().map(rule_value).collect()),
        ),
    ])
}

fn rule_value(rule: &ChannelIdentitySelectionRule) -> Value {
    Value::Map(vec![
        (
            Value::from(RULE_KEYS[0]),
            Value::from(rule.rule_id.as_str()),
        ),
        (
            Value::from(RULE_KEYS[1]),
            Value::from(rule.relationship.as_str()),
        ),
        (Value::from(RULE_KEYS[2]), scope_value(&rule.scope)),
        (Value::from(RULE_KEYS[3]), Value::from(rule.face.as_str())),
        (
            Value::from(RULE_KEYS[4]),
            optional_entity_value(rule.pinned_identity_ref),
        ),
        (Value::from(RULE_KEYS[5]), Value::from(rule.priority)),
        (Value::from(RULE_KEYS[6]), Value::from(rule.enabled)),
        (Value::from(RULE_KEYS[7]), Value::from(rule.agent_amendable)),
        (Value::from(RULE_KEYS[8]), Value::from(rule.updated_at)),
        (
            Value::from(RULE_KEYS[9]),
            optional_entity_value(rule.updated_by),
        ),
        (
            Value::from(RULE_KEYS[10]),
            Value::from(rule.writer_kind.as_str()),
        ),
    ])
}

fn scope_value(scope: &SelectionRuleScope) -> Value {
    let mut entries = vec![(Value::from("kind"), Value::from(scope.kind_str()))];
    match scope {
        SelectionRuleScope::VaultDefault => {}
        SelectionRuleScope::World { world_ref } => {
            entries.push((Value::from("world_ref"), entity_value(*world_ref)));
        }
        SelectionRuleScope::Relationship { relationship_ref } => {
            entries.push((
                Value::from("relationship_ref"),
                entity_value(*relationship_ref),
            ));
        }
        SelectionRuleScope::Brief { brief_ref } => {
            entries.push((Value::from("brief_ref"), Value::from(brief_ref.as_str())));
        }
        SelectionRuleScope::Space { space_ref } => {
            entries.push((Value::from("space_ref"), Value::from(space_ref.as_str())));
        }
    }
    Value::Map(entries)
}

fn entity_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn optional_entity_value(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, entity_value)
}

/// Decodes a stored overlay, rejecting every shape two decoders could read
/// differently: invalid MessagePack, trailing bytes, a non-map root, non-string
/// keys, unknown or missing or reordered or duplicated keys, bad enum tokens,
/// malformed scopes, and invalid entity references.
fn decode_rule_set(raw: &[u8]) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
    let mut cursor = Cursor::new(raw);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| ChannelIdentitySelectionError::MalformedRuleSet("not valid MessagePack"))?;
    if cursor.position() != raw.len() as u64 {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(
            "trailing bytes after rule set map",
        ));
    }
    let fields = strict_fields(&value, &RULE_SET_KEYS, "rule set map")?;
    let schema_version = fields[0]
        .as_u64()
        .and_then(|raw| u16::try_from(raw).ok())
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
            "schema_version must be a u16",
        ))?;
    let revision = fields[1]
        .as_u64()
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
            "revision must be a u64",
        ))?;
    let Value::Array(raw_rows) = fields[2] else {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(
            "rows must be an array",
        ));
    };
    let mut rows = Vec::with_capacity(raw_rows.len());
    for raw_row in raw_rows {
        rows.push(rule_from_value(raw_row)?);
    }
    let set = ChannelIdentitySelectionRuleSet {
        schema_version,
        revision,
        rows,
    };
    set.validate_stored()?;
    Ok(set)
}

fn rule_from_value(value: &Value) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRule> {
    let fields = strict_fields(value, &RULE_KEYS, "rule map")?;
    let rule =
        ChannelIdentitySelectionRule {
            rule_id: token(fields[0], "rule_id must be a string")?.to_owned(),
            relationship: RelationshipContext::parse(token(
                fields[1],
                "relationship must be a string",
            )?)
            .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                "unknown relationship context token",
            ))?,
            scope: scope_from_value(fields[2])?,
            face: ChannelIdentityFace::parse(token(fields[3], "face must be a string")?).ok_or(
                ChannelIdentitySelectionError::MalformedRuleSet("unknown face token"),
            )?,
            pinned_identity_ref: optional_entity_from_value(fields[4])?,
            priority: fields[5]
                .as_i64()
                .and_then(|raw| i32::try_from(raw).ok())
                .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                    "priority must be an i32",
                ))?,
            enabled: boolean(fields[6], "enabled must be a boolean")?,
            agent_amendable: boolean(fields[7], "agent_amendable must be a boolean")?,
            updated_at: fields[8].as_u64().ok_or(
                ChannelIdentitySelectionError::MalformedRuleSet("updated_at must be a u64"),
            )?,
            updated_by: optional_entity_from_value(fields[9])?,
            writer_kind: SelectionRuleWriterKind::parse(token(
                fields[10],
                "writer_kind must be a string",
            )?)
            .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                "unknown writer kind token",
            ))?,
        };
    rule.validate()?;
    Ok(rule)
}

fn scope_from_value(value: &Value) -> ChannelIdentitySelectionResult<SelectionRuleScope> {
    let Value::Map(entries) = value else {
        return Err(ChannelIdentitySelectionError::MalformedScope);
    };
    let (kind_key, kind_value) = entries
        .first()
        .ok_or(ChannelIdentitySelectionError::MalformedScope)?;
    if kind_key.as_str() != Some("kind") {
        return Err(ChannelIdentitySelectionError::MalformedScope);
    }
    let kind = kind_value
        .as_str()
        .ok_or(ChannelIdentitySelectionError::MalformedScope)?;
    if kind == "vault_default" {
        return match entries.len() {
            1 => Ok(SelectionRuleScope::VaultDefault),
            _ => Err(ChannelIdentitySelectionError::MalformedScope),
        };
    }
    if entries.len() != 2 {
        return Err(ChannelIdentitySelectionError::MalformedScope);
    }
    let (payload_key, payload) = &entries[1];
    let scope = match (kind, payload_key.as_str()) {
        ("world", Some("world_ref")) => SelectionRuleScope::World {
            world_ref: entity_from_value(payload)?,
        },
        ("relationship", Some("relationship_ref")) => SelectionRuleScope::Relationship {
            relationship_ref: entity_from_value(payload)?,
        },
        ("brief", Some("brief_ref")) => SelectionRuleScope::Brief {
            brief_ref: scope_text(payload)?,
        },
        ("space", Some("space_ref")) => SelectionRuleScope::Space {
            space_ref: scope_text(payload)?,
        },
        _ => return Err(ChannelIdentitySelectionError::MalformedScope),
    };
    scope.validate()?;
    Ok(scope)
}

fn scope_text(value: &Value) -> ChannelIdentitySelectionResult<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(ChannelIdentitySelectionError::MalformedScope)
}

/// An entity reference is 16 raw bytes and nothing else — a same-length string
/// is a different wire type and is refused rather than reinterpreted.
fn entity_from_value(value: &Value) -> ChannelIdentitySelectionResult<EntityId> {
    let Value::Binary(raw) = value else {
        return Err(ChannelIdentitySelectionError::InvalidEntityRef);
    };
    let bytes = <[u8; 16]>::try_from(raw.as_slice())
        .map_err(|_| ChannelIdentitySelectionError::InvalidEntityRef)?;
    EntityId::from_bytes(bytes).map_err(|_| ChannelIdentitySelectionError::InvalidEntityRef)
}

fn optional_entity_from_value(value: &Value) -> ChannelIdentitySelectionResult<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        other => entity_from_value(other).map(Some),
    }
}

fn token<'a>(value: &'a Value, what: &'static str) -> ChannelIdentitySelectionResult<&'a str> {
    value
        .as_str()
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(what))
}

fn boolean(value: &Value, what: &'static str) -> ChannelIdentitySelectionResult<bool> {
    value
        .as_bool()
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(what))
}

/// Requires the map to carry exactly `keys`, in order, with string keys.
///
/// One check rejects unknown keys, missing keys, duplicates, and reordering,
/// which is what makes the encoding canonical rather than merely parseable.
fn strict_fields<'a>(
    value: &'a Value,
    keys: &[&str],
    what: &'static str,
) -> ChannelIdentitySelectionResult<Vec<&'a Value>> {
    let Value::Map(entries) = value else {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(what));
    };
    if entries.len() != keys.len() {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(what));
    }
    let mut fields = Vec::with_capacity(keys.len());
    for (index, (key, field)) in entries.iter().enumerate() {
        if key.as_str() != Some(keys[index]) {
            return Err(ChannelIdentitySelectionError::MalformedRuleSet(what));
        }
        fields.push(field);
    }
    Ok(fields)
}

// ---------------------------------------------------------------------------
// Storage + amendment
// ---------------------------------------------------------------------------

fn stored_rule_set(
    vault_meta: &OverlayDb,
    txn: &RoTxn<'_>,
) -> ChannelIdentitySelectionResult<Option<ChannelIdentitySelectionRuleSet>> {
    match vault_meta.get(txn, CHANNEL_IDENTITY_SELECTION_KEY)? {
        Some(raw) => decode_rule_set(&raw).map(Some),
        None => Ok(None),
    }
}

/// Applies one patch to the stored overlay rows under writer authority.
fn apply_patch(
    rows: &mut Vec<ChannelIdentitySelectionRule>,
    builtins: &[ChannelIdentitySelectionRule],
    writer: &ChannelIdentitySelectionWriter,
    patch: ChannelIdentitySelectionPatch,
) -> ChannelIdentitySelectionResult<()> {
    match patch {
        ChannelIdentitySelectionPatch::Upsert(mut rule) => {
            // Provenance is DERIVED here, so whatever the caller put in these
            // two fields is overwritten rather than trusted.
            rule.writer_kind = writer.kind();
            rule.updated_by = Some(writer.actor_ref());
            rule.validate()?;
            let existing = rows
                .iter()
                .find(|row| row.rule_id == rule.rule_id)
                .or_else(|| builtins.iter().find(|row| row.rule_id == rule.rule_id));
            authorize_upsert(writer, existing, &rule)?;
            match rows.iter().position(|row| row.rule_id == rule.rule_id) {
                Some(index) => rows[index] = rule,
                None => rows.push(rule),
            }
            Ok(())
        }
        ChannelIdentitySelectionPatch::Remove { rule_id } => {
            let Some(index) = rows.iter().position(|row| row.rule_id == rule_id) else {
                // A builtin is compiled law: it is disabled by upserting a
                // shadow with `enabled = false`, never deleted.
                return Err(if builtins.iter().any(|row| row.rule_id == rule_id) {
                    ChannelIdentitySelectionError::BuiltinRuleNotRemovable
                } else {
                    ChannelIdentitySelectionError::RuleNotFound
                });
            };
            authorize_write(writer, &rows[index])?;
            rows.remove(index);
            Ok(())
        }
    }
}

/// An agent may only touch rows that are currently agent-amendable, and may
/// never leave one locked behind it.
fn authorize_upsert(
    writer: &ChannelIdentitySelectionWriter,
    existing: Option<&ChannelIdentitySelectionRule>,
    next: &ChannelIdentitySelectionRule,
) -> ChannelIdentitySelectionResult<()> {
    if writer.kind() != SelectionRuleWriterKind::Agent {
        return Ok(());
    }
    if let Some(existing) = existing {
        authorize_write(writer, existing)?;
    }
    if next.agent_amendable {
        Ok(())
    } else {
        Err(ChannelIdentitySelectionError::AgentCannotLockRule)
    }
}

fn authorize_write(
    writer: &ChannelIdentitySelectionWriter,
    existing: &ChannelIdentitySelectionRule,
) -> ChannelIdentitySelectionResult<()> {
    if writer.kind() != SelectionRuleWriterKind::Agent || existing.agent_amendable {
        Ok(())
    } else {
        Err(ChannelIdentitySelectionError::RuleNotAgentAmendable)
    }
}

impl Vault {
    /// Reads the compiled selection law: stored overlay over the builtins.
    ///
    /// A fresh vault returns the six builtins at revision `0`. Corrupt storage
    /// fails typed rather than resolving against a guess.
    pub fn channel_identity_selection_rules(
        &self,
    ) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
        let rtxn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let stored = stored_rule_set(&self.store.vault_meta, &rtxn)?;
        compile_channel_identity_selection(stored.as_ref())
    }

    /// Amends the selection law under compare-and-swap on `expected_revision`.
    ///
    /// An accepted change stamps the derived writer kind and `updated_by` onto
    /// the row and advances the revision by exactly one. The whole read,
    /// authorization, compile, and write happen in one transaction, so two
    /// racing writers cannot both land against the same revision.
    pub fn update_channel_identity_selection_rules(
        &self,
        expected_revision: u64,
        writer: &ChannelIdentitySelectionWriter,
        patch: ChannelIdentitySelectionPatch,
    ) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
        let builtins = builtin_channel_identity_selection_rules();
        self.try_with_write_txn(|wtxn| {
            let stored = stored_rule_set(&self.store.vault_meta, &*wtxn)?;
            let current = stored.as_ref().map_or(0, |set| set.revision);
            if current != expected_revision {
                return Err(ChannelIdentitySelectionError::RevisionConflict {
                    expected: expected_revision,
                    stored: current,
                });
            }
            let mut rows = stored.map(|set| set.rows).unwrap_or_default();
            apply_patch(&mut rows, &builtins, writer, patch)?;
            rows.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
            let record = ChannelIdentitySelectionRuleSet {
                schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
                revision: current
                    .checked_add(1)
                    .ok_or(ChannelIdentitySelectionError::RevisionOverflow)?,
                rows,
            };
            // Compile BEFORE writing: an amendment that would make the
            // compiled law ambiguous is refused, not persisted and discovered
            // on the next read.
            let compiled = compile_channel_identity_selection(Some(&record))?;
            let bytes = encode_rule_set(&record)?;
            self.store
                .vault_meta
                .put(wtxn, CHANNEL_IDENTITY_SELECTION_KEY, &bytes)?;
            Ok(compiled)
        })
    }

    /// Reads the stored overlay exactly as persisted, without the builtins.
    ///
    /// Callers that need the law want [`Self::channel_identity_selection_rules`];
    /// this door exists for provenance inspection of what was actually written.
    pub fn stored_channel_identity_selection_rules(
        &self,
    ) -> ChannelIdentitySelectionResult<Option<ChannelIdentitySelectionRuleSet>> {
        let rtxn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        stored_rule_set(&self.store.vault_meta, &rtxn)
    }
}

#[cfg(test)]
mod tests;
