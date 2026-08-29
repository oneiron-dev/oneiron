//! Channel-identity selection law (OF-413 R1 / INB-01).
//!
//! One generic, vault-resident rule table decides — per *relationship
//! context* — which semantic **face** the agent wears. The six compiled
//! defaults are owner-editable and agent-amendable per row; a thread pin wins
//! ahead of every mutable row; and any malformed storage fails typed rather
//! than letting the engine pick an arbitrary identity.
//!
//! Deliberate non-goals, pinned so later tickets do not reopen this file:
//!
//! * Selection chooses the *face only*. It never mutates a
//!   [`crate::channel_identity::ChannelIdentity`] record, never grants or
//!   checks egress authority (that stays in the Gate POLICY zone), and is not
//!   a customization preference blob.
//! * Consent posture and thread continuity belong to other rows of the lane.
//!   The [`ChannelIdentityThreadPin`] input is defined here so the downstream
//!   thread-passport work consumes a type instead of editing this module.
//! * Candidates are *host-classified*: the caller supplies the identity ref,
//!   its existing [`ChannelIdentityShape`], the face it wears, and whether it
//!   is live. No shape variant is required beyond the ones that exist today.
//!
//! Purity rule: nothing in this module names a venture, product, person,
//! persona, prompt, or user-facing sentence. The worked override from the
//! design doc lives only in the module's tests.

use std::borrow::Cow;
use std::cmp::Reverse;
use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::channel_identity::ChannelIdentityShape;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

/// Current selection rule-set schema version.
pub const CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION: u64 = 1;

/// `vault_meta` (manifest DB #5) key holding the one strict rule set.
pub const CHANNEL_IDENTITY_SELECTION_RULES_KEY: &[u8] = b"channel_identity_selection:v1:rules";

/// Pinned on-disk MessagePack key set for the rule-set envelope.
pub const CHANNEL_IDENTITY_SELECTION_SET_KEYS: [&str; 3] = ["schema_version", "revision", "rules"];

/// Pinned on-disk MessagePack key set for one rule row.
pub const CHANNEL_IDENTITY_SELECTION_RULE_KEYS: [&str; 10] = [
    "rule_id",
    "context",
    "scope_kind",
    "scope_ref",
    "face",
    "priority",
    "agent_amendable",
    "updated_at",
    "updated_by",
    "writer_kind",
];

const KEY_SCHEMA_VERSION: &str = CHANNEL_IDENTITY_SELECTION_SET_KEYS[0];
const KEY_REVISION: &str = CHANNEL_IDENTITY_SELECTION_SET_KEYS[1];
const KEY_RULES: &str = CHANNEL_IDENTITY_SELECTION_SET_KEYS[2];

const KEY_RULE_ID: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[0];
const KEY_CONTEXT: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[1];
const KEY_SCOPE_KIND: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[2];
const KEY_SCOPE_REF: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[3];
const KEY_FACE: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[4];
const KEY_PRIORITY: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[5];
const KEY_AGENT_AMENDABLE: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[6];
const KEY_UPDATED_AT: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[7];
const KEY_UPDATED_BY: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[8];
const KEY_WRITER_KIND: &str = CHANNEL_IDENTITY_SELECTION_RULE_KEYS[9];

const SCOPE_KIND_VAULT_DEFAULT: &str = "vault_default";
const SCOPE_KIND_WORLD: &str = "world";

/// Upper bound on a stored rule table; a larger table is corrupt storage.
pub const MAX_CHANNEL_IDENTITY_SELECTION_RULES: usize = 256;

const MAX_RULE_ID_BYTES: usize = 64;

/// Result alias for the selection law's module-local error.
pub type SelectionResult<T> = std::result::Result<T, ChannelIdentitySelectionError>;

// ---------------------------------------------------------------------------
// Axes
// ---------------------------------------------------------------------------

/// The relationship context a message is being sent in.
///
/// This is the *only* key of the selection law: the face follows from the
/// relationship, never from the venture, the counterparty's name, or a
/// per-message heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelationshipContext {
    /// Deal / client threads where relationship continuity is the value.
    WorkDeal,
    /// Scheduling, logistics, and cc-the-agent traffic.
    SchedulingLogistics,
    /// Outreach sent at volume, where sender reputation is consumable.
    CampaignOutreach,
    /// Transactional plumbing (confirmations, invites, receipts).
    TransactionalSystem,
    /// Personal and friend threads.
    PersonalFriends,
    /// Multi-participant rooms on any platform.
    GroupSpace,
}

impl RelationshipContext {
    /// Every relationship context, in the canonical order of the rule table.
    pub const ALL: [Self; 6] = [
        Self::WorkDeal,
        Self::SchedulingLogistics,
        Self::CampaignOutreach,
        Self::TransactionalSystem,
        Self::PersonalFriends,
        Self::GroupSpace,
    ];

    /// Stable wire token for this context.
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

    /// Parses a stable wire token.
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

    /// Compiled vault-default face for this context.
    #[must_use]
    pub const fn default_face(self) -> ChannelIdentityFace {
        match self {
            Self::WorkDeal => ChannelIdentityFace::DelegatedOwnerAccount,
            Self::SchedulingLogistics => ChannelIdentityFace::AgentNamedAddress,
            Self::CampaignOutreach => ChannelIdentityFace::SideDomainAddress,
            Self::TransactionalSystem => ChannelIdentityFace::HouseIdentity,
            Self::PersonalFriends => ChannelIdentityFace::CompanionIdentity,
            Self::GroupSpace => ChannelIdentityFace::NamedGroupParticipant,
        }
    }

    /// Stable rule id of this context's compiled builtin row.
    #[must_use]
    pub const fn builtin_rule_id(self) -> &'static str {
        match self {
            Self::WorkDeal => "builtin.work_deal",
            Self::SchedulingLogistics => "builtin.scheduling_logistics",
            Self::CampaignOutreach => "builtin.campaign_outreach",
            Self::TransactionalSystem => "builtin.transactional_system",
            Self::PersonalFriends => "builtin.personal_friends",
            Self::GroupSpace => "builtin.group_space",
        }
    }
}

/// The semantic face the agent wears on the envelope.
///
/// A face is *not* a [`ChannelIdentityShape`]: several shapes can carry one
/// face, and a host classifies its own identities. Keeping the axis semantic
/// is what lets this module compile without the delegated shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelIdentityFace {
    /// The owner's own account, ridden under a grant.
    DelegatedOwnerAccount,
    /// The agent's own named work address.
    AgentNamedAddress,
    /// An agent-owned identity on an isolated secondary domain.
    SideDomainAddress,
    /// The house / primary product identity used for plumbing.
    HouseIdentity,
    /// The companion's own personal-side presence.
    CompanionIdentity,
    /// A named, disclosed participant inside a shared room.
    NamedGroupParticipant,
}

impl ChannelIdentityFace {
    /// Every face, in the canonical order of the rule table.
    pub const ALL: [Self; 6] = [
        Self::DelegatedOwnerAccount,
        Self::AgentNamedAddress,
        Self::SideDomainAddress,
        Self::HouseIdentity,
        Self::CompanionIdentity,
        Self::NamedGroupParticipant,
    ];

    /// Stable wire token for this face.
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

    /// Parses a stable wire token.
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

/// How wide a rule row reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectionRuleScope {
    /// Applies whenever no exact-scope row matches.
    VaultDefault,
    /// Applies only inside one world.
    World(EntityId),
}

impl SelectionRuleScope {
    /// Higher rank wins before lower rank, independent of stored row order.
    const fn rank(self) -> u8 {
        match self {
            Self::VaultDefault => 0,
            Self::World(_) => 1,
        }
    }

    /// Returns whether this scope is in force for `world_ref`.
    #[must_use]
    pub fn matches(self, world_ref: Option<EntityId>) -> bool {
        match self {
            Self::VaultDefault => true,
            Self::World(scoped) => world_ref == Some(scoped),
        }
    }
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

/// Provenance class of the last write to a rule row.
///
/// [`Self::SystemDefault`] is reachable only by compiling the builtin table;
/// no runtime write can mint it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectionWriterKind {
    /// A compiled builtin row that has never been amended.
    SystemDefault,
    /// The vault owner.
    Owner,
    /// The agent, acting under the row's amendable flag.
    Agent,
}

impl SelectionWriterKind {
    /// Stable wire token for this writer kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemDefault => "system_default",
            Self::Owner => "owner",
            Self::Agent => "agent",
        }
    }

    /// Parses a stable wire token.
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

/// An authenticated amender of the rule table.
///
/// The writer kind is *derived* from the actor class carried by an
/// authenticated [`WriteActor`]; it is never accepted as caller-supplied data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionWriter {
    actor_ref: EntityId,
    kind: SelectionWriterKind,
}

impl SelectionWriter {
    /// Derives the writer from an authenticated write actor.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelIdentitySelectionError::WriterClassNotAmendable`] for a
    /// system actor: `system_default` provenance belongs to the compiled table
    /// alone, so a system caller has no amendment door here.
    pub fn from_authenticated_write(actor: WriteActor) -> SelectionResult<Self> {
        let kind = match actor.actor_class() {
            EdgeActorClass::Human => SelectionWriterKind::Owner,
            EdgeActorClass::Agent => SelectionWriterKind::Agent,
            EdgeActorClass::System => {
                return Err(ChannelIdentitySelectionError::WriterClassNotAmendable);
            }
        };
        Ok(Self {
            actor_ref: actor.entity_ref(),
            kind,
        })
    }

    /// Entity stamped into `updated_by` on every accepted change.
    #[must_use]
    pub const fn actor_ref(self) -> EntityId {
        self.actor_ref
    }

    /// Derived writer kind.
    #[must_use]
    pub const fn kind(self) -> SelectionWriterKind {
        self.kind
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// One row of the selection law.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRule {
    /// Stable, vault-unique row id.
    pub rule_id: String,
    /// Relationship context this row answers.
    pub context: RelationshipContext,
    /// How wide the row reaches.
    pub scope: SelectionRuleScope,
    /// Face the row selects.
    pub face: ChannelIdentityFace,
    /// Tie-break weight within one scope rank; greater wins.
    pub priority: u32,
    /// Whether the agent may amend or remove this row.
    pub agent_amendable: bool,
    /// Wall-clock stamp of the last accepted change.
    pub updated_at: u64,
    /// Actor stamped by the last accepted change; `None` only for builtins.
    pub updated_by: Option<EntityId>,
    /// Provenance class of the last accepted change.
    pub writer_kind: SelectionWriterKind,
}

impl SelectionRule {
    fn validate(&self) -> SelectionResult<()> {
        validate_rule_id(&self.rule_id)?;
        match (self.writer_kind, self.updated_by) {
            (SelectionWriterKind::SystemDefault, None)
            | (SelectionWriterKind::Owner | SelectionWriterKind::Agent, Some(_)) => Ok(()),
            _ => Err(ChannelIdentitySelectionError::InvalidRule(
                "writer stamp does not match writer kind",
            )),
        }
    }

    /// Deterministic precedence key; greater wins.
    fn precedence_key(&self) -> (u8, u32, u64, Reverse<&str>) {
        (
            self.scope.rank(),
            self.priority,
            self.updated_at,
            Reverse(self.rule_id.as_str()),
        )
    }
}

/// Caller-supplied row content for an upsert.
///
/// Provenance fields are absent on purpose: `updated_by` and `writer_kind` are
/// stamped from the authenticated [`SelectionWriter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRuleAmendment {
    /// Stable, vault-unique row id.
    pub rule_id: String,
    /// Relationship context this row answers.
    pub context: RelationshipContext,
    /// How wide the row reaches.
    pub scope: SelectionRuleScope,
    /// Face the row selects.
    pub face: ChannelIdentityFace,
    /// Tie-break weight within one scope rank; greater wins.
    pub priority: u32,
    /// Whether the agent may amend or remove the resulting row.
    pub agent_amendable: bool,
    /// Wall-clock stamp for the change.
    pub updated_at: u64,
}

fn validate_rule_id(rule_id: &str) -> SelectionResult<()> {
    if rule_id.is_empty() || rule_id.len() > MAX_RULE_ID_BYTES {
        return Err(ChannelIdentitySelectionError::InvalidRule(
            "rule id length out of range",
        ));
    }
    if rule_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(ChannelIdentitySelectionError::InvalidRule(
            "rule id contains an invalid character",
        ))
    }
}

// ---------------------------------------------------------------------------
// Rule set
// ---------------------------------------------------------------------------

/// The whole selection law for one vault at one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRuleSet {
    revision: u64,
    rules: Vec<SelectionRule>,
}

impl SelectionRuleSet {
    /// The six compiled defaults, in canonical order, at revision 1.
    ///
    /// Every row is agent-amendable and owner-editable; every row carries
    /// `writer_kind = SystemDefault` and no `updated_by`.
    #[must_use]
    pub fn compiled_defaults() -> Self {
        let rules = RelationshipContext::ALL
            .into_iter()
            .map(|context| SelectionRule {
                rule_id: context.builtin_rule_id().to_owned(),
                context,
                scope: SelectionRuleScope::VaultDefault,
                face: context.default_face(),
                priority: 0,
                agent_amendable: true,
                updated_at: 0,
                updated_by: None,
                writer_kind: SelectionWriterKind::SystemDefault,
            })
            .collect();
        Self { revision: 1, rules }
    }

    /// Builds a validated rule set from stored or constructed rows.
    ///
    /// # Errors
    ///
    /// Fails typed on a regressed revision, an over-long table, an invalid
    /// row, a duplicate `rule_id`, or two vault-default rows claiming one
    /// relationship context.
    pub fn from_rows(revision: u64, rules: Vec<SelectionRule>) -> SelectionResult<Self> {
        let set = Self { revision, rules };
        set.validate()?;
        Ok(set)
    }

    fn validate(&self) -> SelectionResult<()> {
        if self.revision == 0 {
            return Err(ChannelIdentitySelectionError::RevisionRegressed { stored: 0 });
        }
        if self.rules.len() > MAX_CHANNEL_IDENTITY_SELECTION_RULES {
            return Err(ChannelIdentitySelectionError::MalformedRuleSet(
                "rule count exceeds the pinned maximum",
            ));
        }
        for (index, rule) in self.rules.iter().enumerate() {
            rule.validate()?;
            for other in &self.rules[index + 1..] {
                if other.rule_id == rule.rule_id {
                    return Err(ChannelIdentitySelectionError::DuplicateRuleId);
                }
                // Exactly one canonical winner per relationship context: two
                // vault-default rows for one context would make the law's
                // fallback answer depend on an arbitrary tie-break.
                // Exact-scope rows may stack; precedence orders them.
                if other.context == rule.context
                    && matches!(rule.scope, SelectionRuleScope::VaultDefault)
                    && matches!(other.scope, SelectionRuleScope::VaultDefault)
                {
                    return Err(ChannelIdentitySelectionError::DuplicateCanonicalWinner);
                }
            }
        }
        Ok(())
    }

    /// Current revision; every accepted change increments it by exactly one.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// All rows, in stored order (which never affects resolution).
    #[must_use]
    pub fn rules(&self) -> &[SelectionRule] {
        &self.rules
    }

    /// Looks a row up by id.
    #[must_use]
    pub fn rule(&self, rule_id: &str) -> Option<&SelectionRule> {
        self.rules.iter().find(|rule| rule.rule_id == rule_id)
    }

    fn check_revision(&self, expected: u64) -> SelectionResult<()> {
        if expected == self.revision {
            Ok(())
        } else {
            Err(ChannelIdentitySelectionError::RevisionConflict {
                expected,
                stored: self.revision,
            })
        }
    }

    fn next_revision(&self) -> SelectionResult<u64> {
        self.revision
            .checked_add(1)
            .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                "revision overflow",
            ))
    }

    /// Inserts or replaces one row under compare-and-swap on `expected_revision`.
    ///
    /// # Errors
    ///
    /// Fails typed on a stale `expected_revision`, an agent writer targeting a
    /// non-amendable row, an agent writer trying to lock a row, or any row
    /// invariant broken by the result.
    pub fn upsert(
        &self,
        writer: SelectionWriter,
        expected_revision: u64,
        amendment: &SelectionRuleAmendment,
    ) -> SelectionResult<Self> {
        self.check_revision(expected_revision)?;
        validate_rule_id(&amendment.rule_id)?;
        let existing = self
            .rules
            .iter()
            .position(|rule| rule.rule_id == amendment.rule_id);
        if writer.kind() == SelectionWriterKind::Agent {
            if !amendment.agent_amendable {
                return Err(ChannelIdentitySelectionError::AgentCannotLockRule);
            }
            if let Some(index) = existing
                && !self.rules[index].agent_amendable
            {
                return Err(ChannelIdentitySelectionError::RuleNotAgentAmendable);
            }
        }
        let row = SelectionRule {
            rule_id: amendment.rule_id.clone(),
            context: amendment.context,
            scope: amendment.scope,
            face: amendment.face,
            priority: amendment.priority,
            agent_amendable: amendment.agent_amendable,
            updated_at: amendment.updated_at,
            updated_by: Some(writer.actor_ref()),
            writer_kind: writer.kind(),
        };
        let mut rules = self.rules.clone();
        match existing {
            Some(index) => rules[index] = row,
            None => rules.push(row),
        }
        Self::from_rows(self.next_revision()?, rules)
    }

    /// Removes one row under compare-and-swap on `expected_revision`.
    ///
    /// # Errors
    ///
    /// Fails typed on a stale `expected_revision`, an unknown `rule_id`, or an
    /// agent writer targeting a non-amendable row.
    pub fn remove(
        &self,
        writer: SelectionWriter,
        expected_revision: u64,
        rule_id: &str,
    ) -> SelectionResult<Self> {
        self.check_revision(expected_revision)?;
        let index = self
            .rules
            .iter()
            .position(|rule| rule.rule_id == rule_id)
            .ok_or(ChannelIdentitySelectionError::RuleNotFound)?;
        if writer.kind() == SelectionWriterKind::Agent && !self.rules[index].agent_amendable {
            return Err(ChannelIdentitySelectionError::RuleNotAgentAmendable);
        }
        let mut rules = self.rules.clone();
        rules.remove(index);
        Self::from_rows(self.next_revision()?, rules)
    }

    /// Returns the winning row for `context` inside `world_ref`.
    ///
    /// Precedence is deterministic and order-independent: exact scope beats
    /// vault default, then greater priority, then later `updated_at`, then
    /// lexically smaller `rule_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelIdentitySelectionError::NoRuleForContext`] when no row
    /// is in force. The law never falls through to another context's face.
    pub fn winning_rule(
        &self,
        context: RelationshipContext,
        world_ref: Option<EntityId>,
    ) -> SelectionResult<&SelectionRule> {
        let mut winner: Option<&SelectionRule> = None;
        for rule in &self.rules {
            if rule.context != context || !rule.scope.matches(world_ref) {
                continue;
            }
            if winner.is_none_or(|current| rule.precedence_key() > current.precedence_key()) {
                winner = Some(rule);
            }
        }
        winner.ok_or(ChannelIdentitySelectionError::NoRuleForContext)
    }

    /// Resolves the face the agent wears for one request.
    ///
    /// A valid thread pin is honored ahead of every mutable row. Otherwise the
    /// winning row's face is matched against the host-classified candidates;
    /// when nothing carries that face the call fails closed.
    ///
    /// # Errors
    ///
    /// Fails typed on duplicate candidates, a missing or inactive pinned
    /// candidate, no rule in force, or no active candidate wearing the
    /// selected face.
    pub fn resolve(
        &self,
        request: ChannelIdentitySelectionRequest,
        candidates: &[ChannelIdentityCandidate],
    ) -> SelectionResult<ChannelIdentitySelection> {
        validate_candidates(candidates)?;
        if let Some(pin) = request.thread_pin {
            return resolve_thread_pin(pin, candidates);
        }
        let rule = self.winning_rule(request.context, request.world_ref)?;
        let chosen = pick_candidate_for_face(rule.face, candidates)
            .ok_or(ChannelIdentitySelectionError::NoCandidateForFace)?;
        Ok(ChannelIdentitySelection {
            identity_ref: chosen.identity_ref,
            facet_ref: chosen.facet_ref,
            face: chosen.face,
            shape: chosen.shape,
            source: ChannelIdentitySelectionSource::Rule {
                rule_id: rule.rule_id.clone(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Request / candidates / outcome
// ---------------------------------------------------------------------------

/// A thread-scoped identity pin, honored before any mutable row.
///
/// Defined here so the downstream thread-passport work consumes this input
/// instead of reopening the selection law.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentityThreadPin {
    /// Identity the thread is pinned to.
    pub identity_ref: EntityId,
    /// Facet the thread is pinned to, when the pin carries one.
    pub facet_ref: Option<EntityId>,
}

/// One host-classified identity the caller is willing to wear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentityCandidate {
    /// The `ChannelIdentity` record this candidate stands for.
    pub identity_ref: EntityId,
    /// The record's existing addressability shape.
    pub shape: ChannelIdentityShape,
    /// The face the host classifies this identity as wearing.
    pub face: ChannelIdentityFace,
    /// Facet bound to the identity, when the host has one.
    pub facet_ref: Option<EntityId>,
    /// Whether the identity is live enough to be chosen.
    pub active: bool,
}

/// One selection question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentitySelectionRequest {
    /// Relationship context of the conversation.
    pub context: RelationshipContext,
    /// World the conversation sits in, when the caller knows one.
    pub world_ref: Option<EntityId>,
    /// Thread pin, when the thread already wears a mask.
    pub thread_pin: Option<ChannelIdentityThreadPin>,
}

impl ChannelIdentitySelectionRequest {
    /// Builds an unpinned, vault-default-scoped request.
    #[must_use]
    pub const fn new(context: RelationshipContext) -> Self {
        Self {
            context,
            world_ref: None,
            thread_pin: None,
        }
    }

    /// Scopes the request to a world.
    #[must_use]
    pub const fn in_world(mut self, world_ref: EntityId) -> Self {
        self.world_ref = Some(world_ref);
        self
    }

    /// Attaches a thread pin.
    #[must_use]
    pub const fn with_thread_pin(mut self, pin: ChannelIdentityThreadPin) -> Self {
        self.thread_pin = Some(pin);
        self
    }
}

/// Why a selection was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelIdentitySelectionSource {
    /// A valid thread pin was honored ahead of the rule table.
    ThreadPin,
    /// The named row of the rule table won.
    Rule {
        /// Winning row id.
        rule_id: String,
    },
}

/// The face the agent wears for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentitySelection {
    /// Chosen identity record.
    pub identity_ref: EntityId,
    /// Chosen facet, if any.
    pub facet_ref: Option<EntityId>,
    /// Face the chosen identity wears.
    pub face: ChannelIdentityFace,
    /// Chosen identity's addressability shape, carried through unchanged.
    pub shape: ChannelIdentityShape,
    /// Provenance of the decision.
    pub source: ChannelIdentitySelectionSource,
}

fn validate_candidates(candidates: &[ChannelIdentityCandidate]) -> SelectionResult<()> {
    for (index, candidate) in candidates.iter().enumerate() {
        for other in &candidates[index + 1..] {
            if other.identity_ref == candidate.identity_ref {
                return Err(ChannelIdentitySelectionError::DuplicateCandidate);
            }
        }
    }
    Ok(())
}

fn resolve_thread_pin(
    pin: ChannelIdentityThreadPin,
    candidates: &[ChannelIdentityCandidate],
) -> SelectionResult<ChannelIdentitySelection> {
    let pinned = candidates
        .iter()
        .find(|candidate| candidate.identity_ref == pin.identity_ref)
        .ok_or(ChannelIdentitySelectionError::PinnedCandidateMissing)?;
    if !pinned.active {
        return Err(ChannelIdentitySelectionError::PinnedCandidateInactive);
    }
    Ok(ChannelIdentitySelection {
        identity_ref: pin.identity_ref,
        facet_ref: pin.facet_ref,
        face: pinned.face,
        shape: pinned.shape,
        source: ChannelIdentitySelectionSource::ThreadPin,
    })
}

/// Picks the lowest-id active candidate wearing `face`.
///
/// Same-face candidates are equally valuable by construction, so the tie-break
/// is a stable id ordering rather than a fallback to a different face.
fn pick_candidate_for_face(
    face: ChannelIdentityFace,
    candidates: &[ChannelIdentityCandidate],
) -> Option<&ChannelIdentityCandidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.active && candidate.face == face)
        .min_by_key(|candidate| candidate.identity_ref)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Module-local typed failures of the selection law.
///
/// Every variant is a fail-closed outcome: no path here degrades into picking
/// an arbitrary or more valuable identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelIdentitySelectionError {
    /// No rule set is installed in `vault_meta`.
    #[error("channel identity selection rule set is not installed")]
    RuleSetMissing,
    /// A rule set is already installed; defaults are never silently rewritten.
    #[error("channel identity selection rule set is already installed")]
    RuleSetAlreadyInstalled,
    /// Stored bytes are not a well-formed rule set.
    #[error("channel identity selection rule set is malformed: {0}")]
    MalformedRuleSet(&'static str),
    /// One row broke a row invariant.
    #[error("channel identity selection rule is invalid: {0}")]
    InvalidRule(&'static str),
    /// Two rows share a `rule_id`.
    #[error("channel identity selection rule ids are not unique")]
    DuplicateRuleId,
    /// Two vault-default rows claim one relationship context.
    #[error("two vault-default channel identity selection rules claim one relationship context")]
    DuplicateCanonicalWinner,
    /// The caller's `expected_revision` is not the stored revision.
    #[error("channel identity selection revision conflict: expected {expected}, stored {stored}")]
    RevisionConflict {
        /// Revision the caller compared and swapped against.
        expected: u64,
        /// Revision actually stored.
        stored: u64,
    },
    /// A rule-set revision did not advance by exactly one.
    #[error("channel identity selection revision regressed at {stored}")]
    RevisionRegressed {
        /// Offending revision.
        stored: u64,
    },
    /// The authenticated actor class has no amendment door here.
    #[error("actor class cannot amend channel identity selection rules")]
    WriterClassNotAmendable,
    /// An agent writer targeted a row the owner marked non-amendable.
    #[error("channel identity selection rule is not agent-amendable")]
    RuleNotAgentAmendable,
    /// An agent writer tried to write a non-amendable row.
    #[error("an agent writer cannot lock a channel identity selection rule")]
    AgentCannotLockRule,
    /// The named row does not exist.
    #[error("channel identity selection rule not found")]
    RuleNotFound,
    /// No row is in force for the requested context and scope.
    #[error("no channel identity selection rule matches the relationship context")]
    NoRuleForContext,
    /// No active candidate wears the selected face.
    #[error("no active candidate wears the selected channel identity face")]
    NoCandidateForFace,
    /// The pinned identity is absent from the candidate set.
    #[error("pinned channel identity candidate is missing")]
    PinnedCandidateMissing,
    /// The pinned identity is present but not active.
    #[error("pinned channel identity candidate is not active")]
    PinnedCandidateInactive,
    /// Two candidates share one identity reference.
    #[error("channel identity candidates are not unique")]
    DuplicateCandidate,
    /// A storage-layer failure surfaced from the vault.
    #[error(transparent)]
    Storage(Box<crate::error::Error>),
}

impl From<crate::error::Error> for ChannelIdentitySelectionError {
    fn from(value: crate::error::Error) -> Self {
        Self::Storage(Box::new(value))
    }
}

impl From<heed::Error> for ChannelIdentitySelectionError {
    fn from(value: heed::Error) -> Self {
        Self::Storage(Box::new(crate::error::Error::from(value)))
    }
}

// ---------------------------------------------------------------------------
// Strict MessagePack codec
// ---------------------------------------------------------------------------

fn malformed(reason: &'static str) -> ChannelIdentitySelectionError {
    ChannelIdentitySelectionError::MalformedRuleSet(reason)
}

/// Encodes a rule set in canonical MessagePack field order.
///
/// # Errors
///
/// Returns [`ChannelIdentitySelectionError::MalformedRuleSet`] when the value
/// cannot be written.
pub fn encode_selection_rule_set(set: &SelectionRuleSet) -> SelectionResult<Vec<u8>> {
    set.validate()?;
    let rules = set.rules.iter().map(encode_selection_rule).collect();
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_REVISION), Value::from(set.revision)),
        (Value::from(KEY_RULES), Value::Array(rules)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| malformed("rule set MessagePack encode failed"))?;
    Ok(out)
}

fn encode_selection_rule(rule: &SelectionRule) -> Value {
    let (scope_kind, scope_ref) = match rule.scope {
        SelectionRuleScope::VaultDefault => (SCOPE_KIND_VAULT_DEFAULT, Value::Nil),
        SelectionRuleScope::World(world_ref) => (SCOPE_KIND_WORLD, Value::from(world_ref.to_hex())),
    };
    Value::Map(vec![
        (Value::from(KEY_RULE_ID), Value::from(rule.rule_id.as_str())),
        (Value::from(KEY_CONTEXT), Value::from(rule.context.as_str())),
        (Value::from(KEY_SCOPE_KIND), Value::from(scope_kind)),
        (Value::from(KEY_SCOPE_REF), scope_ref),
        (Value::from(KEY_FACE), Value::from(rule.face.as_str())),
        (Value::from(KEY_PRIORITY), Value::from(rule.priority)),
        (
            Value::from(KEY_AGENT_AMENDABLE),
            Value::from(rule.agent_amendable),
        ),
        (Value::from(KEY_UPDATED_AT), Value::from(rule.updated_at)),
        (
            Value::from(KEY_UPDATED_BY),
            rule.updated_by
                .map_or(Value::Nil, |actor| Value::from(actor.to_hex())),
        ),
        (
            Value::from(KEY_WRITER_KIND),
            Value::from(rule.writer_kind.as_str()),
        ),
    ])
}

/// Decodes and validates a stored rule set.
///
/// # Errors
///
/// Fails typed on trailing bytes, an unknown or missing key, a bad enum token,
/// a malformed scope, an invalid `EntityId` reference, a duplicate row, or a
/// regressed revision.
pub fn decode_selection_rule_set(bytes: &[u8]) -> SelectionResult<SelectionRuleSet> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| malformed("rule set MessagePack decode failed"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(malformed("rule set has trailing bytes"));
    }
    let Value::Map(entries) = &value else {
        return Err(malformed("rule set is not a map"));
    };
    validate_keys(entries, &CHANNEL_IDENTITY_SELECTION_SET_KEYS)?;
    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION)
    {
        return Err(malformed("rule set schema version is unsupported"));
    }
    let revision = required_value(entries, KEY_REVISION)?
        .as_u64()
        .ok_or_else(|| malformed("rule set revision is not a u64"))?;
    let Value::Array(rows) = required_value(entries, KEY_RULES)? else {
        return Err(malformed("rule set rules is not an array"));
    };
    let rules = rows
        .iter()
        .map(decode_selection_rule)
        .collect::<SelectionResult<Vec<SelectionRule>>>()?;
    SelectionRuleSet::from_rows(revision, rules)
}

fn decode_selection_rule(value: &Value) -> SelectionResult<SelectionRule> {
    let Value::Map(entries) = value else {
        return Err(malformed("rule row is not a map"));
    };
    validate_keys(entries, &CHANNEL_IDENTITY_SELECTION_RULE_KEYS)?;
    let rule_id = required_string(entries, KEY_RULE_ID)?.to_owned();
    let context = RelationshipContext::parse(required_string(entries, KEY_CONTEXT)?)
        .ok_or_else(|| malformed("rule row context is not a pinned context"))?;
    let scope = decode_scope(
        required_string(entries, KEY_SCOPE_KIND)?,
        required_value(entries, KEY_SCOPE_REF)?,
    )?;
    let face = ChannelIdentityFace::parse(required_string(entries, KEY_FACE)?)
        .ok_or_else(|| malformed("rule row face is not a pinned face"))?;
    let priority = u32::try_from(
        required_value(entries, KEY_PRIORITY)?
            .as_u64()
            .ok_or_else(|| malformed("rule row priority is not a u64"))?,
    )
    .map_err(|_| malformed("rule row priority exceeds u32"))?;
    let agent_amendable = required_value(entries, KEY_AGENT_AMENDABLE)?
        .as_bool()
        .ok_or_else(|| malformed("rule row agent_amendable is not a bool"))?;
    let updated_at = required_value(entries, KEY_UPDATED_AT)?
        .as_u64()
        .ok_or_else(|| malformed("rule row updated_at is not a u64"))?;
    let updated_by = decode_optional_entity_ref(required_value(entries, KEY_UPDATED_BY)?)?;
    let writer_kind = SelectionWriterKind::parse(required_string(entries, KEY_WRITER_KIND)?)
        .ok_or_else(|| malformed("rule row writer_kind is not a pinned writer kind"))?;
    let rule = SelectionRule {
        rule_id,
        context,
        scope,
        face,
        priority,
        agent_amendable,
        updated_at,
        updated_by,
        writer_kind,
    };
    rule.validate()?;
    Ok(rule)
}

fn decode_scope(kind: &str, scope_ref: &Value) -> SelectionResult<SelectionRuleScope> {
    match kind {
        SCOPE_KIND_VAULT_DEFAULT => {
            if matches!(scope_ref, Value::Nil) {
                Ok(SelectionRuleScope::VaultDefault)
            } else {
                Err(malformed("vault-default rule row carries a scope ref"))
            }
        }
        SCOPE_KIND_WORLD => decode_entity_ref(scope_ref).map(SelectionRuleScope::World),
        _ => Err(malformed("rule row scope kind is not a pinned scope")),
    }
}

fn decode_optional_entity_ref(value: &Value) -> SelectionResult<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_entity_ref(value).map(Some)
    }
}

fn decode_entity_ref(value: &Value) -> SelectionResult<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| malformed("entity reference is not a string"))?;
    EntityId::from_hex(hex).map_err(|_| malformed("entity reference is not a valid entity id"))
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> SelectionResult<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(|| malformed("field is not a string"))
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> SelectionResult<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| malformed("a pinned key is missing"))
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> SelectionResult<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| malformed("a map key is not a string"))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(malformed("an unknown key is present"));
        };
        if seen[index] {
            return Err(malformed("a key is repeated"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(malformed("a pinned key is missing"))
    }
}

// ---------------------------------------------------------------------------
// Vault door
// ---------------------------------------------------------------------------

impl Vault {
    /// Installs the six compiled defaults into `vault_meta`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelIdentitySelectionError::RuleSetAlreadyInstalled`] when
    /// a rule set already exists; an existing law is never silently rewritten.
    pub fn install_channel_identity_selection_defaults(&self) -> SelectionResult<SelectionRuleSet> {
        let defaults = SelectionRuleSet::compiled_defaults();
        let bytes = encode_selection_rule_set(&defaults)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self
            .store
            .vault_meta
            .get(&wtxn, CHANNEL_IDENTITY_SELECTION_RULES_KEY)?
            .is_some()
        {
            return Err(ChannelIdentitySelectionError::RuleSetAlreadyInstalled);
        }
        self.store
            .vault_meta
            .put(&mut wtxn, CHANNEL_IDENTITY_SELECTION_RULES_KEY, &bytes)?;
        wtxn.commit()?;
        Ok(defaults)
    }

    /// Reads the installed rule set.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelIdentitySelectionError::RuleSetMissing`] when nothing
    /// is installed, or a decode failure when the stored bytes are malformed.
    pub fn channel_identity_selection_rules(&self) -> SelectionResult<SelectionRuleSet> {
        let rtxn = self.store.env.read_txn()?;
        let raw = self
            .store
            .vault_meta
            .get(&rtxn, CHANNEL_IDENTITY_SELECTION_RULES_KEY)?
            .ok_or(ChannelIdentitySelectionError::RuleSetMissing)?;
        decode_selection_rule_set(raw.as_ref())
    }

    /// Inserts or replaces one rule row under compare-and-swap.
    ///
    /// # Errors
    ///
    /// Propagates every [`SelectionRuleSet::upsert`] failure plus storage and
    /// decode failures.
    pub fn upsert_channel_identity_selection_rule(
        &self,
        writer: SelectionWriter,
        expected_revision: u64,
        amendment: &SelectionRuleAmendment,
    ) -> SelectionResult<SelectionRuleSet> {
        self.amend_channel_identity_selection_rules(|current| {
            current.upsert(writer, expected_revision, amendment)
        })
    }

    /// Removes one rule row under compare-and-swap.
    ///
    /// # Errors
    ///
    /// Propagates every [`SelectionRuleSet::remove`] failure plus storage and
    /// decode failures.
    pub fn remove_channel_identity_selection_rule(
        &self,
        writer: SelectionWriter,
        expected_revision: u64,
        rule_id: &str,
    ) -> SelectionResult<SelectionRuleSet> {
        self.amend_channel_identity_selection_rules(|current| {
            current.remove(writer, expected_revision, rule_id)
        })
    }

    /// Resolves the face the agent wears for one request.
    ///
    /// # Errors
    ///
    /// Propagates every [`SelectionRuleSet::resolve`] failure plus storage and
    /// decode failures.
    pub fn resolve_channel_identity_selection(
        &self,
        request: ChannelIdentitySelectionRequest,
        candidates: &[ChannelIdentityCandidate],
    ) -> SelectionResult<ChannelIdentitySelection> {
        self.channel_identity_selection_rules()?
            .resolve(request, candidates)
    }

    fn amend_channel_identity_selection_rules(
        &self,
        change: impl FnOnce(&SelectionRuleSet) -> SelectionResult<SelectionRuleSet>,
    ) -> SelectionResult<SelectionRuleSet> {
        let mut wtxn = self.store.env.write_txn()?;
        let current = {
            let raw: Cow<'_, [u8]> = self
                .store
                .vault_meta
                .get(&wtxn, CHANNEL_IDENTITY_SELECTION_RULES_KEY)?
                .ok_or(ChannelIdentitySelectionError::RuleSetMissing)?;
            decode_selection_rule_set(raw.as_ref())?
        };
        let next = change(&current)?;
        let expected_next = current.next_revision()?;
        if next.revision() != expected_next {
            return Err(ChannelIdentitySelectionError::RevisionRegressed {
                stored: next.revision(),
            });
        }
        let bytes = encode_selection_rule_set(&next)?;
        self.store
            .vault_meta
            .put(&mut wtxn, CHANNEL_IDENTITY_SELECTION_RULES_KEY, &bytes)?;
        wtxn.commit()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
