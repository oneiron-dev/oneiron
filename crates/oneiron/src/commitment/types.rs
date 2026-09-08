//! Pinned commitment schema consts, key sets, bounds, and domain types.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec::validate_non_empty_bounded;

/// Current `commitment.record` value schema version.
pub const COMMITMENT_VALUE_SCHEMA_VERSION: u64 = 1;

/// Pinned `commitment.*` claim predicates for CMT-1.
pub const COMMITMENT_CLAIM_PREDICATES: [&str; 1] = [PREDICATE_COMMITMENT_RECORD];

/// The atomic commitment fact record.
pub const PREDICATE_COMMITMENT_RECORD: &str = "commitment.record";

/// Pinned top-level MessagePack key set for `commitment.record` values.
pub const COMMITMENT_VALUE_KEYS: [&str; 8] = [
    "schema_version",
    "obligor",
    "beneficiary",
    "content",
    "schedule",
    "strength",
    "status",
    "birth_provenance",
];

pub(super) const KEY_SCHEMA_VERSION: &str = COMMITMENT_VALUE_KEYS[0];

pub(super) const KEY_OBLIGOR: &str = COMMITMENT_VALUE_KEYS[1];

pub(super) const KEY_BENEFICIARY: &str = COMMITMENT_VALUE_KEYS[2];

pub(super) const KEY_CONTENT: &str = COMMITMENT_VALUE_KEYS[3];

pub(super) const KEY_SCHEDULE: &str = COMMITMENT_VALUE_KEYS[4];

pub(super) const KEY_STRENGTH: &str = COMMITMENT_VALUE_KEYS[5];

pub(super) const KEY_STATUS: &str = COMMITMENT_VALUE_KEYS[6];

pub(super) const KEY_BIRTH_PROVENANCE: &str = COMMITMENT_VALUE_KEYS[7];

pub(super) const COMMITMENT_OBLIGOR_KEYS: [&str; 2] = ["kind", "entity_ref"];

pub(super) const KEY_OBLIGOR_KIND: &str = COMMITMENT_OBLIGOR_KEYS[0];

pub(super) const KEY_OBLIGOR_ENTITY_REF: &str = COMMITMENT_OBLIGOR_KEYS[1];

pub(super) const COMMITMENT_CONTENT_KEYS: [&str; 2] = ["text", "payload_ref"];

pub(super) const KEY_CONTENT_TEXT: &str = COMMITMENT_CONTENT_KEYS[0];

pub(super) const KEY_CONTENT_PAYLOAD_REF: &str = COMMITMENT_CONTENT_KEYS[1];

pub(super) const COMMITMENT_BIRTH_PROVENANCE_KEYS: [&str; 2] = ["kind", "reference"];

pub(super) const KEY_BIRTH_KIND: &str = COMMITMENT_BIRTH_PROVENANCE_KEYS[0];

pub(super) const KEY_BIRTH_REFERENCE: &str = COMMITMENT_BIRTH_PROVENANCE_KEYS[1];

const MAX_COMMITMENT_TEXT_BYTES: usize = 8 * 1024;

const MAX_COMMITMENT_PAYLOAD_REF_BYTES: usize = 1024;

const MAX_COMMITMENT_BIRTH_REFERENCE_BYTES: usize = 1024;

/// The class of actor that owes the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentObligorKind {
    Owner,
    Agent,
    ThirdParty,
}

impl CommitmentObligorKind {
    /// Stable on-disk string for this obligor class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Agent => "agent",
            Self::ThirdParty => "third_party",
        }
    }

    /// Parses a pinned obligor class string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "agent" => Some(Self::Agent),
            "third_party" => Some(Self::ThirdParty),
            _ => None,
        }
    }
}

/// Who owes the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitmentObligor {
    pub kind: CommitmentObligorKind,
    pub entity_ref: EntityId,
}

impl CommitmentObligor {
    /// Creates an obligor reference.
    #[must_use]
    pub const fn new(kind: CommitmentObligorKind, entity_ref: EntityId) -> Self {
        Self { kind, entity_ref }
    }
}

/// What is promised.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitmentContent {
    pub text: String,
    pub payload_ref: Option<String>,
}

impl CommitmentContent {
    /// Creates text content with an optional host-local typed payload ref.
    pub fn new(text: impl Into<String>, payload_ref: Option<String>) -> Result<Self> {
        let content = Self {
            text: text.into(),
            payload_ref,
        };
        content.validate()?;
        Ok(content)
    }

    fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.text,
            MAX_COMMITMENT_TEXT_BYTES,
            "commitment content text must be non-empty and bounded",
        )?;
        if let Some(payload_ref) = &self.payload_ref {
            validate_non_empty_bounded(
                payload_ref,
                MAX_COMMITMENT_PAYLOAD_REF_BYTES,
                "commitment content payload_ref must be non-empty and bounded",
            )?;
        }
        Ok(())
    }
}

/// Commitment strength tier. The tier is the future wake dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentStrength {
    StatedIntention,
    Decision,
    Commitment,
}

impl CommitmentStrength {
    /// Stable on-disk string for this tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatedIntention => "stated_intention",
            Self::Decision => "decision",
            Self::Commitment => "commitment",
        }
    }

    /// Parses a pinned strength tier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stated_intention" => Some(Self::StatedIntention),
            "decision" => Some(Self::Decision),
            "commitment" => Some(Self::Commitment),
            _ => None,
        }
    }

    /// Resolves extractor proposal vs explicit user override.
    ///
    /// Agent-owed commitments are always full `commitment` strength. For other
    /// obligors, an explicit user statement overrides the extractor proposal.
    #[must_use]
    pub const fn resolve(
        obligor_kind: CommitmentObligorKind,
        extractor_proposal: Self,
        explicit_user_override: Option<Self>,
    ) -> Self {
        if matches!(obligor_kind, CommitmentObligorKind::Agent) {
            Self::Commitment
        } else if let Some(user_override) = explicit_user_override {
            user_override
        } else {
            extractor_proposal
        }
    }
}

/// Commitment status. CMT-1 ships explicit fulfill/release/supersede verbs;
/// lapse storage is present for the later CMT lapse path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentStatus {
    Open,
    Fulfilled,
    Released,
    Lapsed,
    Superseded,
}

impl CommitmentStatus {
    /// Stable on-disk string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Fulfilled => "fulfilled",
            Self::Released => "released",
            Self::Lapsed => "lapsed",
            Self::Superseded => "superseded",
        }
    }

    /// Parses a pinned status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "fulfilled" => Some(Self::Fulfilled),
            "released" => Some(Self::Released),
            "lapsed" => Some(Self::Lapsed),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(self, Self::Open)
            && matches!(
                next,
                Self::Fulfilled | Self::Released | Self::Lapsed | Self::Superseded
            )
    }
}

/// Explicit source of a fulfillment effect (CMT-4, ONE-1541).
///
/// Every status-effecting fulfillment names the thing that caused it. There is
/// no ambient or inferred arm: a Dreamer witness writes a PROPOSAL claim
/// instead of a status, and only these three explicit sources reach
/// [`Vault::fulfill_commitment`].
///
/// [`Self::ChecklistTick`] is the typed N6 hook. It is deliberately UNWIRED:
/// the engine has no checklist-tick producer, so the dispatcher accepts the
/// variant for a future caller and this ticket adds no checklist module, event
/// parser, polling loop, or adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FulfillmentSource {
    /// The owner marked the obligation done directly.
    UserDone,
    /// A task brief that `Fulfills` the commitment completed.
    BriefCompletion { brief_ref: EntityId },
    /// A checklist item was ticked. Typed, with no producer in this ticket.
    ChecklistTick,
}

impl FulfillmentSource {
    /// Stable string for this fulfillment source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDone => "user_done",
            Self::BriefCompletion { .. } => "brief_completion",
            Self::ChecklistTick => "checklist_tick",
        }
    }
}

/// Origin category for a commitment birth event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentBirthKind {
    RunTreeNode,
    Brief,
    SurfaceAction,
}

impl CommitmentBirthKind {
    /// Stable on-disk string for this birth category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunTreeNode => "run_tree_node",
            Self::Brief => "brief",
            Self::SurfaceAction => "surface_action",
        }
    }

    /// Parses a pinned birth category string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "run_tree_node" => Some(Self::RunTreeNode),
            "brief" => Some(Self::Brief),
            "surface_action" => Some(Self::SurfaceAction),
            _ => None,
        }
    }
}

/// Provenance for the moment that created the commitment fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitmentBirthProvenance {
    pub kind: CommitmentBirthKind,
    pub reference: String,
}

impl CommitmentBirthProvenance {
    /// Creates a birth provenance reference.
    pub fn new(kind: CommitmentBirthKind, reference: impl Into<String>) -> Result<Self> {
        let birth = Self {
            kind,
            reference: reference.into(),
        };
        birth.validate()?;
        Ok(birth)
    }

    fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.reference,
            MAX_COMMITMENT_BIRTH_REFERENCE_BYTES,
            "commitment birth provenance reference must be non-empty and bounded",
        )
    }
}

/// Decoded `commitment.record` value.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitmentRecord {
    pub obligor: CommitmentObligor,
    pub beneficiary: EntityId,
    pub content: CommitmentContent,
    /// Opaque CMT schedule payload. CMT-1 stores and gates it, but does not
    /// parse or evaluate it.
    pub schedule: Value,
    pub strength: CommitmentStrength,
    pub status: CommitmentStatus,
    pub birth_provenance: CommitmentBirthProvenance,
}

impl CommitmentRecord {
    /// Creates a commitment record. Agent-owed records are normalized to full
    /// `commitment` strength before validation.
    pub fn new(
        obligor: CommitmentObligor,
        beneficiary: EntityId,
        content: CommitmentContent,
        schedule: Value,
        strength: CommitmentStrength,
        status: CommitmentStatus,
        birth_provenance: CommitmentBirthProvenance,
    ) -> Result<Self> {
        let strength = CommitmentStrength::resolve(obligor.kind, strength, None);
        let record = Self {
            obligor,
            beneficiary,
            content,
            schedule,
            strength,
            status,
            birth_provenance,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates CMT-1 record invariants.
    pub fn validate(&self) -> Result<()> {
        self.content.validate()?;
        self.birth_provenance.validate()?;
        if matches!(self.schedule, Value::Nil) {
            return Err(Error::InvalidClaimBody(
                "commitment schedule payload must be present",
            ));
        }
        if self.obligor.kind == CommitmentObligorKind::Agent
            && self.strength != CommitmentStrength::Commitment
        {
            return Err(Error::InvalidClaimBody(
                "agent-owed commitments must have commitment strength",
            ));
        }
        Ok(())
    }
}
