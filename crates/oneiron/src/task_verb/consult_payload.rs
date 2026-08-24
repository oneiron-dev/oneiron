use std::collections::HashSet;

use crate::Vault;
use crate::consult_ladder::{ConsultLineage, ConsultPurpose, EntityDeltaArtifact};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The only ref kinds a consult payload may carry. A consult asks ABOUT
/// durable state; it never transports the state itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsultPayloadRef {
    Claim(EntityId),
    Turn(EntityId),
}

impl ConsultPayloadRef {
    /// The referenced entity.
    #[must_use]
    pub const fn entity_ref(self) -> EntityId {
        match self {
            Self::Claim(entity_ref) | Self::Turn(entity_ref) => entity_ref,
        }
    }

    pub(super) const fn entity_type(self) -> u8 {
        match self {
            Self::Claim(_) => crate::registry::ENTITY_TYPE_CLAIM,
            Self::Turn(_) => crate::registry::ENTITY_TYPE_TURN,
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Claim(_) => "cl",
            Self::Turn(_) => "tn",
        }
    }

    /// Canonical `cl_*` / `tn_*` rendering.
    #[must_use]
    pub fn short_ref(self) -> String {
        format!("{}_{}", self.prefix(), self.entity_ref().to_hex())
    }

    /// Parses one caller string into the typed enum and binds it to a RESOLVED
    /// entity of the matching kind. Unknown prefixes, malformed ids, and
    /// unresolved or mistyped targets are refused here — this is a shape
    /// guarantee established before persistence, not a scrubber run over
    /// arbitrary JSON afterwards.
    pub fn parse(vault: &Vault, value: &str) -> Result<Self> {
        let (prefix, hex) = value
            .split_once('_')
            .ok_or(Error::InvalidTaskBody("tasks.consult.ref"))?;
        let entity_ref =
            EntityId::from_hex(hex).map_err(|_| Error::InvalidTaskBody("tasks.consult.ref"))?;
        let parsed = match prefix {
            "cl" => Self::Claim(entity_ref),
            "tn" => Self::Turn(entity_ref),
            _ => return Err(Error::InvalidTaskBody("tasks.consult.ref")),
        };
        if vault.get_entity_type(&entity_ref)? != Some(parsed.entity_type()) {
            return Err(Error::InvalidTaskBody("tasks.consult.ref"));
        }
        Ok(parsed)
    }
}

/// The typed consult request. There is no arbitrary-`Value` door: a caller who
/// needs to ask about a large artifact persists it first and passes its ref.
///
/// The three ONE-1888 additions are optional and default to absent. Absent is
/// exactly ONE-1699's question consult, so no migration rewrites a stored row
/// and no old row decodes differently than it did before this ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultPayload {
    // ONE-1699 fields — unchanged and required.
    pub question_ref: ConsultPayloadRef,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub correlation_ref: EntityId,

    // ONE-1888 additions — optional/defaulted, never a re-shape.
    pub purpose: Option<ConsultPurpose>,
    pub entity_delta: Option<EntityDeltaArtifact>,
    pub lineage: Option<ConsultLineage>,
}

impl ConsultPayload {
    /// The ONE-1699 construction surface, unchanged.
    #[must_use]
    pub const fn question(
        question_ref: ConsultPayloadRef,
        context_refs: Vec<ConsultPayloadRef>,
        correlation_ref: EntityId,
    ) -> Self {
        Self {
            question_ref,
            context_refs,
            correlation_ref,
            purpose: None,
            entity_delta: None,
            lineage: None,
        }
    }

    /// Declares this consult an entity-delta ask over one typed artifact.
    #[must_use]
    pub fn with_entity_delta(mut self, delta: EntityDeltaArtifact) -> Self {
        self.purpose = Some(ConsultPurpose::EntityDelta);
        self.entity_delta = Some(delta);
        self
    }

    /// Links this consult to the record it counters, appeals, or escalates.
    #[must_use]
    pub const fn with_lineage(mut self, lineage: ConsultLineage) -> Self {
        self.lineage = Some(lineage);
        self
    }

    /// Typed `cl_*`/`tn_*` entries carried by this payload.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        1 + self.context_refs.len()
    }

    /// `None` and `Some(Question)` are the SAME ONE-1699 shape; only an
    /// explicit `EntityDelta` requires the typed artifact.
    #[must_use]
    pub fn consult_purpose(&self) -> ConsultPurpose {
        self.purpose.unwrap_or(ConsultPurpose::Question)
    }

    /// Every carried ref is distinct. A repeated context ref (or a context ref
    /// that restates the question) is a caller bug the schema forbids, not a
    /// convenience to silently de-duplicate.
    pub(super) fn validate(&self) -> Result<()> {
        let mut seen = HashSet::with_capacity(self.ref_count());
        seen.insert(self.question_ref);
        for context_ref in &self.context_refs {
            if !seen.insert(*context_ref) {
                return Err(Error::InvalidTaskBody("tasks.consult.duplicate_ref"));
            }
        }
        self.validate_purpose()
    }

    /// The ONE-1888 validation matrix: the purpose and the typed artifact
    /// agree, or the payload is refused. A question consult carrying a delta —
    /// or a delta consult carrying none — is a shape no writer may persist.
    fn validate_purpose(&self) -> Result<()> {
        let agrees = match self.consult_purpose() {
            ConsultPurpose::Question => self.entity_delta.is_none(),
            ConsultPurpose::EntityDelta => self.entity_delta.is_some(),
        };
        if !agrees {
            return Err(Error::InvalidTaskBody("tasks.consult.purpose"));
        }
        // Chatter never enters the state machine: the artifact carries refs,
        // and a thread pointer is the ONLY door to the discussion itself.
        if let Some(delta) = &self.entity_delta
            && delta.proposer_actor_ref == delta.owning_actor_ref
        {
            // A cross-actor consult whose proposer IS the owner is the
            // auto-apply path taking the wrong door.
            return Err(Error::InvalidTaskBody("tasks.consult.same_actor"));
        }
        Ok(())
    }
}

/// Typed recovery choices offered with an expiry digest. The engine never
/// carries product copy: the consuming lens localizes "peer offline — try
/// another actor / nudge" from these tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultRecovery {
    RetryAssignee,
    NudgeAssignee,
    TryPeer(EntityId),
}

impl ConsultRecovery {
    /// Stable wire token for the choice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetryAssignee => "retry_assignee",
            Self::NudgeAssignee => "nudge_assignee",
            Self::TryPeer(_) => "try_peer",
        }
    }
}
