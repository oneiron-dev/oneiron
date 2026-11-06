//! Typed consult request and recovery payloads for the consult ladder.
//! Entry [`ConsultPayload`]; built by ask doors, read by `consult_result` and every facade.
//! Owned by `task_verb`; large artifacts travel by ref, never inline.
use std::collections::HashSet;

use crate::consult_ladder::{ConsultLineage, ConsultPurpose, EntityDeltaArtifact};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

pub use crate::claim::consult_payload_ref::ConsultPayloadRef;

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
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "tasks.consult.duplicate_ref",
                )));
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
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "tasks.consult.purpose",
            )));
        }
        // Chatter never enters the state machine: the artifact carries refs,
        // and a thread pointer is the ONLY door to the discussion itself.
        if let Some(delta) = &self.entity_delta
            && delta.proposer_actor_ref == delta.owning_actor_ref
        {
            // A cross-actor consult whose proposer IS the owner is the
            // auto-apply path taking the wrong door.
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "tasks.consult.same_actor",
            )));
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
    /// Ask a peer instead: the named one, or `None` for "try another peer",
    /// which leaves the choice of peer to whoever takes the recovery.
    TryPeer(Option<EntityId>),
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
