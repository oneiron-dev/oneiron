//! Entity-addressed provenance carried by consolidated evidence.

use crate::claim::ClaimSource;
use crate::entity_id::EntityId;

/// One typed hop of a consolidation provenance chain (ONE-1710).
///
/// The kinds are ADDRESSING roles, not trust classes: a chain says which
/// stored entities a candidate descends from, and `evidence_chain_source`
/// separately folds those into the D10 meet. `EntityId` carries no
/// `Serialize`/`Deserialize` (entity_id.rs), so the chain rides the crate's
/// hand-rolled rmpv codec below rather than serde derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsolidationProvenanceHopKind {
    /// The stored peer-answer TURN.
    AnswerTurn,
    /// The synced consult TASK that elicited the answer.
    ConsultTask,
    /// The answering peer CONNECTION actor (never the vendor/harness label).
    PeerActor,
    /// An optional durable result artifact carried by the answer.
    ResultArtifact,
}

impl ConsolidationProvenanceHopKind {
    /// The pinned on-disk string for this hop kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnswerTurn => "answer_turn",
            Self::ConsultTask => "consult_task",
            Self::PeerActor => "peer_actor",
            Self::ResultArtifact => "result_artifact",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "answer_turn" => Some(Self::AnswerTurn),
            "consult_task" => Some(Self::ConsultTask),
            "peer_actor" => Some(Self::PeerActor),
            "result_artifact" => Some(Self::ResultArtifact),
            _ => None,
        }
    }
}

/// One hop: what it is, which entity it names, and (optionally) the actor
/// behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationProvenanceHop {
    pub kind: ConsolidationProvenanceHopKind,
    pub entity_ref: EntityId,
    pub actor_ref: Option<EntityId>,
}

/// The structured evidence payload a promoted consolidation claim stores:
/// the post-admission refs, the typed chain, and the computed meet — all
/// machine-readable after promotion, never a display string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidationEvidenceEnvelope {
    pub refs: Vec<EntityId>,
    pub chain: Vec<ConsolidationProvenanceHop>,
    pub source_meet: ClaimSource,
}
