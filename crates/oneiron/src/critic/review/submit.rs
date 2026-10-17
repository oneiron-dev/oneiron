//! One critic review through a host's door (`vault.critic.review`): what the
//! caller binds and what the review gives back. The host reads the target
//! under the caller's own scope, asks every lens's questions through its
//! decision ladder and returns the verdict, each lens's artifact and the
//! receipts. Nothing is applied to the target.
use serde::{Deserialize, Serialize};

use super::{ReviewArtifactKind, ReviewCritic, ReviewRequest, ReviewResult};
use crate::EdgeActorClass;
use crate::attempt_queue::AttemptId;
use crate::critic::{CritiqueArtifact, CritiqueTriage, LensCatalog};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::llm::decision::DecisionReceipt;
use crate::write_envelope::WriteActor;

/// One critic review's binding: the target, the session its verdict is
/// tagged with, the lens catalog and, for every lens, its stored skill and
/// the actor executing it. The same binding under the same run replays the
/// review already written.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticReviewSubmit {
    /// The entity under review, 32-hex, read under the caller's own scope.
    pub target_ref: String,
    /// `document`, `design` or `claim_write` (a proposed claim).
    pub kind: String,
    /// The session the verdict is tagged with, 32-hex.
    pub session_ref: String,
    /// The run the review belongs to; its artifacts are keyed under it.
    pub run_ref: String,
    /// The task type's node the critics' reliability is learned at.
    pub type_node: String,
    /// The task-type tree version that node is in.
    pub type_tree_version: u32,
    /// The reliability axis.
    pub axis: String,
    /// The confidence, in `0..=1`, at which a merged finding resolves without
    /// a person.
    pub auto_resolve_threshold: f64,
    /// The lens catalog (`LensCatalog`), as JSON. Every lens in it is bound in
    /// `critics`.
    pub catalog: serde_json::Value,
    /// Each lens's stored skill and the actor executing it.
    pub critics: Vec<CriticBinding>,
}

/// One lens's stored skill and the actor executing it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticBinding {
    /// The lens's id in the catalog.
    pub lens_id: String,
    /// The lens's stored SKILL, 32-hex.
    pub lens_ref: String,
    /// The actor executing the lens, 32-hex.
    pub actor_ref: String,
    /// That actor's class: 0 human, 1 agent, 2 system.
    pub actor_class: u8,
}

/// What a review gave back: the verdict claim, the triage, each lens's
/// artifact and one receipt per typed question asked (none when the review
/// replayed from its cache).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticReviewOutcome {
    pub verdict_claim_ref: String,
    pub triage: CritiqueTriage,
    pub artifacts: Vec<CritiqueArtifact>,
    pub receipts: Vec<DecisionReceipt>,
}

impl CriticReviewSubmit {
    /// The review `actor` asks for at `at`, and its lens catalog. The run's
    /// branch attempt is derived from `run_ref`, so a repeated binding keys
    /// the same review.
    pub fn bind(&self, actor: WriteActor, at: u64) -> Result<(ReviewRequest, LensCatalog)> {
        let kind = match self.kind.as_str() {
            "document" => ReviewArtifactKind::Document,
            "design" => ReviewArtifactKind::Design,
            "claim_write" => ReviewArtifactKind::ClaimWrite,
            _ => return Err(invalid("review kind is document, design or claim_write")),
        };
        if self.run_ref.trim().is_empty() {
            return Err(invalid("a review names its run"));
        }
        let catalog = LensCatalog::from_json_str(&self.catalog.to_string())?;
        let critics = self
            .critics
            .iter()
            .map(|critic| {
                let class = EdgeActorClass::try_from_u8(critic.actor_class)
                    .ok_or_else(|| invalid("a critic's actor class is 0, 1 or 2"))?;
                Ok(ReviewCritic {
                    lens_id: critic.lens_id.clone(),
                    lens_ref: EntityId::from_hex(&critic.lens_ref)?,
                    actor: WriteActor::new(EntityId::from_hex(&critic.actor_ref)?, class),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let digest = blake3::hash(self.run_ref.as_bytes());
        let request = ReviewRequest {
            actor,
            target: EntityId::from_hex(&self.target_ref)?,
            kind,
            session: EntityId::from_hex(&self.session_ref)?,
            run_id: self.run_ref.clone(),
            branch_attempt: AttemptId::from_bytes(&digest.as_bytes()[..16])?,
            auto_resolve_threshold: self.auto_resolve_threshold,
            type_ref: TypeRef {
                node_id: self.type_node.clone(),
                tree_version: self.type_tree_version,
            },
            axis: self.axis.clone(),
            critics,
            at,
        };
        Ok((request, catalog))
    }
}

impl From<ReviewResult> for CriticReviewOutcome {
    fn from(result: ReviewResult) -> Self {
        Self {
            verdict_claim_ref: result.verdict_claim.to_hex(),
            triage: result.triage,
            artifacts: result.artifacts,
            receipts: result.receipts,
        }
    }
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
