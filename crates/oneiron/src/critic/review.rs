//! Artifact-independent review fan-out and the persisted calibration feedback loop.
use super::*;
use crate::claim::ClaimSource;
use crate::llm::decision::DecisionReceipt;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
mod outcomes;
mod persistence;
mod questions;
pub use outcomes::{record_review_outcome, recurring_findings};
use persistence::*;
pub use questions::{
    REVIEW_DIAL, ReviewDecisions, ReviewFinding, ReviewNote, ReviewNotes, ReviewWording,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewArtifactKind {
    Document,
    Design,
    ClaimWrite,
}

/// One lens's review of the target. None contains sibling output.
#[derive(Debug, Clone)]
pub struct CriticReviewInput {
    pub target: EntityId,
    pub kind: ReviewArtifactKind,
    pub lens: CriticLens,
    pub run_id: String,
    pub branch_attempt: AttemptId,
}

#[derive(Debug, Clone)]
pub struct ReviewRequest {
    pub actor: WriteActor,
    pub target: EntityId,
    pub kind: ReviewArtifactKind,
    pub session: EntityId,
    pub run_id: String,
    pub branch_attempt: AttemptId,
    pub auto_resolve_threshold: f64,
    pub at: u64,
}

#[derive(Debug, Clone)]
pub struct ReviewResult {
    pub verdict_claim: EntityId,
    pub triage: CritiqueTriage,
    pub artifacts: Vec<CritiqueArtifact>,
    /// One receipt per typed question asked; empty when the review replays from its cache.
    pub receipts: Vec<DecisionReceipt>,
}

/// Review a document, design or proposed claim through the same consolidator as tournaments.
/// A session-scoped parent verdict cites every private artifact; outcomes are separate claims.
/// Each lens's verdict, severity, scope and hard check are typed decisions on the shared path.
pub fn review_artifact(
    vault: &Vault,
    request: &ReviewRequest,
    catalog: &LensCatalog,
    decisions: &ReviewDecisions<'_>,
) -> Result<ReviewResult> {
    validate_catalog(catalog)?;
    decisions.validate()?;
    if !request.auto_resolve_threshold.is_finite()
        || !(0.0..=1.0).contains(&request.auto_resolve_threshold)
    {
        return Err(invalid_critic_config("invalid review confidence threshold"));
    }
    if vault.get_entity_type(&request.target)?.is_none()
        || vault.get_entity_type(&request.session)? != Some(crate::registry::ENTITY_TYPE_SESSION)
    {
        return Err(Error::EntityNotFound);
    }
    if request.kind == ReviewArtifactKind::ClaimWrite
        && vault.get_entity_type(&request.target)? != Some(crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Err(invalid_critic_config("claim review target is not a claim"));
    }
    {
        let txn = vault.store.env.read_txn()?;
        if let Some(result) = cached_review(vault, &txn, request)? {
            return Ok(result);
        }
    }
    let inputs = catalog
        .lenses
        .iter()
        .map(|lens| CriticReviewInput {
            target: request.target,
            kind: request.kind,
            lens: lens.clone(),
            run_id: request.run_id.clone(),
            branch_attempt: request.branch_attempt,
        })
        .collect::<Vec<_>>();
    let (artifacts, receipts) = decisions.review(&inputs, request.at)?;
    let reliabilities = read_reliabilities(vault, &request.session, catalog)?;
    let mut triage = triage_critiques(catalog, &artifacts, &reliabilities)?;
    triage.findings =
        super::findings::merge_findings(&artifacts, &reliabilities, request.auto_resolve_threshold);
    triage.auto_resolved =
        super::findings::verdict_confidence(&artifacts, &reliabilities, triage.verdict)
            >= request.auto_resolve_threshold;
    let mut result = persist_review(vault, request, &triage, &artifacts)?;
    result.receipts = receipts;
    Ok(result)
}

fn value_of<T: Serialize>(value: &T) -> Result<Value> {
    let bytes =
        rmp_serde::to_vec_named(value).map_err(|_| invalid_critic_config("review encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| invalid_critic_config("review value"))
}

#[cfg(test)]
pub(crate) mod tests;
