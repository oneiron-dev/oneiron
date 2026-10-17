//! Artifact-independent review fan-out and the persisted calibration feedback loop.
use super::*;
use crate::claim::ClaimSource;
use crate::learning::TypeRef;
use crate::llm::decision::DecisionReceipt;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
mod dissent;
mod outcomes;
pub use dissent::{
    CriticPrediction, ReviewDissent, preserve_review_dissent, project_all_review_dissent,
    project_review_dissent,
};
mod persistence;
mod questions;
pub use outcomes::{record_review_outcome, recurring_findings};
use persistence::*;
pub use questions::{
    REVIEW_DIAL, ReviewDecisions, ReviewFinding, ReviewNote, ReviewNotes, ReviewWording,
};
mod submit;
pub use submit::{CriticBinding, CriticReviewOutcome, CriticReviewSubmit};

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
    pub lens_ref: EntityId,
    pub critic: WriteActor,
    pub type_ref: TypeRef,
    pub axis: String,
    pub run_id: String,
    pub branch_attempt: AttemptId,
}

/// The stored lens skill and the actor executing it. Catalogue domains describe
/// prompts only; they never key measured reliability.
#[derive(Debug, Clone)]
pub struct ReviewCritic {
    pub lens_id: String,
    pub lens_ref: EntityId,
    pub actor: WriteActor,
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
    /// The task's existing placement, shared with routing and planning.
    pub type_ref: TypeRef,
    pub axis: String,
    pub critics: Vec<ReviewCritic>,
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
    request.type_ref.validate()?;
    if request.critics.len() != catalog.lenses.len() {
        return Err(invalid_critic_config(
            "review must bind every lens to its skill and actor",
        ));
    }
    let mut bound = BTreeMap::new();
    for critic in &request.critics {
        if bound.insert(critic.lens_id.as_str(), critic).is_some()
            || vault.get_entity_type(&critic.lens_ref)? != Some(crate::registry::ENTITY_TYPE_SKILL)
        {
            return Err(invalid_critic_config(
                "review lens requires a unique stored skill",
            ));
        }
        LearningCell::new(LearningPredicate::Reliability, critic.lens_ref)
            .executor(critic.actor.entity_ref().to_hex())
            .type_ref(request.type_ref.clone())
            .axis(request.axis.clone())
            .validate()?;
    }
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
            drop(txn);
            preserve_overruled(vault, &result, request.at)?;
            return Ok(result);
        }
    }
    let inputs = catalog
        .lenses
        .iter()
        .map(|lens| {
            let critic = bound
                .get(lens.id.as_str())
                .ok_or_else(|| invalid_critic_config("review lens is not bound"))?;
            Ok(CriticReviewInput {
                target: request.target,
                kind: request.kind,
                lens: lens.clone(),
                lens_ref: critic.lens_ref,
                critic: critic.actor,
                type_ref: request.type_ref.clone(),
                axis: request.axis.clone(),
                run_id: request.run_id.clone(),
                branch_attempt: request.branch_attempt,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (artifacts, receipts) = decisions.review(&inputs, request.at)?;
    let reliabilities = read_reliabilities(vault, &artifacts)?;
    let mut triage = triage_critiques(catalog, &artifacts, &reliabilities)?;
    triage.findings =
        super::findings::merge_findings(&artifacts, &reliabilities, request.auto_resolve_threshold);
    triage.auto_resolved =
        super::findings::verdict_confidence(&artifacts, &reliabilities, triage.verdict)
            >= request.auto_resolve_threshold;
    let mut result = persist_review(vault, request, &triage, &artifacts)?;
    result.receipts = receipts;
    preserve_overruled(vault, &result, request.at)?;
    Ok(result)
}

fn preserve_overruled(vault: &Vault, result: &ReviewResult, at: u64) -> Result<()> {
    for artifact in result.artifacts.iter().filter(|artifact| {
        !artifact.out_of_scope
            && artifact.verdict != result.triage.verdict
            && artifact.prediction.is_some()
    }) {
        preserve_review_dissent(vault, result, &artifact.artifact_id, at)?;
    }
    Ok(())
}

fn value_of<T: Serialize>(value: &T) -> Result<Value> {
    let bytes =
        rmp_serde::to_vec_named(value).map_err(|_| invalid_critic_config("review encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| invalid_critic_config("review value"))
}

#[cfg(test)]
pub(crate) mod tests;
