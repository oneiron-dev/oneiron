//! Testable overruled predictions: attributed opinions and bound standing questions,
//! never critique claims. Facts, not elapsed horizons or agreement, settle them.
use super::*;
use crate::learning::{Anchor, LearningEvidence, Observation};
use crate::llm::decision::questions::{
    self, OutcomeBinding, QuestionActivation, QuestionDefinition, RefreshPolicy, StandingAnswer,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestion, ProviderPin,
};
use crate::note::TakeTarget;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticPrediction {
    pub what: String,
    /// Absolute Unix seconds; absence of a fact by this time is not a negative label.
    pub by_when: u64,
    pub how_checked: OutcomeBinding,
}

impl CriticPrediction {
    pub(in crate::critic) fn validate(&self, predicted_at: u64) -> Result<()> {
        self.how_checked.validate()?;
        if self.what.trim().is_empty()
            || self.what.len() > MAX_SUGGESTED_EDIT_BYTES
            || self.by_when <= predicted_at
            || self.by_when - predicted_at != self.how_checked.horizon
        {
            return Err(invalid_critic_config(
                "prediction requires what, a future horizon and an outcome binding",
            ));
        }
        Ok(())
    }
}

/// Retained beside the private review, not a vault claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewDissent {
    pub artifact_id: String,
    pub note: Option<EntityId>,
    pub question: Option<EntityId>,
    pub settled_fact: Option<EntityId>,
}

/// Retain a prediction when triage or an anchored outcome overruled its critique.
/// A critique without a prediction stays in its run-tree branch.
pub fn preserve_review_dissent(
    vault: &Vault,
    result: &ReviewResult,
    artifact_id: &str,
    at: u64,
) -> Result<Option<ReviewDissent>> {
    let artifact = persisted_artifact(vault, &result.verdict_claim, artifact_id)?;
    let Some(prediction) = &artifact.prediction else {
        return Ok(None);
    };
    validate_critique_artifact(&artifact)?;
    let (principal, mut state, verdict) = dissent_state(vault, &result.verdict_claim, artifact_id)?;
    if verdict == artifact.verdict && !dismissed(vault, &result.verdict_claim, artifact_id)? {
        return Ok(None);
    }
    let actor = artifact.provenance.actor()?;
    if state.note.is_none() {
        let markdown = serde_json::to_string_pretty(prediction)
            .map_err(|_| invalid_critic_config("dissent prediction encoding"))?;
        let receipt = vault
            .memory(actor.entity_ref(), actor.actor_class())
            .author_dissent(TakeTarget::Claim(result.verdict_claim), markdown)
            .map_err(|error| invalid_critic_config(error.to_string()))?;
        state.note = Some(EntityId::from_hex(&receipt.id_hex)?);
        save_dissent(vault, &result.verdict_claim, &state)?;
    }
    let unit = EntityId::from_hex(&artifact.candidate_ref)?;
    if state.question.is_none() {
        let record = questions::create_question(
            vault,
            principal,
            QuestionDefinition {
                question: DecisionQuestion {
                    id: EntityId::now(),
                    version: 1,
                    text: prediction.what.clone(),
                    class: DecisionClass::Judgment,
                    contract: AnswerContract::Noul,
                    accept_type: false,
                },
                adapter: "graph".to_owned(),
                units: vec![unit],
                recipe: "critic.dissent".to_owned(),
                profile: "critic.dissent".to_owned(),
                dial: REVIEW_DIAL,
                activation: QuestionActivation::Standing,
                // This records the critic's original prediction once. Arrivals label it;
                // they must not ask another model to replace it.
                refresh: RefreshPolicy {
                    on_arrival: false,
                    every_seconds: None,
                },
                delivery: "none".to_owned(),
                learning: true,
                binding: Some(prediction.how_checked.clone()),
                criteria: questions::QuestionCriteria::default(),
                audience: questions::QuestionAudience::Asker,
                posture: None,
                media: questions::QuestionMedia::default(),
                deadline_ms: None,
                artifacts: Vec::new(),
            },
            artifact.created_at,
        )?;
        state.question = Some(record.definition.question.id);
        save_dissent(vault, &result.verdict_claim, &state)?;
    }
    let question = state.question.ok_or(Error::EntityNotFound)?;
    let frontier =
        questions::standing_source_frontier(vault, principal, question, 1, actor, unit, &[])?;
    let providers = artifact
        .provenance
        .model_revision
        .as_ref()
        .map(|revision| ProviderPin {
            rung: REVIEW_DIAL.ceiling,
            model: artifact.provenance.model_id.clone(),
            version: revision.clone(),
        })
        .into_iter()
        .collect();
    questions::backfill_standing_answer(
        vault,
        principal,
        question,
        1,
        actor,
        StandingAnswer {
            unit,
            answer: DecisionAnswer::Noul(true),
            probability: Some(1.0),
            evidence: Vec::new(),
            providers,
            paired: Vec::new(),
            source_frontier: frontier,
        },
        artifact.created_at,
    )?;
    // Backfill also catches facts that arrived before the dissent was retained.
    project_review_dissent(vault, result, at)?;
    Ok(Some(state))
}

fn dismissed(vault: &Vault, verdict_id: &EntityId, artifact: &str) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let verdict = vault
        .get_claim_in_txn(&txn, verdict_id)?
        .ok_or(Error::EntityNotFound)?;
    if !trusted_claim(vault, &txn, verdict_id, &verdict)? {
        return Err(invalid_critic_config(
            "dissent requires a producer-bound review",
        ));
    }
    let session = EntityId::from_hex(
        verdict
            .session_tag
            .as_deref()
            .ok_or_else(|| invalid_critic_config("review has no session bundle"))?,
    )?;
    let key = Value::from(format!("{}:{artifact}", verdict_id.to_hex()));
    for id in vault.claims_for_subject_in_txn(&txn, &session)? {
        let Some(body) = vault.get_claim_in_txn(&txn, &id)? else {
            continue;
        };
        if body.predicate == "review.outcome"
            && candidate_evidence(&body) == Some(&key)
            && crate::claim::claim_surfaceable(&body)
            && trusted_claim(vault, &txn, &id, &body)?
            && let Some(value) = body.value.as_array()
            && value.last().and_then(Value::as_bool) == Some(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Fold OF-516's fact labels into each original critic's exact learning cell.
/// Replaying the projection replaces the same evidence receipt, never adds a vote.
/// Hosts call this when refreshing a review's outcome view; a missed horizon alone
/// has no calibration effect.
pub fn project_review_dissent(vault: &Vault, result: &ReviewResult, at: u64) -> Result<usize> {
    let mut settled = 0;
    for artifact in result
        .artifacts
        .iter()
        .filter(|artifact| !artifact.out_of_scope && artifact.prediction.is_some())
    {
        let stored = persisted_artifact(vault, &result.verdict_claim, &artifact.artifact_id)?;
        let (principal, mut state, _) =
            dissent_state(vault, &result.verdict_claim, &stored.artifact_id)?;
        let Some(question) = state.question else {
            continue;
        };
        questions::project_bound_outcomes(vault, principal, question)?;
        let pairs = questions::calibration_pairs(
            vault,
            principal,
            question,
            crate::claim::CallerLocality::OnDevice,
        )?;
        let Some(pair) = pairs
            .into_iter()
            .min_by_key(|pair| (pair.outcome.occurred_at, pair.outcome.fact))
        else {
            if state.settled_fact.take().is_some() {
                crate::learning::withdraw_evidence(
                    vault,
                    &stored.calibration,
                    &outcomes::calibration_receipt(&result.verdict_claim, &stored.artifact_id),
                    at,
                )?;
                save_dissent(vault, &result.verdict_claim, &state)?;
            }
            continue;
        };
        if pair.outcome.noise_weight == 0.0 {
            continue;
        }
        let mut evidence = LearningEvidence::anchored(
            outcomes::calibration_receipt(&result.verdict_claim, &stored.artifact_id),
            pair.outcome.occurred_at,
            Anchor::WorldOutcome,
            Observation::Success(pair.outcome.label),
        );
        evidence.weight = pair.outcome.noise_weight;
        crate::learning::record_evidence(vault, &stored.calibration, &evidence, at)?;
        state.settled_fact = Some(pair.outcome.fact);
        save_dissent(vault, &result.verdict_claim, &state)?;
        settled += 1;
    }
    Ok(settled)
}

/// The measured-state sweep also folds newly arrived facts for retained dissent.
pub fn project_all_review_dissent(vault: &Vault, at: u64) -> Result<usize> {
    let mut settled = 0;
    for review in reviews_with_dissent(vault)? {
        settled += project_review_dissent(vault, &review, at)?;
    }
    Ok(settled)
}
