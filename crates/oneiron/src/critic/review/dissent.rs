//! Testable overruled predictions: attributed opinions and bound standing questions,
//! never critique claims. Facts, not elapsed horizons or agreement, settle them.
use super::*;
use crate::learning::{Anchor, LearningEvidence, Observation};
use crate::llm::decision::questions::{
    self, OutcomeBinding, QuestionActivation, QuestionDefinitionInput, RefreshPolicy,
    StandingAnswer,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestionInput, ProviderPin,
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
/// A critique without a prediction stays in its run-tree branch. A caller
/// claims the dissent before it authors any of it (FIX 12161): while another
/// caller in this run keeps it, this one does nothing and gives back `None`.
pub fn preserve_review_dissent(
    vault: &Vault,
    result: &ReviewResult,
    artifact_id: &str,
    at: u64,
) -> Result<Option<ReviewDissent>> {
    let artifact = persisted_artifact(vault, &result.verdict_claim, artifact_id)?;
    if artifact.prediction.is_none() {
        return Ok(None);
    }
    validate_critique_artifact(&artifact)?;
    let (principal, class, state, verdict) =
        dissent_state(vault, &result.verdict_claim, artifact_id)?;
    if verdict == artifact.verdict && !dismissed(vault, &result.verdict_claim, artifact_id)? {
        return Ok(None);
    }
    let state = if state.note.is_some() && state.question.is_some() {
        state
    } else {
        let Some(state) = claim_dissent(vault, &result.verdict_claim, artifact_id)? else {
            return Ok(None);
        };
        let kept = author_claimed_dissent(
            vault,
            &result.verdict_claim,
            &artifact,
            principal,
            class,
            state,
        );
        if let Err(error) = release_dissent_claim(vault, &result.verdict_claim, artifact_id) {
            tracing::warn!(
                kind = ?error.kind(),
                "a dissent's claim was not released; the next run resumes it"
            );
        }
        kept?
    };
    let actor = artifact.provenance.actor()?;
    let unit = EntityId::from_hex(&artifact.candidate_ref)?;
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
            rule: None,
            source_frontier: frontier,
        },
        artifact.created_at,
    )?;
    // Backfill also catches facts that arrived before the dissent was retained.
    project_review_dissent(vault, result, at)?;
    Ok(Some(state))
}

/// Authors the NOTE and the standing question a claimed dissent still lacks,
/// saving each as it lands, so a dissent that stops resumes without a second.
fn author_claimed_dissent(
    vault: &Vault,
    verdict: &EntityId,
    artifact: &CritiqueArtifact,
    principal: EntityId,
    class: Option<crate::EdgeActorClass>,
    mut state: ReviewDissent,
) -> Result<ReviewDissent> {
    let Some(prediction) = &artifact.prediction else {
        return Ok(state);
    };
    let actor = artifact.provenance.actor()?;
    if state.note.is_none() {
        let markdown = serde_json::to_string_pretty(prediction)
            .map_err(|_| invalid_critic_config("dissent prediction encoding"))?;
        let receipt = vault
            .memory(actor.entity_ref(), actor.actor_class())
            .author_dissent(TakeTarget::Claim(*verdict), markdown)
            .map_err(|error| invalid_critic_config(error.to_string()))?;
        state.note = Some(EntityId::from_hex(&receipt.id_hex)?);
        save_dissent(vault, verdict, &state)?;
    }
    if state.question.is_none() {
        // The question keeps the class its review's actor authenticated as
        // (FIX 1588); a review stored before that asks as its principal reads.
        let asker = match class {
            Some(class) => WriteActor::new(principal, class),
            None => questions::principal_actor(vault, principal)?,
        };
        let record = questions::create_question(
            vault,
            asker,
            QuestionDefinitionInput {
                question: DecisionQuestionInput {
                    text: prediction.what.clone(),
                    class: DecisionClass::Judgment,
                    contract: AnswerContract::Noul,
                    accept_type: false,
                },
                adapter: "graph".to_owned(),
                units: vec![EntityId::from_hex(&artifact.candidate_ref)?],
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
        save_dissent(vault, verdict, &state)?;
    }
    Ok(state)
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
/// has no calibration effect unless the binding has a `silence` key, which pairs like a fact.
pub fn project_review_dissent(vault: &Vault, result: &ReviewResult, at: u64) -> Result<usize> {
    let mut settled = 0;
    for artifact in result
        .artifacts
        .iter()
        .filter(|artifact| !artifact.out_of_scope && artifact.prediction.is_some())
    {
        let stored = persisted_artifact(vault, &result.verdict_claim, &artifact.artifact_id)?;
        let (principal, _, mut state, _) =
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
                // The critique's standing outcome takes its receipt back in
                // the same write (FIX 12219).
                outcomes::withdraw_fact_evidence(vault, &result.verdict_claim, &stored, at)?;
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
/// It first records the evidence each standing critique outcome still owes
/// (FIX 12159), then keeps the dissent an overruling triage or outcome left
/// unkept (FIX 12105, 12161).
pub fn project_all_review_dissent(vault: &Vault, at: u64) -> Result<usize> {
    if let Err(error) = outcomes::finish_owed_outcomes(vault, at) {
        tracing::warn!(
            kind = ?error.kind(),
            "the critique outcomes owing evidence did not read; the sweep goes on"
        );
    }
    keep_overruled_dissent(vault, at)?;
    let mut settled = 0;
    for review in reviews_with_dissent(vault)? {
        settled += project_review_dissent(vault, &review, at)?;
    }
    Ok(settled)
}

/// Keeps the dissent of each predicted critique that its review's triage or
/// a `review.outcome` valued false overruled and whose dissent has no
/// standing question yet (FIX 12105, 12161). An outcome recorded inside
/// another write, such as a team's settlement in the owner's inbox decision,
/// keeps no dissent there, since keeping it opens writes of its own; one
/// whose dissent stopped after its commit, or whose review's own keep failed,
/// resumes here. A critique whose outcome does not read is skipped, and one
/// whose dissent does not keep warns; the sweep goes on.
fn keep_overruled_dissent(vault: &Vault, at: u64) -> Result<()> {
    for (review, artifacts) in reviews_with_unkept_dissent(vault)? {
        for artifact_id in &artifacts {
            let triage_overruled = review.artifacts.iter().any(|artifact| {
                artifact.artifact_id == *artifact_id && artifact.verdict != review.triage.verdict
            });
            if !triage_overruled {
                match dismissed(vault, &review.verdict_claim, artifact_id) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            "a critique's outcome did not read; its dissent waits"
                        );
                        continue;
                    }
                }
            }
            if let Err(error) = preserve_review_dissent(vault, &review, artifact_id, at) {
                tracing::warn!(
                    kind = ?error.kind(),
                    "an overruled critique's dissent was not kept; the sweep goes on"
                );
            }
        }
    }
    Ok(())
}
