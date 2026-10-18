//! Freeze the question's own labels, check backend reads and bind the sufficiency card.

use super::*;
use crate::claim::CallerLocality;
use crate::llm::decision::questions::{answer_records_in_txn, calibration_pairs_in_txn, read_question_in_txn};
use crate::llm::decision::{AnswerContract, DecisionAnswer};
use crate::llm::registry::invalid;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn freeze_cases(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &ModelTrialRequest,
    locality: CallerLocality,
) -> Result<Vec<FrozenTrialCase>> {
    let question = read_question_in_txn(
        vault,
        txn,
        request.principal,
        request.question,
        Some(request.question_version),
    )?
    .ok_or(Error::EntityNotFound)?;
    if !matches!(question.definition.question.contract, AnswerContract::Noul) {
        return Err(invalid(
            "bound model trials require a yes/no outcome contract",
        ));
    }
    let answers = answer_records_in_txn(vault, txn, request.principal, request.question)?;
    let pairs = calibration_pairs_in_txn(vault, txn, request.principal, request.question, locality)?;
    let mut seen = BTreeSet::new();
    request
        .held_out
        .iter()
        .map(|selection| {
            if selection.source_family.trim().is_empty()
                || selection.source_family.len() > 256
                || !seen.insert(selection.answer)
            {
                return Err(invalid("invalid or duplicate held-out source family"));
            }
            let answer = answers
                .iter()
                .find(|answer| {
                    answer.claim == selection.answer
                        && answer.decision.receipt.question_version == request.question_version
                })
                .ok_or_else(|| invalid("held-out answer is not from this question version"))?;
            let pair = pairs
                .iter()
                .find(|pair| {
                    pair.outcome.answer == selection.answer && pair.outcome.fact == selection.fact
                })
                .ok_or(Error::EntityNotFound)?;
            if !pair.outcome.noise_weight.is_finite() || pair.outcome.noise_weight <= 0.0 {
                return Err(invalid("held-out labels need positive noise weights"));
            }
            Ok(FrozenTrialCase {
                selection: selection.clone(),
                unit: answer.unit,
                source_frontier: answer.frontier,
                fact_value_hash: pair.outcome.fact_value_hash,
                label: pair.outcome.label,
                noise_weight: pair.outcome.noise_weight,
                derived_from: pair.derived_from.clone(),
            })
        })
        .collect()
}

fn reading(
    trial: &ModelTrial,
    backend: &PricedModelBackend,
    input: TrialReading,
) -> Result<(
    Option<crate::llm::decision::TypedDecision>,
    ModelCostReceipt,
)> {
    if input.backend != backend.pin {
        return Err(invalid("trial read used another backend serving pin"));
    }
    let cost = backend.cost_receipt(input.usage, 1)?;
    let mut decision = input.decision;
    if let Some(value) = &mut decision {
        let receipt = &mut value.receipt;
        if receipt.question != trial.request.question
            || receipt.question_version != trial.request.question_version
            || receipt.principal != trial.request.principal
            || receipt.providers.is_empty()
            || receipt.providers.iter().any(|provider| {
                provider.model != backend.pin.model.as_str()
                    || provider.version != backend.pin.model.revision()
            })
            || !matches!(
                value.answer,
                DecisionAnswer::Noul(_) | DecisionAnswer::Abstain
            )
            || value
                .probability
                .is_some_and(|p| !p.is_finite() || !(0.0..=1.0).contains(&p))
        {
            return Err(invalid(
                "trial read does not match the pinned question and model",
            ));
        }
        receipt.cost_per_thousand = Some(cost.cost_per_thousand);
    }
    Ok((decision, cost))
}

fn loss(value: &Option<crate::llm::decision::TypedDecision>, label: bool) -> Option<f64> {
    let value = value.as_ref()?;
    if !matches!(value.answer, DecisionAnswer::Noul(_)) {
        return None;
    }
    Some((value.probability? - if label { 1.0 } else { 0.0 }).powi(2))
}

pub(super) fn measure(
    trial: &ModelTrial,
    observations: Vec<TrialObservation>,
) -> Result<TrialEvidence> {
    if observations.len() != trial.cases.len() {
        return Err(invalid(
            "trial needs one billed observation per held-out case",
        ));
    }
    let mut by_answer = BTreeMap::new();
    for observation in observations {
        let id = observation.answer;
        if by_answer.insert(id, observation).is_some() {
            return Err(invalid("duplicate held-out measurement"));
        }
    }
    let mut measurements = Vec::new();
    let mut families = BTreeMap::<&str, (f64, f64, f64)>::new();
    let mut complete = true;
    let (mut incumbent_cost, mut candidate_cost) = (0.0, 0.0);
    for case in &trial.cases {
        let input = by_answer
            .remove(&case.selection.answer)
            .ok_or_else(|| invalid("held-out measurement missing"))?;
        let (incumbent, old_cost) = reading(trial, &trial.incumbent, input.incumbent)?;
        let (candidate, new_cost) = reading(trial, &trial.candidate, input.candidate)?;
        incumbent_cost += old_cost.cost;
        candidate_cost += new_cost.cost;
        let family = families.entry(&case.selection.source_family).or_default();
        match (loss(&incumbent, case.label), loss(&candidate, case.label)) {
            (Some(old), Some(new)) => {
                family.0 += old * case.noise_weight;
                family.1 += new * case.noise_weight;
                family.2 += case.noise_weight;
            }
            _ => complete = false,
        }
        measurements.push(TrialMeasurement {
            answer: case.selection.answer,
            incumbent,
            candidate,
            incumbent_cost: old_cost,
            candidate_cost: new_cost,
        });
    }
    let units = trial.cases.len() as f64;
    let trial_cost = incumbent_cost + candidate_cost;
    let incumbent_cost_per_thousand = incumbent_cost * 1_000.0 / units;
    let candidate_cost_per_thousand = candidate_cost * 1_000.0 / units;
    if [
        trial_cost,
        incumbent_cost_per_thousand,
        candidate_cost_per_thousand,
    ]
    .iter()
    .any(|value| !value.is_finite())
    {
        return Err(invalid("trial cost overflow"));
    }
    let incumbent_loss = complete.then(|| {
        families
            .values()
            .map(|family| family.0 / family.2)
            .sum::<f64>()
            / families.len() as f64
    });
    let candidate_loss = complete.then(|| {
        families
            .values()
            .map(|family| family.1 / family.2)
            .sum::<f64>()
            / families.len() as f64
    });
    let encoded =
        crate::llm::canonical_json_bytes(&(&trial.request.set, &trial.cases, &measurements))
            .map_err(|error| invalid(error.to_string()))?;
    Ok(TrialEvidence {
        measurements,
        measurements_hash: *blake3::hash(&encoded).as_bytes(),
        incumbent_loss,
        candidate_loss,
        independent_families: families.len(),
        incumbent_cost_per_thousand,
        candidate_cost_per_thousand,
        trial_cost,
    })
}

pub(super) fn quality(
    trial: &ModelTrial,
    evidence: &TrialEvidence,
    assessment: &TrialAssessment,
) -> Result<TrialQuality> {
    if assessment.set != trial.request.set
        || assessment.measurements_hash != evidence.measurements_hash
        || !assessment.retest_noise.is_finite()
        || assessment.retest_noise < 0.0
        || assessment.stricter_margin.is_some_and(|margin| {
            !margin.is_finite() || margin < 0.0 || margin > assessment.retest_noise
        })
        || assessment.required_families == 0
    {
        return Err(invalid(
            "trial sufficiency card does not match the measured set",
        ));
    }
    let Some(interval) = assessment.paired_gain else {
        return Ok(TrialQuality::Unknown);
    };
    if !interval.low.is_finite() || !interval.high.is_finite() || interval.low > interval.high {
        return Err(invalid("invalid paired quality interval"));
    }
    let (Some(old), Some(new)) = (evidence.incumbent_loss, evidence.candidate_loss) else {
        return Ok(TrialQuality::Unknown);
    };
    if !assessment.versions_match
        || assessment.canary_diverged
        || !assessment.rare_slices_sufficient
        || evidence.independent_families < assessment.required_families
        || evidence.trial_cost > trial.estimated_cost
        || old - new < interval.low
        || old - new > interval.high
    {
        return Ok(TrialQuality::Unknown);
    }
    let margin = assessment
        .stricter_margin
        .unwrap_or(assessment.retest_noise);
    Ok(if interval.low > 0.0 {
        TrialQuality::Better
    } else if interval.low > -margin {
        TrialQuality::NotWorse
    } else if interval.high < -margin {
        TrialQuality::Worse
    } else {
        TrialQuality::Unknown
    })
}

pub(super) fn action(
    trial: &ModelTrial,
    evidence: &TrialEvidence,
    quality: TrialQuality,
) -> ModelTrialAction {
    let old = evidence.incumbent_cost_per_thousand;
    let new = evidence.candidate_cost_per_thousand;
    let policy = &trial.request.policy;
    match quality {
        TrialQuality::Unknown => ModelTrialAction::Unknown,
        TrialQuality::Worse => ModelTrialAction::Stay,
        TrialQuality::Better | TrialQuality::NotWorse
            if new < old || (quality == TrialQuality::Better && new <= old) =>
        {
            if policy.auto_approve && !policy.candidate_needs_download {
                ModelTrialAction::AutoApprove
            } else {
                ModelTrialAction::Offer
            }
        }
        TrialQuality::Better if new > old => {
            let caps: Vec<f64> = [policy.vault_cost_cap, policy.project_cost_cap]
                .into_iter()
                .flatten()
                .collect();
            if !caps.is_empty() && caps.iter().all(|cap| new <= *cap) {
                ModelTrialAction::Offer
            } else {
                ModelTrialAction::AskTradeoff
            }
        }
        _ => ModelTrialAction::Stay,
    }
}
