//! Route-conditioned calibration (Engine row 22229, after StartLux-Decision's policy-aware
//! fit): a question's calibration pairs grouped by how each answer was returned, an isotonic
//! map fitted on one half of each group's source cases, and the raw and fitted calibration,
//! accepted error and coverage measured on the other half. The report sits beside the per-seat
//! question evaluation and shares its definitions. A fitted probability is advice: no band,
//! grant, scope, critical-write check, consent or route reads it, and nothing keeps it.

mod isotonic;
mod metrics;
pub(super) mod receipt_route;
mod report;
mod split;

pub use metrics::ECE_BINS;
pub(super) use receipt_route::answer_pair;
pub use report::{
    AcceptanceAtCut, CalibrationMetrics, CalibrationPairRef, MapKnot, RouteCalibrationGroup,
    RouteCalibrationMap, RouteCalibrationReport, RouteFit, RouteFitRefusal, RouteGroupKey,
};

use super::{CalibrationPair, calibration_pairs};
use crate::llm::decision::DecisionAnswer;
use crate::{EntityId, Result, Vault};

/// The fewest fit-half pairs a route group needs for a fitted map: one pair fits a constant,
/// which orders nothing. A structural floor, not a sample-size target: the check half's
/// numbers show what a small fit is worth.
const MIN_ROUTE_FIT_PAIRS: usize = 2;

/// `principal`'s question `question` calibrated per route: its [`calibration_pairs`], read
/// with the same caller and world rechecks and the same `destination` filter, grouped by
/// [`RouteGroupKey`], each group's map fitted on its fit half and measured on its check half.
/// Any vault whose question has answer receipts and outcome labels reads it, a bench vault
/// included; another principal's question has no pairs, so no groups.
///
/// # Errors
/// As [`calibration_pairs`].
pub fn route_calibration_report(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<crate::settings::ReadDestination>,
) -> Result<RouteCalibrationReport> {
    let pairs = calibration_pairs(vault, principal, question, destination)?;
    Ok(report(question, &pairs))
}

/// The report of `question`'s `pairs`: groups in the order their first pair was read.
fn report(question: EntityId, pairs: &[CalibrationPair]) -> RouteCalibrationReport {
    let sides = split::fit_sides(question, pairs);
    let mut groups: Vec<(RouteGroupKey, Vec<(&CalibrationPair, bool)>)> = Vec::new();
    for (pair, fit) in pairs.iter().zip(sides) {
        let key = RouteGroupKey {
            question_version: pair.question_version,
            route: pair.route,
            policy: pair.policy,
            providers: pair.providers.clone(),
        };
        match groups.iter().position(|(held, _)| *held == key) {
            Some(at) => groups[at].1.push((pair, fit)),
            None => groups.push((key, vec![(pair, fit)])),
        }
    }
    let derived_from: std::collections::BTreeSet<EntityId> = pairs
        .iter()
        .flat_map(|pair| pair.derived_from.iter().copied())
        .collect();
    RouteCalibrationReport {
        question,
        groups: groups
            .into_iter()
            .map(|(key, members)| group(question, key, &members))
            .collect(),
        derived_from: derived_from.into_iter().collect(),
    }
}

/// One route group: its check half's raw calibration, and its map fitted on its fit half
/// when the fit half holds [`MIN_ROUTE_FIT_PAIRS`] pairs and weighs something.
fn group(
    question: EntityId,
    key: RouteGroupKey,
    members: &[(&CalibrationPair, bool)],
) -> RouteCalibrationGroup {
    let fit: Vec<&CalibrationPair> = members
        .iter()
        .filter(|(_, fit)| *fit)
        .map(|(pair, _)| *pair)
        .collect();
    let check: Vec<&CalibrationPair> = members
        .iter()
        .filter(|(_, fit)| !*fit)
        .map(|(pair, _)| *pair)
        .collect();
    let raw = metrics::calibration(check.iter().copied().map(point));
    let outcome = if fit.len() < MIN_ROUTE_FIT_PAIRS {
        RouteFit::Refused {
            reason: RouteFitRefusal::TooFewFitPairs {
                needed: MIN_ROUTE_FIT_PAIRS,
            },
        }
    } else {
        let points: Vec<(f64, bool, f64)> = fit.iter().copied().map(point).collect();
        let knots = isotonic::fit(&points);
        if knots.is_empty() {
            RouteFit::Refused {
                reason: RouteFitRefusal::WeightlessFit,
            }
        } else {
            let fitted = metrics::calibration(check.iter().copied().map(|pair| {
                let (probability, label, weight) = point(pair);
                (isotonic::apply(&knots, probability), label, weight)
            }));
            let checked: Vec<metrics::Judged> =
                check.iter().map(|pair| judged(&knots, pair)).collect();
            let acceptance = metrics::acceptance(&knots, &checked);
            RouteFit::Fitted {
                map: RouteCalibrationMap {
                    question,
                    key: key.clone(),
                    fit: fit
                        .iter()
                        .map(|pair| CalibrationPairRef {
                            answer: pair.outcome.answer,
                            fact: pair.outcome.fact,
                        })
                        .collect(),
                    knots,
                },
                fitted,
                acceptance,
            }
        }
    };
    RouteCalibrationGroup {
        key,
        fit_pairs: fit.len(),
        check_pairs: check.len(),
        raw,
        fit: outcome,
    }
}

/// `pair` as the fit and the calibration read it: its raw probability, its label and the
/// label's noise weight. A probability outside 0..=1, or a weight that is not a finite
/// positive number, weighs nothing.
fn point(pair: &CalibrationPair) -> (f64, bool, f64) {
    let probability = pair.probability;
    let weight = pair.outcome.noise_weight;
    let measured = probability.is_finite()
        && (0.0..=1.0).contains(&probability)
        && weight.is_finite()
        && weight > 0.0;
    (
        probability,
        pair.outcome.label,
        if measured { weight } else { 0.0 },
    )
}

/// `pair` as the acceptance table reads it: the map's fitted confidence in the pair's own
/// answer and whether that answer was right. A yes/no answer's probability is P(yes), and its
/// label the outcome; any other answer's label says whether it held. An abstention is never
/// accepted.
fn judged(knots: &[MapKnot], pair: &CalibrationPair) -> metrics::Judged {
    let (probability, label, weight) = point(pair);
    let fitted = isotonic::apply(knots, probability);
    let (confidence, right) = match &pair.prediction {
        DecisionAnswer::Noul(yes) => (
            Some(if *yes { fitted } else { 1.0 - fitted }),
            *yes == label,
        ),
        DecisionAnswer::Choice(_)
        | DecisionAnswer::Score(_)
        | DecisionAnswer::Box(_)
        | DecisionAnswer::Point(_) => (Some(fitted), label),
        DecisionAnswer::Abstain => (None, false),
    };
    metrics::Judged {
        confidence,
        right,
        weight,
    }
}
