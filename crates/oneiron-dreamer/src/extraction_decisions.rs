//! Decides one bound extraction reply without deriving or writing claims.
//!
//! Corrections use the complete listed-subject operand array before routing.
//! Corrected operands are reobserved and folded into evidence unions. Each
//! non-skipped set then reads and judges exactly its retained component.

use std::collections::BTreeMap;
use std::fmt;

use oneiron_remote::OneironClient;
use serde_json::Value;

use crate::conflict_decisions::{self, ConflictDecision, Correction, ResolutionInput};
use crate::extraction_observations::{self, Observations, read_observations};
use crate::extraction_reply::{BoundExtractionReply, ExtractionOperands, decision_operands};
use crate::extraction_routing::{self, ExtractionRoutePlan, JudgeSet};
use crate::extraction_selection::{self, ExtractionSelectionConfig, ExtractionSelectionPlan};

mod skips;
mod verdict;

pub use skips::{bound_correction, fast_path};

/// Borrows the bound client and the unchanged inputs for one reply's decisions.
#[derive(Clone, Copy)]
pub struct Input<'a> {
    /// Borrows the client bound to this admitted extraction attempt.
    pub client: &'a OneironClient,
    /// Names the admitted extraction attempt.
    pub attempt: &'a str,
    /// Holds the attempt's clock in Unix milliseconds for every observations read.
    pub now_ms: u64,
    /// Borrows the decoded bound extraction reply.
    pub reply: &'a BoundExtractionReply,
    /// Borrows the effective selection configuration served to the caller.
    pub config: &'a ExtractionSelectionConfig,
    /// Pins the effective policy required by every observations read.
    pub policy_pin: &'a str,
}

/// Names which native no-model rule selected a prior head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipRule {
    /// Uses the retained identity's single-valued predicate.
    FastPath,
    /// Uses the surviving correction bound to the set's sole head.
    BoundCorrection,
}

/// Records exactly one result for a routed judge set.
#[derive(Debug, Clone, PartialEq)]
pub enum SetOutcome {
    /// Records a no-model replacement target without inventing a decision receipt.
    Skipped {
        /// Names the prior head that e2g may apply as the supersession target.
        prior_head: String,
        /// Records the first native skip rule that holds.
        rule: SkipRule,
    },
    /// Preserves the pure fold's resolution and actual ordered decision entries.
    Decided(ConflictDecision),
}

/// Hands correction and conflict decisions to the later landing policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Holds complete listed-subject operands with only chosen corrections added.
    pub operands: Vec<Value>,
    /// Maps each operand position to its candidate index in the decoded reply.
    pub candidate_indexes: Vec<usize>,
    /// Holds one correction result per operand in complete operand order.
    pub corrections: Vec<Correction>,
    /// Holds selection read after applying corrections and observing evidence unions.
    pub selection: ExtractionSelectionPlan,
    /// Holds the route plan built from those same post-correction observations.
    pub route: ExtractionRoutePlan,
    /// Holds one outcome per judge set in route-plan order.
    pub sets: Vec<SetOutcome>,
}

/// Explains why the whole decision run stopped without returning partial output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Preserves a bound verdict refusal and its engine code.
    Client {
        /// Names the refused verb.
        verb: &'static str,
        /// Preserves the engine's refusal code.
        code: String,
        /// Preserves the engine's refusal message without interpreting it.
        message: String,
    },
    /// Describes an operand or request that could not be encoded or decoded.
    Decode {
        /// Names the input or verb being decoded.
        verb: &'static str,
        /// Describes the serialization failure.
        message: String,
    },
    /// Preserves a refusal by the existing pure decision folds.
    Decisions(conflict_decisions::Error),
    /// Preserves a bound observations failure.
    Observations(extraction_observations::Error),
    /// Preserves a selection or routing failure.
    Routing(extraction_routing::Error),
    /// Rejects missing served positions, retained identities or prior rows.
    InvalidObservations(String),
    /// Rejects a member whose claim changed between routing and component reads.
    IdentityMoved {
        /// Names the member's position in the complete operand array.
        candidate: usize,
        /// Holds the claim served for routing.
        expected: String,
        /// Holds the claim served for the exact component read.
        actual: String,
    },
    /// Preserves a typed layout refusal whose field could not be decoded.
    Layout {
        /// Preserves the refusal's engine code.
        code: String,
        /// Preserves its message without interpreting it.
        message: String,
        /// Preserves the typed layout decoder's failure.
        error: conflict_decisions::Error,
    },
    /// Rejects a second layout refusal for the same read after supplying a layout.
    RepeatedLayout {
        /// Preserves the second refusal's engine code.
        code: String,
        /// Preserves its message without interpreting it.
        message: String,
    },
}

impl Error {
    /// Returns the engine code for a direct or wrapped bound refusal.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. }
            | Self::Layout { code, .. }
            | Self::RepeatedLayout { code, .. } => Some(code),
            Self::Observations(error) => error.code(),
            Self::Routing(extraction_routing::Error::Selection(
                extraction_selection::Error::Observations(error),
            )) => error.code(),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "extraction decisions: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Decides corrections, refreshes routing and skips or decides every judge set.
///
/// Every refusal except the first typed layout refusal ends the whole run.
/// Successful abstentions and escalations remain decisions. No deadline cap,
/// retry, fallback, merged value, marker or write is introduced here.
///
/// # Errors
///
/// Preserves client codes, pure-policy and read errors, and rejects missing
/// routing context or a member identity that moved before its component read.
pub fn run(input: Input<'_>) -> Result<Outcome, Error> {
    check_policy(input.policy_pin, &input.config.policy_pin)?;
    let ExtractionOperands {
        mut operands,
        candidate_indexes,
    } = decision_operands(input.reply).map_err(|error| Error::Decode {
        verb: "extraction reply",
        message: error.to_string(),
    })?;
    let observations = observe(input, &operands)?;
    let corrections = verdict::corrections(
        input.client,
        conflict_decisions::Input {
            candidates: &operands,
            observations: &observations,
        },
    )?;
    for correction in &corrections {
        if let Some(head) = &correction.corrects {
            let operand = operands.get_mut(correction.candidate).ok_or_else(|| {
                Error::InvalidObservations("a correction names an unknown operand".into())
            })?;
            operand["corrects"] = Value::String(head.clone());
        }
    }
    let (groups, observations) = extraction_selection::observe_groups(
        input.client,
        input.attempt,
        input.now_ms,
        &operands,
        input.policy_pin,
    )
    .map_err(|error| Error::Routing(error.into()))?;
    let selection =
        extraction_selection::select(&groups, &observations, input.now_ms, input.config)
            .map_err(|error| Error::Routing(error.into()))?;
    let route = extraction_routing::route(&selection, &observations, input.config)
        .map_err(Error::Routing)?;
    let unions = extraction_selection::union_operands(&operands, &groups);
    let union_positions: BTreeMap<usize, usize> = groups
        .groups
        .iter()
        .enumerate()
        .map(|(position, group)| (group.representative_index, position))
        .collect();
    let mut sets = Vec::with_capacity(route.judge_sets.len());
    for set in &route.judge_sets {
        let rule = if fast_path(set, &observations)? {
            Some(SkipRule::FastPath)
        } else if bound_correction(set, &observations, &route.corrections)? {
            Some(SkipRule::BoundCorrection)
        } else {
            None
        };
        if let Some(rule) = rule {
            let prior_head = set.prior_head.clone().ok_or_else(|| {
                Error::InvalidObservations("a skipped set has no prior head".into())
            })?;
            sets.push(SetOutcome::Skipped { prior_head, rule });
        } else {
            let component = component_operands(set, &unions, &union_positions)?;
            let component_observations = observe(input, &component)?;
            let local = local_set(set)?;
            check_members(set, &local, &observations, &component_observations)?;
            let mut decision = verdict::resolution(
                input.client,
                ResolutionInput {
                    input: conflict_decisions::Input {
                        candidates: &component,
                        observations: &component_observations,
                    },
                    set: &local,
                },
            )?;
            if let Some(identity) = decision.identity {
                decision.identity =
                    Some(*set.component_indexes.get(identity).ok_or_else(|| {
                        Error::InvalidObservations(
                            "a kept identity is outside its component".into(),
                        )
                    })?);
            }
            sets.push(SetOutcome::Decided(decision));
        }
    }
    Ok(Outcome {
        operands,
        candidate_indexes,
        corrections,
        selection,
        route,
        sets,
    })
}

fn observe(input: Input<'_>, operands: &[Value]) -> Result<Observations, Error> {
    let observations = read_observations(input.client, input.attempt, input.now_ms, operands)
        .map_err(Error::Observations)?;
    check_policy(input.policy_pin, &observations.policy_pin)?;
    Ok(observations)
}

fn check_policy(expected: &str, actual: &str) -> Result<(), Error> {
    if expected != actual {
        return Err(Error::Routing(extraction_routing::Error::PolicyPin {
            expected: expected.into(),
            actual: actual.into(),
        }));
    }
    Ok(())
}

fn component_operands(
    set: &JudgeSet,
    unions: &[Value],
    union_positions: &BTreeMap<usize, usize>,
) -> Result<Vec<Value>, Error> {
    set.component_indexes
        .iter()
        .map(|index| {
            union_positions
                .get(index)
                .and_then(|position| unions.get(*position))
                .cloned()
                .ok_or_else(|| {
                    Error::InvalidObservations("a component names an unknown group".into())
                })
        })
        .collect()
}

fn local_set(set: &JudgeSet) -> Result<JudgeSet, Error> {
    let candidate_indexes = set
        .candidate_indexes
        .iter()
        .map(|index| {
            set.component_indexes
                .iter()
                .position(|component| component == index)
                .ok_or_else(|| {
                    Error::InvalidObservations("a set member is outside its component".into())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JudgeSet {
        candidate_indexes,
        component_indexes: (0..set.component_indexes.len()).collect(),
        identity_token: set.identity_token.clone(),
        prior_heads: set.prior_heads.clone(),
        prior_head: set.prior_head.clone(),
    })
}

fn check_members(
    set: &JudgeSet,
    local: &JudgeSet,
    routed: &Observations,
    component: &Observations,
) -> Result<(), Error> {
    for (index, local_index) in set.candidate_indexes.iter().zip(&local.candidate_indexes) {
        let before = routed.candidates.iter().find(|row| row.index == *index);
        let after = component
            .candidates
            .iter()
            .find(|row| row.index == *local_index);
        let (Some(before), Some(after)) = (before, after) else {
            return Err(Error::InvalidObservations(
                "a set member has no observation row".into(),
            ));
        };
        if before.claim != after.claim {
            return Err(Error::IdentityMoved {
                candidate: *index,
                expected: before.claim.clone(),
                actual: after.claim.clone(),
            });
        }
    }
    Ok(())
}
