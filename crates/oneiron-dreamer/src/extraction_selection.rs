//! Groups extraction operands and selects their verified evidence unions.
//!
//! Equality tokens and selection facts come from the bound observations read.
//! This module chooses only grouping, strength order, holds and a retry suggestion.
//! It neither derives claim identifiers nor routes candidates against prior claims.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;

use oneiron_remote::OneironClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::extraction_observations::{self, CandidateObservation, Observations, read_observations};
use crate::strength_scoring::{SelectionConfig, StrengthSignals};

/// Mirrors the effective selection policy together with the inputs page's policy pin.
/// Scheduling fields are ignored; every selection and scoring field is required.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ExtractionSelectionConfig {
    /// Names the native selection policy version.
    pub version: u8,
    /// Gives the required evidence soak duration in milliseconds.
    pub soak_ms: u64,
    /// Gives the minimum verified distinct citation count.
    pub evidence_minimum: usize,
    /// Carries the native threshold for validation, without nominating any conflicts.
    pub cosine_threshold: f64,
    /// Holds the unchanged scoring subset shared with the strength archive.
    #[serde(flatten)]
    scoring: SelectionConfig,
    /// Pins the full effective extraction policy, not just the scoring subset.
    pub policy_pin: String,
}

impl ExtractionSelectionConfig {
    /// Reads the inputs page's selection row and binds its separately served policy pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] if the row is not an object or a required field is missing.
    pub fn from_selection(mut selection: Value, policy_pin: &str) -> Result<Self, Error> {
        let row = selection
            .as_object_mut()
            .ok_or_else(|| Error::Decode("the selection policy is not an object".to_owned()))?;
        row.insert(
            "policy_pin".to_owned(),
            Value::String(policy_pin.to_owned()),
        );
        serde_json::from_value(selection).map_err(|error| Error::Decode(error.to_string()))
    }

    /// Validates the consumed policy fields as native selection validates them.
    fn validate(&self) -> Result<(), Error> {
        let config = &self.scoring;
        let weights = &config.weights;
        if self.version != 1
            || config.frequency_scale == 0
            || config.diversity_scale == 0
            || config.recency_window_ms == 0
            || !unit(self.cosine_threshold)
            || !unit(config.default_type_prior)
            || config.type_priors.values().any(|prior| !unit(*prior))
            || [
                weights.type_prior,
                weights.frequency,
                weights.recency,
                weights.diversity,
            ]
            .iter()
            .any(|weight| !unit(*weight))
            || weights.type_prior <= weights.frequency + weights.recency + weights.diversity
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
}

/// Names one fold by its first request member and retains every original member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateGroup {
    /// Names the first member's original request index.
    pub representative_index: usize,
    /// Names all members in original request order.
    pub member_indexes: Vec<usize>,
    /// Names the claim every member corrects, or none when any member corrects
    /// nothing or another claim, as native assembly keeps a merged correction.
    pub corrects: Option<String>,
}

/// Keeps bound candidate groups separate from candidates still awaiting person binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateGroups {
    /// Holds groups in first-member request order.
    pub groups: Vec<CandidateGroup>,
    /// Names unbound request positions without dropping or grouping them.
    pub pending_bindings: Vec<usize>,
}

/// Carries one group's strength and its original request members.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredCandidateGroup {
    /// Names the first member's original request index.
    pub representative_index: usize,
    /// Names all members in original request order.
    pub member_indexes: Vec<usize>,
    /// Names the claim every member corrects, as [`CandidateGroup::corrects`] does.
    pub corrects: Option<String>,
    /// Gives the native four-signal weighted score, including for held groups.
    pub score: f64,
}

/// Gives the first native selection condition that holds a candidate back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionHold {
    /// The evidence is too young or its earliest time is in the future.
    Soak,
    /// The verified distinct citation count is below the policy minimum.
    EvidenceCount,
}

/// Records the selection choice under the final union read's policy and facts pins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractionSelectionPlan {
    /// Names ready representatives in native strength, rank and claim order.
    pub ready: Vec<usize>,
    /// Names held representatives and their reasons in native claim order.
    pub held: Vec<(usize, SelectionHold)>,
    /// Retains every group's score and member mapping in first-member order.
    pub groups: Vec<ScoredCandidateGroup>,
    /// Retains every request position awaiting person binding.
    pub pending_bindings: Vec<usize>,
    /// Suggests the native retry deadline without scheduling the attempt.
    pub retry_at_ms: u64,
    /// Names the full effective extraction policy used for this choice.
    pub policy_pin: String,
    /// Names the final read's complete union facts.
    pub facts_pin: String,
}

/// Explains why observations could not produce a selection plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Preserves a bound observations read failure.
    Observations(extraction_observations::Error),
    /// Describes a selection row that did not decode.
    Decode(String),
    /// Rejects a native-invalid consumed policy field or strength signal.
    InvalidConfig,
    /// Rejects a read under another effective policy.
    PolicyPin {
        /// Names the policy required by the caller.
        expected: String,
        /// Names the policy served or supplied instead.
        actual: String,
    },
    /// Describes missing, repeated or incorrectly indexed candidate observations.
    InvalidObservations(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observations(error) => write!(formatter, "{error}"),
            Self::Decode(message) => {
                write!(formatter, "cannot decode extraction selection: {message}")
            }
            Self::InvalidConfig => write!(
                formatter,
                "invalid consolidation selection policy or signals"
            ),
            Self::PolicyPin { expected, actual } => {
                write!(
                    formatter,
                    "selection requires policy {expected}, not {actual}"
                )
            }
            Self::InvalidObservations(message) => {
                write!(
                    formatter,
                    "invalid extraction selection observations: {message}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<extraction_observations::Error> for Error {
    fn from(error: extraction_observations::Error) -> Self {
        Self::Observations(error)
    }
}

/// Folds bound observations by native keys, as native assembly folds extracted candidates.
///
/// Rows are in request order. A `None` at a request position explicitly represents
/// a declared person with no native tokens yet. Bound rows retain their request indexes.
/// Native assembly folds by `(CandidateKeys, supersedes)`, and every extracted candidate
/// supersedes nothing, so the fold key is `CandidateKeys` alone: identity, topic and
/// value. Slice is redundant with identity and is not part of it. Members that correct
/// different claims still fold; the group keeps a correction only when every member
/// names the same claim.
#[must_use]
pub fn group_candidates(observations: &[Option<CandidateObservation>]) -> CandidateGroups {
    let mut result = CandidateGroups {
        groups: Vec::new(),
        pending_bindings: Vec::new(),
    };
    let mut by_key = BTreeMap::new();
    for (position, observation) in observations.iter().enumerate() {
        let Some(candidate) = observation else {
            result.pending_bindings.push(position);
            continue;
        };
        match by_key.entry(native_keys(candidate)) {
            Entry::Vacant(slot) => {
                slot.insert(result.groups.len());
                result.groups.push(CandidateGroup {
                    representative_index: candidate.index,
                    member_indexes: vec![candidate.index],
                    corrects: candidate.corrects.clone(),
                });
            }
            Entry::Occupied(slot) => {
                let group = &mut result.groups[*slot.get()];
                group.member_indexes.push(candidate.index);
                if group.corrects != candidate.corrects {
                    group.corrects = None;
                }
            }
        }
    }
    result
}

/// Names the native `CandidateKeys` equality tokens of one observation.
fn native_keys(candidate: &CandidateObservation) -> (&str, &str, &str) {
    (
        candidate.identity_token.as_str(),
        candidate.topic_token.as_str(),
        candidate.value_token.as_str(),
    )
}

/// Builds one operand per group with an ordered, exact-deduplicated evidence union.
///
/// Operands have the checked `CandidateOperand` shape. All other representative
/// fields, including the representative's own `corrects`, remain unchanged, so the
/// union keeps the representative's identity, as native assembly keeps the first
/// member's. The group's merged correction is [`CandidateGroup::corrects`]. The engine
/// recounts verified citations, times and diversity on these unions; none are summed.
///
/// # Panics
///
/// Panics if a group's member index does not name an operand in the supplied request.
#[must_use]
pub fn union_operands(operands: &[Value], groups: &CandidateGroups) -> Vec<Value> {
    groups
        .groups
        .iter()
        .map(|group| {
            let mut operand = operands[group.representative_index].clone();
            let mut evidence = Vec::new();
            for index in &group.member_indexes {
                if let Some(entries) = operands[*index]["evidence"].as_array() {
                    for entry in entries {
                        if !evidence.contains(entry) {
                            evidence.push(entry.clone());
                        }
                    }
                }
            }
            operand["evidence"] = Value::Array(evidence);
            operand
        })
        .collect()
}

/// Selects verified group unions with native scoring, holds, ordering and retry arithmetic.
///
/// Each observation's index names the original representative, not its compact union
/// request position. The remote adapter remaps those positions before calling here.
///
/// # Errors
///
/// Returns an error for a different clock or policy pin, invalid consumed policy
/// fields or signals, or anything other than one observation per bound group.
pub fn select(
    groups: &CandidateGroups,
    union_observations: &Observations,
    now_ms: u64,
    config: &ExtractionSelectionConfig,
) -> Result<ExtractionSelectionPlan, Error> {
    check_policy_pin(&config.policy_pin, &union_observations.policy_pin)?;
    config.validate()?;
    if union_observations.now_ms != now_ms {
        return Err(Error::InvalidObservations(
            "the read echoes another clock".to_owned(),
        ));
    }
    let by_index: BTreeMap<_, _> = union_observations
        .candidates
        .iter()
        .map(|candidate| (candidate.index, candidate))
        .collect();
    if by_index.len() != union_observations.candidates.len()
        || by_index.len() != groups.groups.len()
    {
        return Err(Error::InvalidObservations(
            "expected one row per group".to_owned(),
        ));
    }
    let mut ready = Vec::new();
    let mut held = Vec::new();
    let mut scored = Vec::new();
    let mut retry = None;
    for group in &groups.groups {
        let candidate = by_index.get(&group.representative_index).ok_or_else(|| {
            Error::InvalidObservations("a group representative has no union row".to_owned())
        })?;
        let score = candidate_score(candidate, now_ms, &config.scoring)?;
        scored.push(ScoredCandidateGroup {
            representative_index: group.representative_index,
            member_indexes: group.member_indexes.clone(),
            corrects: group.corrects.clone(),
            score,
        });
        let hold = if now_ms < candidate.first_seen_ms
            || now_ms - candidate.first_seen_ms < config.soak_ms
        {
            Some(SelectionHold::Soak)
        } else if candidate.evidence_count < config.evidence_minimum {
            Some(SelectionHold::EvidenceCount)
        } else {
            None
        };
        if let Some(hold) = hold {
            let deadline = match hold {
                SelectionHold::Soak => candidate.first_seen_ms.saturating_add(config.soak_ms),
                SelectionHold::EvidenceCount => now_ms.saturating_add(60_000),
            };
            retry = Some(retry.map_or(deadline, |previous: u64| previous.min(deadline)));
            held.push((candidate.claim.as_str(), group.representative_index, hold));
        } else {
            let rank = u128::from(candidate.fan_in) * (1 + u128::from(candidate.new_refs));
            ready.push((
                candidate.claim.as_str(),
                group.representative_index,
                score,
                rank,
            ));
        }
    }
    // Lowercase fixed-width claim hex sorts exactly like native EntityId bytes.
    ready.sort_by(|a, b| {
        b.2.total_cmp(&a.2)
            .then_with(|| b.3.cmp(&a.3))
            .then_with(|| a.0.cmp(b.0))
    });
    held.sort_by_key(|row| row.0);
    Ok(ExtractionSelectionPlan {
        ready: ready.into_iter().map(|(_, index, _, _)| index).collect(),
        held: held
            .into_iter()
            .map(|(_, index, hold)| (index, hold))
            .collect(),
        groups: scored,
        pending_bindings: groups.pending_bindings.clone(),
        retry_at_ms: retry.unwrap_or(now_ms).max(now_ms.saturating_add(1)),
        policy_pin: union_observations.policy_pin.clone(),
        facts_pin: union_observations.facts_pin.clone(),
    })
}

/// Computes and validates one group's four strength signals in native operation order.
fn candidate_score(
    candidate: &CandidateObservation,
    now_ms: u64,
    config: &SelectionConfig,
) -> Result<f64, Error> {
    let signals = StrengthSignals::from_evidence(
        &candidate.predicate,
        candidate.evidence_count as u64,
        candidate.latest_ms,
        candidate.diversity as u64,
        now_ms,
        config,
    );
    if [
        signals.type_prior,
        signals.frequency,
        signals.recency,
        signals.diversity,
    ]
    .iter()
    .any(|signal| !unit(*signal))
    {
        return Err(Error::InvalidConfig);
    }
    Ok(signals.score(&config.weights))
}

/// Observes a request, groups duplicates, and observes only their unions before selecting.
///
/// A subject encoded as `{"declared": n}` remains pending until it has an engine
/// binding. Other subjects retain the engine operand shape. Both reads carry the
/// same clock; the second read occurs only when a group has multiple members.
///
/// # Errors
///
/// Preserves observations read failures and returns [`select`]'s validation errors.
/// Refuses either read or the explicit caller pin when it differs from the config pin,
/// and a union row whose native keys differ from its group's.
pub fn observe_and_select(
    client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    config: &ExtractionSelectionConfig,
    policy_pin: &str,
) -> Result<ExtractionSelectionPlan, Error> {
    check_policy_pin(&config.policy_pin, policy_pin)?;
    let (groups, observations) = observe_groups(client, attempt, now_ms, operands, policy_pin)?;
    select(&groups, &observations, now_ms, config)
}

/// Reads bound operands and their evidence unions under one clock and policy pin.
/// Every returned index names an original request position, including scope and pair facts.
pub(crate) fn observe_groups(
    client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    policy_pin: &str,
) -> Result<(CandidateGroups, Observations), Error> {
    let request_indexes: Vec<usize> = operands
        .iter()
        .enumerate()
        .filter_map(|(index, operand)| (!declared_subject(operand)).then_some(index))
        .collect();
    let bound_operands: Vec<Value> = request_indexes
        .iter()
        .map(|index| operands[*index].clone())
        .collect();
    let mut observations = read_observations(client, attempt, now_ms, &bound_operands)?;
    check_policy_pin(policy_pin, &observations.policy_pin)?;
    remap_indexes(&mut observations, &request_indexes)?;
    let mut rows = vec![None; operands.len()];
    for candidate in &observations.candidates {
        rows[candidate.index] = Some(candidate.clone());
    }
    let groups = group_candidates(&rows);
    if groups
        .groups
        .iter()
        .any(|group| group.member_indexes.len() > 1)
    {
        let union = union_operands(operands, &groups);
        observations = read_observations(client, attempt, now_ms, &union)?;
        let representatives: Vec<usize> = groups
            .groups
            .iter()
            .map(|group| group.representative_index)
            .collect();
        remap_indexes(&mut observations, &representatives)?;
        let moved = observations.candidates.iter().any(|union| {
            rows[union.index]
                .as_ref()
                .is_none_or(|first| native_keys(first) != native_keys(union))
        });
        if moved {
            return Err(Error::InvalidObservations(
                "a union read changed its group's native keys".to_owned(),
            ));
        }
    }
    check_policy_pin(policy_pin, &observations.policy_pin)?;
    Ok((groups, observations))
}

/// Recognizes only the reply mirror's explicit declared-person subject form.
fn declared_subject(operand: &Value) -> bool {
    operand["subject"].as_object().is_some_and(|subject| {
        subject.len() == 1
            && subject
                .get("declared")
                .is_some_and(|declared| declared.as_u64().is_some())
    })
}

/// Restores every original request index after a compact bound or union read.
fn remap_indexes(observations: &mut Observations, request_indexes: &[usize]) -> Result<(), Error> {
    if observations.candidates.len() != request_indexes.len() {
        return Err(Error::InvalidObservations(
            "the read omitted a candidate".to_owned(),
        ));
    }
    if request_indexes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::InvalidObservations(
            "compact request indexes are not strictly increasing".to_owned(),
        ));
    }
    let original_index = |index: usize| {
        request_indexes.get(index).copied().ok_or_else(|| {
            Error::InvalidObservations("the read names an unknown candidate".to_owned())
        })
    };
    let mut seen = vec![false; request_indexes.len()];
    for candidate in &mut observations.candidates {
        let index = candidate.index;
        let original = original_index(index)?;
        if seen[index] {
            return Err(Error::InvalidObservations(
                "the read repeated a candidate".to_owned(),
            ));
        }
        seen[index] = true;
        candidate.index = original;
    }
    for prior in &mut observations.priors {
        for index in &mut prior.scope_equal_candidates {
            *index = original_index(*index)?;
        }
        for index in &mut prior.non_widening_candidates {
            *index = original_index(*index)?;
        }
        for index in &mut prior.subject_predicate_equal_candidates {
            *index = original_index(*index)?;
        }
    }
    for replay in &mut observations.replay {
        replay.index = original_index(replay.index)?;
    }
    for score in &mut observations.scores {
        score.i = original_index(score.i)?;
        score.j = original_index(score.j)?;
        if score.i >= score.j {
            return Err(Error::InvalidObservations(
                "a similarity pair is not strictly ordered".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Requires the effective policy pin shared with the inputs page.
fn check_policy_pin(expected: &str, actual: &str) -> Result<(), Error> {
    if expected != actual {
        return Err(Error::PolicyPin {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

/// Tests the same finite unit interval as native selection.
fn unit(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
