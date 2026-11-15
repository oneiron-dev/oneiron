//! Plans one reply's conflict items and merged-value steps without landing claims.
//!
//! Each judge set of `extraction_decisions::Outcome` becomes one derive item:
//! a `conflict_resolution` item for a skip, a merge or an accumulate, or a
//! `conflict` item for an escalation, a missing standing answer, a null merged
//! value or a cross-predicate merge that names none. A merge or supersede asks
//! the bound merged-value step first, except when no kept member spans
//! predicates. The policy builds items and asks the step; it never commits.

use std::fmt;

use oneiron_remote::OneironClient;
use serde_json::{Value, json};

use crate::conflict_decisions::{ConflictDecision, Resolution};
use crate::extraction_decisions::{Outcome, SetOperands, SetOutcome};
use crate::extraction_reply::{BoundExtractionCandidate, BoundExtractionReply};

/// The bound merged-value submit verb.
const STEPS_SUBMIT_VERB: &str = "ai.steps.submit";

/// The most lexical hints one member lands with, as the engine normalizes them.
const MAX_HINTS: usize = 8;

/// The most UTF-8 bytes one hint holds, as the engine normalizes them.
const MAX_HINT_BYTES: usize = 256;

/// Names the job's decision a resolved set lands with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedOutcome {
    /// The set's one member replaces the set's prior head with no verdict.
    Skip,
    /// One merged claim from the whole set replaces the recomputed head.
    Merge,
    /// Every member lands as a plain write beside the heads.
    Accumulate,
}

/// Names why a set opens a marker instead of resolving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenCause {
    /// The set's verdict escalated.
    Escalated,
    /// The set's verdict left no standing answer.
    NoStandingAnswer,
    /// The merged-value step finished without a value.
    NoMergedValue,
    /// A merge that names none spans predicates.
    CrossPredicateMergeUnnamed,
}

/// Holds one set's plan: its derive item with how the set resolved.
#[derive(Debug, Clone, PartialEq)]
pub enum SetPlan {
    /// The set resolves with the job's decision and its item.
    Resolved {
        /// Holds the job's decision for the set.
        outcome: ResolvedOutcome,
        /// Holds the complete derive item `{"kind": .., "spec": ..}`.
        item: Value,
    },
    /// The set opens a marker with its cause and its item.
    Opened {
        /// Holds why the set opens a marker.
        cause: OpenCause,
        /// Holds the complete derive item `{"kind": .., "spec": ..}`.
        item: Value,
    },
}

impl SetPlan {
    /// Returns the set's derive item.
    #[must_use]
    pub fn item(&self) -> &Value {
        match self {
            Self::Resolved { item, .. } | Self::Opened { item, .. } => item,
        }
    }
}

/// Holds one component candidate's confidence and prospective query hints.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberFacts {
    /// Holds the representative's confidence from 0 to 1.
    pub confidence: f64,
    /// Holds the normalized union of the folded members' hints in member order.
    pub prospective_queries: Vec<String>,
}

/// Holds one plan per judge set in route-plan order.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Holds one set plan per judge set in route-plan order.
    pub sets: Vec<SetPlan>,
}

impl Plan {
    /// Returns the sets' derive items in route-plan order.
    #[must_use]
    pub fn items(&self) -> Vec<Value> {
        self.sets.iter().map(|set| set.item().clone()).collect()
    }
}

/// Borrows the bound client with the reply and decisions one plan covers.
#[derive(Clone, Copy)]
pub struct Input<'a> {
    /// Borrows the client bound to this admitted extraction attempt.
    pub client: &'a OneironClient,
    /// Borrows the decoded bound extraction reply.
    pub reply: &'a BoundExtractionReply,
    /// Borrows the reply's decisions with their operand sets.
    pub outcome: &'a Outcome,
}

/// Explains why the whole plan stopped without returning a partial plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Preserves a bound step refusal with its engine code and set.
    Client {
        /// Names the set's position in the route plan.
        set: usize,
        /// Names the refused verb.
        verb: &'static str,
        /// Preserves the engine's refusal code.
        code: String,
        /// Preserves the engine's refusal message without interpreting it.
        message: String,
    },
    /// Records a step answer that is not a finished value or null.
    Step {
        /// Names the set's position in the route plan.
        set: usize,
        /// Holds the answered status or what was missing.
        status: String,
        /// Describes the answer without interpreting it.
        message: String,
    },
    /// Rejects a kept operand outside the set's members.
    KeptOutsideSet {
        /// Names the set's position in the route plan.
        set: usize,
        /// Names the kept operand position the decision names.
        kept: usize,
    },
    /// Rejects a plan input that cannot name its set.
    InvalidInput(String),
}

impl Error {
    /// Returns the engine code for a bound refusal.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. } => Some(code),
            Self::Step { .. } | Self::KeptOutsideSet { .. } | Self::InvalidInput(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "conflict resolution: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Returns one set's member facts from the reply through its groups.
///
/// Each component candidate takes its representative's confidence and the
/// normalized union of its folded members' hints in member order.
///
/// # Errors
///
/// Rejects a set without operands, a representative without a group or reply
/// candidate, a confidence outside 0 to 1, and a hint over 256 bytes.
pub fn member_facts(
    reply: &BoundExtractionReply,
    outcome: &Outcome,
    set: usize,
) -> Result<Vec<MemberFacts>, Error> {
    let operands = outcome
        .set_operands
        .get(set)
        .ok_or_else(|| Error::InvalidInput(format!("set {set} names no operand set")))?;
    if operands.candidates.len() != operands.representatives.len() {
        return Err(Error::InvalidInput(format!(
            "set {set} holds {} candidates for {} representatives",
            operands.candidates.len(),
            operands.representatives.len()
        )));
    }
    let mut facts = Vec::with_capacity(operands.candidates.len());
    for representative in &operands.representatives {
        let group = outcome
            .selection
            .groups
            .iter()
            .find(|group| group.representative_index == *representative)
            .ok_or_else(|| {
                Error::InvalidInput(format!(
                    "set {set} representative {representative} names no selection group"
                ))
            })?;
        let confidence = reply_confidence(reply, outcome, *representative, set)?;
        let mut hints = Vec::new();
        for member in &group.member_indexes {
            let candidate = reply_candidate(reply, outcome, *member, set)?;
            hints.extend(candidate.prospective_queries.iter().cloned());
        }
        facts.push(MemberFacts {
            confidence,
            prospective_queries: normalize_hints(&hints, set, *representative)?,
        });
    }
    Ok(facts)
}

/// Returns the merged-value request for one set, or none when it asks no step.
///
/// A merge or supersede with a kept member, or with none inside one
/// predicate, asks the step. Every other set asks nothing, including a merge
/// that names none across predicates.
///
/// # Errors
///
/// Rejects a kept operand outside the set's members and priors that do not encode.
pub fn step_request(
    operands: &SetOperands,
    outcome: &SetOutcome,
    set: usize,
) -> Result<Option<Value>, Error> {
    let SetOutcome::Decided(decision) = outcome else {
        return Ok(None);
    };
    let label = match decision.resolution {
        Resolution::Merge => "merge",
        Resolution::Supersede => "supersede",
        Resolution::Accumulate | Resolution::Escalate | Resolution::NoStandingAnswer => {
            return Ok(None);
        }
    };
    let kept = match decision.identity {
        Some(kept) => Some(kept_position(operands, kept, set)?),
        None => None,
    };
    if kept.is_none() && operands.spans_predicates {
        return Ok(None);
    }
    let mut request = serde_json::Map::new();
    request.insert("resolution".to_owned(), Value::String(label.to_owned()));
    if let Some(kept) = kept {
        request.insert("kept".to_owned(), json!(kept));
    }
    request.insert(
        "candidates".to_owned(),
        Value::Array(operands.candidates.clone()),
    );
    let priors = serde_json::to_value(&operands.priors)
        .map_err(|error| Error::InvalidInput(format!("set {set} priors do not encode: {error}")))?;
    request.insert("priors".to_owned(), priors);
    request.insert("set_members".to_owned(), json!(operands.set_members));
    Ok(Some(Value::Object(request)))
}

/// Returns one set's plan from its operands, outcome, facts and merged value.
///
/// `value` is the step's answered value for a merge: `None` when the step
/// finished null. Sets that ask no step ignore it, except a merge that names
/// none across predicates, which opens without asking.
///
/// # Errors
///
/// Rejects facts for another candidate count, a confidence outside 0 to 1, a
/// hint over 256 bytes, a kept operand outside the set's members, and priors
/// that do not encode.
pub fn set_plan(
    operands: &SetOperands,
    outcome: &SetOutcome,
    facts: &[MemberFacts],
    value: Option<&Value>,
    set: usize,
) -> Result<SetPlan, Error> {
    let members = members_json(operands, facts, set)?;
    let heads = heads_json(operands, set)?;
    let local = format!("conflict-set-{set}");
    match outcome {
        SetOutcome::Skipped { .. } => {
            let item = resolution_item(
                &local,
                members,
                heads,
                &operands.set_members,
                ResolvedOutcome::Skip,
                None,
                None,
            );
            Ok(SetPlan::Resolved {
                outcome: ResolvedOutcome::Skip,
                item,
            })
        }
        SetOutcome::Decided(decision) => {
            decided_plan(operands, decision, members, heads, value, &local, set)
        }
    }
}

/// Returns every judge set's plan in route-plan order, asking each merged value once.
///
/// Any step refusal or unfinished step ends the whole plan with the set it
/// names; no partial plan, no retry and no fallback item.
///
/// # Errors
///
/// Preserves step refusals with their engine codes, unfinished or undecodable
/// step answers, kept operands outside their sets, and inputs that cannot name
/// their sets.
pub fn plan(input: Input<'_>) -> Result<Plan, Error> {
    if input.outcome.sets.len() != input.outcome.set_operands.len() {
        return Err(Error::InvalidInput(format!(
            "{} outcomes name {} operand sets",
            input.outcome.sets.len(),
            input.outcome.set_operands.len()
        )));
    }
    if input.outcome.route.judge_sets.len() != input.outcome.sets.len() {
        return Err(Error::InvalidInput(format!(
            "{} outcomes name {} route sets",
            input.outcome.sets.len(),
            input.outcome.route.judge_sets.len()
        )));
    }
    let mut sets = Vec::with_capacity(input.outcome.sets.len());
    for (set, (outcome, operands)) in input
        .outcome
        .sets
        .iter()
        .zip(input.outcome.set_operands.iter())
        .enumerate()
    {
        let facts = member_facts(input.reply, input.outcome, set)?;
        let request = step_request(operands, outcome, set)?;
        let value = match request {
            None => None,
            Some(request) => submit_step(input.client, request, set)?,
        };
        sets.push(set_plan(operands, outcome, &facts, value.as_ref(), set)?);
    }
    Ok(Plan { sets })
}

/// Returns one decided set's plan.
fn decided_plan(
    operands: &SetOperands,
    decision: &ConflictDecision,
    members: Vec<Value>,
    heads: Value,
    value: Option<&Value>,
    local: &str,
    set: usize,
) -> Result<SetPlan, Error> {
    match decision.resolution {
        Resolution::Merge | Resolution::Supersede => {
            merge_plan(operands, decision, members, heads, value, local, set)
        }
        Resolution::Accumulate => {
            let item = resolution_item(
                local,
                members,
                heads,
                &operands.set_members,
                ResolvedOutcome::Accumulate,
                None,
                None,
            );
            Ok(SetPlan::Resolved {
                outcome: ResolvedOutcome::Accumulate,
                item,
            })
        }
        Resolution::Escalate => {
            let item = conflict_item(local, members, heads, &operands.set_members);
            Ok(SetPlan::Opened {
                cause: OpenCause::Escalated,
                item,
            })
        }
        Resolution::NoStandingAnswer => {
            let item = conflict_item(local, members, heads, &operands.set_members);
            Ok(SetPlan::Opened {
                cause: OpenCause::NoStandingAnswer,
                item,
            })
        }
    }
}

/// Returns one merge or supersede set's plan from its kept member and value.
fn merge_plan(
    operands: &SetOperands,
    decision: &ConflictDecision,
    members: Vec<Value>,
    heads: Value,
    value: Option<&Value>,
    local: &str,
    set: usize,
) -> Result<SetPlan, Error> {
    let kept = match decision.identity {
        Some(kept) => Some(kept_position(operands, kept, set)?),
        None => None,
    };
    if kept.is_none() && operands.spans_predicates {
        let item = conflict_item(local, members, heads, &operands.set_members);
        return Ok(SetPlan::Opened {
            cause: OpenCause::CrossPredicateMergeUnnamed,
            item,
        });
    }
    let present = value.filter(|found| !found.is_null());
    let Some(found) = present else {
        let item = conflict_item(local, members, heads, &operands.set_members);
        return Ok(SetPlan::Opened {
            cause: OpenCause::NoMergedValue,
            item,
        });
    };
    let item = resolution_item(
        local,
        members,
        heads,
        &operands.set_members,
        ResolvedOutcome::Merge,
        kept,
        Some(found),
    );
    Ok(SetPlan::Resolved {
        outcome: ResolvedOutcome::Merge,
        item,
    })
}

/// Sends one merged-value request and returns its value, or none for null.
///
/// A finished answer with a value that is not null is a value; a finished
/// answer with null is none. Any other status, a missing result, or an
/// undecodable finished answer is the plan's error for the set.
fn submit_step(client: &OneironClient, request: Value, set: usize) -> Result<Option<Value>, Error> {
    let answer = client
        .agent_verb(STEPS_SUBMIT_VERB, request)
        .map_err(|error| Error::Client {
            set,
            verb: STEPS_SUBMIT_VERB,
            code: error.code,
            message: error.message,
        })?;
    let Some(result) = answer.get("result").filter(|found| !found.is_null()) else {
        return Err(Error::Step {
            set,
            status: "missing".to_owned(),
            message: "the merged-value step answered no result".to_owned(),
        });
    };
    let Some(status) = result.get("status").and_then(Value::as_str) else {
        return Err(Error::Step {
            set,
            status: "missing".to_owned(),
            message: "the merged-value step answered no status".to_owned(),
        });
    };
    if status != "finished" {
        return Err(Error::Step {
            set,
            status: status.to_owned(),
            message: step_failure_message(result),
        });
    }
    let Some(found) = result.get("json").filter(|found| !found.is_null()) else {
        return Err(Error::Step {
            set,
            status: status.to_owned(),
            message: "the finished step answered no json".to_owned(),
        });
    };
    let Some(value) = found.get("value") else {
        return Err(Error::Step {
            set,
            status: status.to_owned(),
            message: "the finished step answered no value".to_owned(),
        });
    };
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(value.clone()))
}

/// Returns the message a non-finished step answer carries.
fn step_failure_message(result: &Value) -> String {
    if let Some(message) = result
        .get("failure")
        .and_then(|failure| failure.get("message"))
        .and_then(Value::as_str)
    {
        return message.to_owned();
    }
    if let Some(trap) = result.get("trap_ref").and_then(Value::as_str) {
        return format!("the merged-value step was denied its budget at trap {trap}");
    }
    format!("the merged-value step answered {result}")
}

/// Returns the kept operand's component position when the set names it.
fn kept_position(operands: &SetOperands, kept: usize, set: usize) -> Result<usize, Error> {
    let Some(position) = operands
        .representatives
        .iter()
        .position(|representative| *representative == kept)
    else {
        return Err(Error::KeptOutsideSet { set, kept });
    };
    if !operands.set_members.contains(&position) {
        return Err(Error::KeptOutsideSet { set, kept });
    }
    Ok(position)
}

/// Returns one operand's reply candidate.
fn reply_candidate<'a>(
    reply: &'a BoundExtractionReply,
    outcome: &Outcome,
    operand: usize,
    set: usize,
) -> Result<&'a BoundExtractionCandidate, Error> {
    let Some(index) = outcome.candidate_indexes.get(operand) else {
        return Err(Error::InvalidInput(format!(
            "set {set} operand {operand} names no reply candidate"
        )));
    };
    reply
        .candidates
        .iter()
        .find(|candidate| candidate.index == *index)
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "set {set} operand {operand} names no reply candidate"
            ))
        })
}

/// Returns one operand's confidence when it lands with a claim.
fn reply_confidence(
    reply: &BoundExtractionReply,
    outcome: &Outcome,
    operand: usize,
    set: usize,
) -> Result<f64, Error> {
    let candidate = reply_candidate(reply, outcome, operand, set)?;
    check_confidence(candidate.confidence, set, operand)?;
    Ok(candidate.confidence)
}

/// Refuses a confidence the wire would refuse.
fn check_confidence(confidence: f64, set: usize, operand: usize) -> Result<(), Error> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(Error::InvalidInput(format!(
            "set {set} operand {operand} confidence {confidence} is outside 0 to 1"
        )));
    }
    Ok(())
}

/// Returns hints trimmed, deduplicated, capped at eight, refusing over-long hints.
fn normalize_hints(
    hints: &[String],
    set: usize,
    representative: usize,
) -> Result<Vec<String>, Error> {
    let mut kept = Vec::new();
    for hint in hints {
        let trimmed = hint.trim();
        if trimmed.is_empty() {
            continue;
        }
        if kept.iter().any(|kept| kept.as_str() == trimmed) {
            continue;
        }
        if kept.len() == MAX_HINTS {
            break;
        }
        if trimmed.len() > MAX_HINT_BYTES {
            return Err(Error::InvalidInput(format!(
                "set {set} representative {representative} hint exceeds 256 bytes"
            )));
        }
        kept.push(trimmed.to_owned());
    }
    Ok(kept)
}

/// Returns one set's members with the union operands unchanged.
fn members_json(
    operands: &SetOperands,
    facts: &[MemberFacts],
    set: usize,
) -> Result<Vec<Value>, Error> {
    if operands.candidates.len() != operands.representatives.len() {
        return Err(Error::InvalidInput(format!(
            "set {set} holds {} candidates for {} representatives",
            operands.candidates.len(),
            operands.representatives.len()
        )));
    }
    if facts.len() != operands.candidates.len() {
        return Err(Error::InvalidInput(format!(
            "set {set} holds {} facts for {} candidates",
            facts.len(),
            operands.candidates.len()
        )));
    }
    let mut members = Vec::with_capacity(operands.candidates.len());
    for (position, (candidate, facts)) in operands.candidates.iter().zip(facts.iter()).enumerate() {
        let operand = operands
            .representatives
            .get(position)
            .copied()
            .unwrap_or(position);
        check_confidence(facts.confidence, set, operand)?;
        let hints = normalize_hints(&facts.prospective_queries, set, operand)?;
        members.push(json!({
            "candidate": candidate.clone(),
            "confidence": facts.confidence,
            "prospective_queries": hints,
        }));
    }
    Ok(members)
}

/// Returns one set's heads as the Resolution read pins them.
fn heads_json(operands: &SetOperands, set: usize) -> Result<Value, Error> {
    serde_json::to_value(&operands.priors)
        .map_err(|error| Error::InvalidInput(format!("set {set} priors do not encode: {error}")))
}

/// Returns one `conflict` item over the set.
fn conflict_item(local: &str, members: Vec<Value>, heads: Value, set_members: &[usize]) -> Value {
    json!({
        "kind": "conflict",
        "spec": {
            "local": local,
            "members": members,
            "heads": heads,
            "set_members": set_members,
        },
    })
}

/// Returns one `conflict_resolution` item over the set.
fn resolution_item(
    local: &str,
    members: Vec<Value>,
    heads: Value,
    set_members: &[usize],
    outcome: ResolvedOutcome,
    kept: Option<usize>,
    value: Option<&Value>,
) -> Value {
    let label = match outcome {
        ResolvedOutcome::Skip => "skip",
        ResolvedOutcome::Merge => "merge",
        ResolvedOutcome::Accumulate => "accumulate",
    };
    let mut spec = serde_json::Map::new();
    spec.insert("local".to_owned(), Value::String(local.to_owned()));
    spec.insert("members".to_owned(), Value::Array(members));
    spec.insert("heads".to_owned(), heads);
    spec.insert("set_members".to_owned(), json!(set_members));
    spec.insert("outcome".to_owned(), Value::String(label.to_owned()));
    if let Some(kept) = kept {
        spec.insert("kept".to_owned(), json!(kept));
    }
    if let Some(value) = value {
        spec.insert("value".to_owned(), value.clone());
    }
    json!({
        "kind": "conflict_resolution",
        "spec": Value::Object(spec),
    })
}
