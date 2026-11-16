//! Runs one admitted extraction attempt through its host-bound client.
//!
//! [`extract`] pages TURNs, finishes every extraction step, joins replies and
//! mints every slice's declared people in one commit after the last step.
//! Native instead mints each slice's people immediately after its reply: a
//! failed step here leaves no person minted. Listing pages sharing a trimmed
//! name and naming TURN set share one person key.
//!
//! [`land`] decides the bound reply, plans every set, then commits one component
//! per batch in ready route order. Held groups do not prevent ready writes.
//!
//! A set whose merged-value step fails ends the job with no component
//! committed. Where the step's result shows a failure native's pass parks the
//! set's open marker for, the job commits that one `conflict` item first
//! ([`conflict_resolution::Error::failed_set_marker`]); for every other plan
//! error it commits nothing. A verdict refusal commits no marker either: the
//! bound verdict answers one code for every cause, so the job cannot tell
//! which of native's endings it is.
//!
//! A person item the engine refuses leaves its candidates skipped with the
//! item's reason tokens: a refused view names no row to bind them to. The job
//! does not pin the attempt's listing; a host that wants a later run's equal
//! step requests answered from the saved steps pins it before the first run,
//! as native's pass does. No production driver calls this job.

use std::fmt;

use oneiron_remote::OneironClient;
use serde_json::{Value, json};

use crate::conflict_resolution::{self, SetPlan};
use crate::extraction_decisions;
use crate::extraction_reply::BoundExtractionReply;
use crate::extraction_selection::ExtractionSelectionConfig;

/// Builds ready components without making client calls.
pub mod components;
/// Pages the admitted attempt's TURN locators and effective policy.
pub mod inputs;
/// Joins reply-local candidate indexes and person declarations.
pub mod join;
/// Builds person items and binds their landed identifiers.
pub mod persons;
/// Submits extraction windows and follows typed slice layouts.
pub mod steps;
/// Reads commit views and preserves opaque client refusals.
mod wire;

/// The admitted attempt and clock supplied by its host.
#[derive(Clone, Copy)]
pub struct Input<'a> {
    /// Borrows the client bound to this one admitted extraction attempt.
    pub client: &'a OneironClient,
    /// Names the attempt as 32 lowercase hexadecimal digits.
    pub attempt: &'a str,
    /// Holds the attempt's frozen Unix clock in milliseconds.
    pub now_ms: u64,
}

/// Records a skipped joined candidate without interpreting reason tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct SkippedCandidate {
    /// Names the candidate in the joined reply's numbering.
    pub index: usize,
    /// Preserves decoder reasons or refused person-item tokens in order.
    pub reasons: Vec<String>,
}

/// Preserves one derive item's view together with its batch identifier.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ItemResult {
    /// Names the item inside its batch.
    pub local: String,
    /// Names the engine's item kind.
    pub kind: String,
    /// Tells whether the engine landed the item.
    pub landed: bool,
    /// Holds the written row identifiers as lowercase hexadecimal digits.
    pub rows: Vec<String>,
    /// Preserves the engine's approval when present.
    pub approval: Option<String>,
    /// Preserves refusal tokens unchanged and in order.
    pub reasons: Vec<String>,
    /// Names the batch the engine returned for this item.
    #[serde(skip)]
    pub batch: String,
}

/// Records the first commit's result for one joined person key.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonResult {
    /// Names the key in first-seen order.
    pub key: usize,
    /// Holds the first landed row's PERSON id, absent for a refusal.
    pub id: Option<String>,
    /// Preserves the person item's complete reported write result.
    pub view: ItemResult,
}

/// Holds phase one's completed reads, replies and person results.
#[derive(Debug, Clone, PartialEq)]
pub struct Extracted {
    /// Counts all TURN rows served by the inputs pages.
    pub served_turns: usize,
    /// Counts finished extraction steps, including memoized submissions.
    pub finished_steps: usize,
    /// Holds the joined reply with Listed subjects only and no persons.
    pub reply: BoundExtractionReply,
    /// Records every joined candidate or skip's original reply and index.
    pub origins: Vec<join::CandidateOrigin>,
    /// Preserves one result per person key in key order.
    pub people: Vec<PersonResult>,
    /// Preserves skips and their exact decoder reasons or item tokens.
    pub skipped: Vec<SkippedCandidate>,
    /// Holds the selection config decoded from the unchanged page policy.
    pub config: ExtractionSelectionConfig,
    /// Pins that complete effective policy for phase two's reads.
    pub policy_pin: String,
    /// Counts the person derive batches, zero or one.
    pub batches: usize,
}

/// Records one component's place, plan and commit view.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentResult {
    /// Names the first route's representative in the decisions operand array.
    pub representative_index: usize,
    /// Names the judge set in route-plan order, absent for a plain candidate.
    pub set: Option<usize>,
    /// Preserves how the set was planned, absent for a plain candidate.
    pub planned: Option<SetPlan>,
    /// Preserves the item's kind, write result and batch identifier.
    pub view: ItemResult,
}

/// Reports both phases without exposing any engine type.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Counts all TURN rows served to phase one.
    pub served_turns: usize,
    /// Counts finished extraction steps, including saved replies.
    pub finished_steps: usize,
    /// Preserves phase one's person results in key order.
    pub people: Vec<PersonResult>,
    /// Preserves all skipped candidates and exact reason tokens.
    pub skipped: Vec<SkippedCandidate>,
    /// Holds committed component results in commit order, including refusals.
    pub components: Vec<ComponentResult>,
    /// Counts ready routes already represented by a head and not committed.
    pub already_represented: usize,
    /// Counts groups held by selection and not committed.
    pub held_groups: usize,
    /// Holds selection's retry suggestion only when at least one group is held.
    pub retry_at_ms: Option<u64>,
    /// Counts operands still awaiting person binding; bound replies yield zero.
    pub pending_bindings: usize,
    /// Counts all derive batches, including the first person batch.
    pub batches: usize,
}

/// Names the stage that ended the job without undoing earlier durable writes.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Preserves a client refusal without reading its message.
    Client {
        /// Names the refused stage's verb.
        verb: &'static str,
        /// Preserves the engine's refusal code.
        code: String,
        /// Preserves the engine's message without interpreting it.
        message: String,
    },
    /// Rejects an answer or policy row the job cannot decode.
    Decode {
        /// Names the verb whose answer or request layout did not decode.
        verb: &'static str,
        /// Describes the local decoding failure.
        message: String,
    },
    /// Rejects an effective policy pin or selection row that moved while paging.
    InputsChanged {
        /// Names the page field that changed.
        field: &'static str,
    },
    /// Rejects an inputs page whose next cursor equals the sent cursor.
    CursorDidNotAdvance,
    /// Preserves a second layout refusal for a supplied engine slice.
    RepeatedLayout {
        /// Preserves the refused resubmission's code.
        code: String,
        /// Preserves the message without interpreting it.
        message: String,
    },
    /// Preserves an extraction step that did not finish.
    Step {
        /// Numbers the proposed step in window, row and page order.
        slice: usize,
        /// Holds its status, or missing when no status was served.
        status: String,
        /// Preserves the entire result JSON without reading its other fields.
        result: Value,
    },
    /// Rejects a candidate or person naming a TURN absent from the inputs pages.
    ReplyTurnNotServed {
        /// Names the TURN the reply cited.
        turn: String,
    },
    /// Preserves the complete decisions stage's refusal or local error.
    Decisions(extraction_decisions::Error),
    /// Preserves the complete set planning stage's refusal or local error.
    Plan(conflict_resolution::Error),
    /// Preserves a failed set's planning error after its open marker's commit.
    SetFailed {
        /// Preserves the merged-value step's failure for the set.
        error: conflict_resolution::Error,
        /// Preserves the marker item's write result, landed or refused.
        marker: ItemResult,
    },
}

impl Error {
    /// Returns an engine refusal code where the failing stage provides one.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. } | Self::RepeatedLayout { code, .. } => Some(code),
            Self::Decisions(error) => error.code(),
            Self::Plan(error) | Self::SetFailed { error, .. } => error.code(),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    /// Formats the error without making policy decisions from its message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "extraction job: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Finishes extraction and person binding without landing any claim.
///
/// # Errors
///
/// Preserves paging, extraction, reply validation and person commit errors.
/// No people are minted until every extraction step has finished.
pub fn extract(input: Input<'_>) -> Result<Extracted, Error> {
    let pages = inputs::collect(input)?;
    let replies = steps::extract(input.client, &pages.turns, pages.per_step)?;
    let finished_steps = replies.len();
    inputs::check_reply_turns(&replies, &pages.turns)?;
    let joined = join::join_replies(&replies);
    let people = persons::mint(input.client, &joined.people, &pages.turns)?;
    let batches = usize::from(!people.is_empty());
    let origins = joined.origins.clone();
    let bound = persons::bind(joined, &people)?;
    Ok(Extracted {
        served_turns: pages.turns.len(),
        finished_steps,
        reply: bound.reply,
        origins,
        people,
        skipped: bound.skipped,
        config: pages.config,
        policy_pin: pages.policy_pin,
        batches,
    })
}

/// Decides phase one's bound reply and commits each ready component separately.
///
/// A plan error lands no component. For a failed merged-value step that
/// [`conflict_resolution::Error::failed_set_marker`] names a set for, the
/// set's open marker is committed as one `conflict` item before the error is
/// returned as [`Error::SetFailed`]; every other plan error commits nothing.
/// Earlier person rows remain durable.
///
/// # Errors
///
/// Preserves whole decisions and plan errors, malformed component inputs,
/// refused commit calls and undecodable commit views. Item refusals are results.
pub fn land(input: Input<'_>, extracted: &Extracted) -> Result<Outcome, Error> {
    let mut outcome = Outcome {
        served_turns: extracted.served_turns,
        finished_steps: extracted.finished_steps,
        people: extracted.people.clone(),
        skipped: extracted.skipped.clone(),
        components: Vec::new(),
        already_represented: 0,
        held_groups: 0,
        retry_at_ms: None,
        pending_bindings: 0,
        batches: extracted.batches,
    };
    if extracted.reply.candidates.is_empty() {
        return Ok(outcome);
    }
    let decisions = extraction_decisions::run(extraction_decisions::Input {
        client: input.client,
        attempt: input.attempt,
        now_ms: input.now_ms,
        reply: &extracted.reply,
        config: &extracted.config,
        policy_pin: &extracted.policy_pin,
    })
    .map_err(Error::Decisions)?;
    let plan = match conflict_resolution::plan(conflict_resolution::Input {
        client: input.client,
        reply: &extracted.reply,
        outcome: &decisions,
    }) {
        Ok(plan) => plan,
        Err(error) => return Err(failed_plan(input, extracted, &decisions, error)),
    };
    let components = components::build(&extracted.reply, &decisions, &plan)?;
    outcome.already_represented = components.already_represented;
    outcome.held_groups = decisions.selection.held.len();
    outcome.retry_at_ms =
        (!decisions.selection.held.is_empty()).then_some(decisions.selection.retry_at_ms);
    outcome.pending_bindings = decisions.selection.pending_bindings.len();
    for component in components.items {
        let request = json!({"items": [component.item], "sources": []});
        let mut views = wire::commit(input.client, request, 1)?;
        let view = views.remove(0);
        outcome.batches += 1;
        outcome.components.push(ComponentResult {
            representative_index: component.representative_index,
            set: component.set,
            planned: component.planned,
            view,
        });
    }
    Ok(outcome)
}

/// Commits a failed set's open marker where native parks one, then answers the error.
///
/// A refused commit call or an item that cannot be built replaces the plan's
/// error, as the fault that came last.
fn failed_plan(
    input: Input<'_>,
    extracted: &Extracted,
    decisions: &extraction_decisions::Outcome,
    error: conflict_resolution::Error,
) -> Error {
    let Some(set) = error.failed_set_marker() else {
        return Error::Plan(error);
    };
    let item = match conflict_resolution::open_marker_item(&extracted.reply, decisions, set) {
        Ok(item) => item,
        Err(build) => return Error::Plan(build),
    };
    match wire::commit(input.client, json!({"items": [item], "sources": []}), 1) {
        Ok(mut views) => Error::SetFailed {
            error,
            marker: views.remove(0),
        },
        Err(refused) => refused,
    }
}

/// Runs the two phases in sequence over the same admitted client and clock.
///
/// # Errors
///
/// Returns the first extraction or landing error, retaining earlier durable writes.
pub fn run(input: Input<'_>) -> Result<Outcome, Error> {
    let extracted = extract(input)?;
    land(input, &extracted)
}
