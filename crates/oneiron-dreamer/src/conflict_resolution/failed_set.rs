//! Decides which failed merged-value step parks its set's open marker, and
//! builds that marker's item.
//!
//! Native's pass decides by the failure whether a set whose merged value did
//! not arrive keeps an open marker before the attempt ends. The job reads the
//! same decision off the step's result where the result shows it, and
//! commits nothing where it does not.

use serde_json::Value;

use crate::extraction_decisions::Outcome;
use crate::extraction_reply::BoundExtractionReply;

use super::{Error, conflict_item, heads_json, member_facts, members_json, set_local};

impl Error {
    /// Returns the set whose open marker native's pass parks for this error.
    ///
    /// Native parks the marker of a set whose merged-value step failed, then
    /// ends the attempt with the failure. It parks none for a refused spend
    /// scope or for a refused finalize of spent work. A schema failure of
    /// spent work parks the marker only before the pass deadline, which the
    /// step's result does not carry, so it names no set here. A refused call,
    /// a budget trap, a parked or erased step, an answer the plan could not
    /// read and a failure class this crate does not know name no set either:
    /// none of them shows an ending native parks a marker for. Only the
    /// result's `status`, `failure.class` and the presence of
    /// `failure.spent_usage` are read; no message is.
    #[must_use]
    pub fn failed_set_marker(&self) -> Option<usize> {
        let Self::Step {
            set,
            status,
            result,
            ..
        } = self
        else {
            return None;
        };
        if status != "failed" {
            return None;
        }
        let failure = result.get("failure")?;
        let class = failure.get("class").and_then(Value::as_str)?;
        let spent = failure
            .get("spent_usage")
            .is_some_and(|usage| !usage.is_null());
        let parks = match class {
            "retryable" | "fatal" | "budget_denied" | "fallback" | "deadline_hard_cut"
            | "engine" => true,
            "finalize_refused" | "schema_validation" => !spent,
            _ => false,
        };
        parks.then_some(*set)
    }
}

/// Returns the `conflict` item that opens one set's marker.
///
/// The item is the one [`super::set_plan`] builds for an opened set: the same
/// members, heads, set members and local name. The extraction job commits it
/// for a set [`Error::failed_set_marker`] names.
///
/// # Errors
///
/// Rejects a set without operands and everything [`member_facts`] rejects.
pub fn open_marker_item(
    reply: &BoundExtractionReply,
    outcome: &Outcome,
    set: usize,
) -> Result<Value, Error> {
    let operands = outcome
        .set_operands
        .get(set)
        .ok_or_else(|| Error::InvalidInput(format!("set {set} names no operand set")))?;
    let facts = member_facts(reply, outcome, set)?;
    let members = members_json(operands, &facts, set)?;
    let heads = heads_json(operands, set)?;
    Ok(conflict_item(
        &set_local(set),
        members,
        heads,
        &operands.set_members,
    ))
}
