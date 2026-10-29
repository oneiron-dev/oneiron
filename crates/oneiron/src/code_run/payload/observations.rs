//! The replay codec of the observations a verb's answer carries beside its
//! output (FIX 2135): each frame the run's host door drained from the run's
//! own board connection, with the connection, the frame's epoch and kind,
//! and the rows it was derived from.
//!
//! An answer with none keeps no `observations` key, and one recorded before
//! any reads back with none. A kept frame decodes whole or the outcome does
//! not: a replayed answer never carries part of a frame.

use rmpv::Value;

use crate::Result;
use crate::code_run::CodeRunBridgeCall;
use crate::code_run::types::{RunObservation, SelfDispatchOutcome};
use crate::context_board::{BoardStreamFrame, FrameKind};

use super::super::support::{
    decode_array, entity_id_value, entity_value, expect_map, invalid_code_run_replay, map_get,
    request_map, str_value, u64_value,
};

/// The board frames the verb answers among `calls` carried beside their
/// outputs, in call order; an answer that does not decode carried none.
pub(crate) fn agent_verb_observations_of(calls: &[CodeRunBridgeCall]) -> Vec<RunObservation> {
    calls
        .iter()
        .filter_map(
            |call| match super::decode_self_dispatch_outcome(&call.outcome) {
                Ok(SelfDispatchOutcome::AgentVerb(answer)) => Some(answer.observations),
                _ => None,
            },
        )
        .flatten()
        .collect()
}

/// The key an answer's observations are kept under, beside its output.
const OBSERVATIONS: &str = "observations";

/// Writes `observations` onto an answer's recorded entries; none writes
/// nothing.
pub(super) fn keep_observations(
    entries: &mut Vec<(&'static str, Value)>,
    observations: &[RunObservation],
) -> Result<()> {
    if observations.is_empty() {
        return Ok(());
    }
    let kept = observations
        .iter()
        .map(observation_value)
        .collect::<Result<Vec<_>>>()?;
    entries.push((OBSERVATIONS, Value::Array(kept)));
    Ok(())
}

/// The observations [`keep_observations`] kept on an answer's entries; none
/// when it kept none.
pub(super) fn decode_observations(entries: &[(Value, Value)]) -> Result<Vec<RunObservation>> {
    map_get(entries, OBSERVATIONS)
        .ok()
        .map_or(Ok(Vec::new()), |kept| {
            decode_array(kept, decode_observation)
        })
}

fn observation_value(observation: &RunObservation) -> Result<Value> {
    let kind = serde_json::to_string(&observation.frame.kind)
        .map_err(|_| invalid_code_run_replay("observation frame does not encode"))?;
    Ok(request_map(vec![
        ("connection", Value::from(observation.connection.as_str())),
        ("epoch", Value::from(observation.frame.epoch)),
        ("frame", Value::from(kind)),
        (
            "rows",
            Value::Array(
                observation
                    .rows
                    .iter()
                    .copied()
                    .map(entity_id_value)
                    .collect(),
            ),
        ),
    ]))
}

fn decode_observation(value: &Value) -> Result<RunObservation> {
    let entries = expect_map(value, "observation must be a map")?;
    let kind: FrameKind = serde_json::from_str(str_value(map_get(entries, "frame")?)?)
        .map_err(|_| invalid_code_run_replay("observation frame does not decode"))?;
    Ok(RunObservation {
        connection: str_value(map_get(entries, "connection")?)?.to_owned(),
        frame: BoardStreamFrame {
            epoch: u64_value(map_get(entries, "epoch")?)?,
            kind,
        },
        rows: decode_array(map_get(entries, "rows")?, entity_value)?,
    })
}
