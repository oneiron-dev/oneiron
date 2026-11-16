//! Proposes bounded windows and follows only the engine's typed slice layout.

use std::ops::Range;

use oneiron_remote::OneironClient;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::extraction_reply::BoundExtractionReply;

use super::inputs::Turn;
use super::{Error, wire};

/// Names the bound extraction submit verb.
const SUBMIT: &str = "ai.steps.submit";

/// Mirrors the extraction-only layout without changing verdict layout decoding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtractionStepLayout {
    /// Holds the engine's slices in native group order.
    StepSlices {
        /// Holds each slice's proposed evidence positions and listing page count.
        slices: Vec<ExtractionStepSlice>,
    },
}

/// Mirrors one slice of a proposed extraction window.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionStepSlice {
    /// Names request evidence positions in ascending order.
    pub evidence: Vec<usize>,
    /// Counts this slice's listing pages.
    pub pages: usize,
}

/// Splits served positions into consecutive proposed step windows.
///
/// A window holds at most `per_step` TURNs, the most one step may cite. An
/// attempt with more TURNs than that is cut at these boundaries, which may
/// fall inside a slice native's pass would send whole. Only this function
/// chooses the boundaries.
///
/// # Panics
///
/// Panics when per_step is zero; the inputs reader rejects that policy first.
#[must_use]
pub fn step_windows(turn_count: usize, per_step: usize) -> Vec<Range<usize>> {
    (0..turn_count)
        .step_by(per_step)
        .map(|start| start..start.saturating_add(per_step).min(turn_count))
        .collect()
}

/// Builds the engine layout's requests in row then listing-page order.
///
/// # Errors
///
/// Rejects an empty slice, a zero page count, unordered
/// or out-of-range positions, and any position omitted or repeated across rows.
pub fn layout_requests(
    window: &[Turn],
    layout: &ExtractionStepLayout,
) -> Result<Vec<Value>, Error> {
    let ExtractionStepLayout::StepSlices { slices } = layout;
    let mut covered = vec![false; window.len()];
    for slice in slices {
        if slice.evidence.is_empty() || slice.pages == 0 {
            return Err(layout_error(
                "a step slice needs evidence and at least one page",
            ));
        }
        if slice.evidence.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(layout_error(
                "slice evidence positions must be strictly ascending",
            ));
        }
        for position in &slice.evidence {
            let Some(seen) = covered.get_mut(*position) else {
                return Err(layout_error(
                    "a slice position is outside the proposed window",
                ));
            };
            if *seen {
                return Err(layout_error("the layout repeats a window position"));
            }
            *seen = true;
        }
    }
    if covered.iter().any(|seen| !seen) || slices.is_empty() {
        return Err(layout_error(
            "the layout does not cover every window position",
        ));
    }
    let mut requests = Vec::new();
    for slice in slices {
        let evidence: Vec<Value> = slice
            .evidence
            .iter()
            .map(|position| locator(&window[*position]))
            .collect();
        for page in 0..slice.pages {
            let mut request = json!({"evidence": evidence});
            if slice.pages > 1 {
                request["page"] = json!(page);
            }
            requests.push(request);
        }
    }
    Ok(requests)
}

/// Runs each window once and resubmits only the slices the engine names.
pub(super) fn extract(
    client: &OneironClient,
    turns: &[Turn],
    per_step: usize,
) -> Result<Vec<BoundExtractionReply>, Error> {
    let mut replies = Vec::new();
    for range in step_windows(turns.len(), per_step) {
        let window = &turns[range];
        let evidence: Vec<Value> = window.iter().map(locator).collect();
        let request = json!({"evidence": evidence});
        match client.agent_verb(SUBMIT, request) {
            Ok(answer) => replies.push(finished_reply(answer, replies.len())?),
            Err(error) => {
                let encoded = serde_json::to_value(&error)
                    .map_err(|failure| layout_error(&failure.to_string()))?;
                let is_slices = encoded
                    .get("extraction_layout")
                    .and_then(|layout| layout.get("kind"))
                    .and_then(Value::as_str)
                    == Some("step_slices");
                if !is_slices {
                    return Err(Error::Client {
                        verb: SUBMIT,
                        code: error.code,
                        message: error.message,
                    });
                }
                let layout = wire::decode(SUBMIT, encoded["extraction_layout"].clone())?;
                for request in layout_requests(window, &layout)? {
                    let answer = match client.agent_verb(SUBMIT, request) {
                        Ok(answer) => answer,
                        Err(error) => {
                            let encoded = serde_json::to_value(&error)
                                .map_err(|failure| layout_error(&failure.to_string()))?;
                            if encoded
                                .get("extraction_layout")
                                .is_some_and(|layout| !layout.is_null())
                            {
                                return Err(Error::RepeatedLayout {
                                    code: error.code,
                                    message: error.message,
                                });
                            }
                            return Err(Error::Client {
                                verb: SUBMIT,
                                code: error.code,
                                message: error.message,
                            });
                        }
                    };
                    replies.push(finished_reply(answer, replies.len())?);
                }
            }
        }
    }
    Ok(replies)
}

/// Builds one locator without reconstructing its source version.
fn locator(turn: &Turn) -> Value {
    json!({"turn": turn.turn, "version": turn.version})
}

/// Reads only the status before decoding a finished bound reply.
fn finished_reply(answer: Value, slice: usize) -> Result<BoundExtractionReply, Error> {
    let result = answer.get("result").cloned().unwrap_or(Value::Null);
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("missing");
    if status != "finished" || result.get("json").is_none_or(Value::is_null) {
        return Err(Error::Step {
            slice,
            status: status.to_owned(),
            result,
        });
    }
    wire::decode(SUBMIT, result["json"].clone())
}

/// Names a malformed layout as the step stage's decode error.
fn layout_error(message: &str) -> Error {
    Error::Decode {
        verb: SUBMIT,
        message: message.to_owned(),
    }
}
