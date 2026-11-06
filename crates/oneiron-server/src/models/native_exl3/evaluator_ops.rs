//! The evaluator op on the house EXL3 worker's socket (FIX 14975), host
//! side: `eval.generate` (`deploy/house-model/exl3_evaluator.py`), one
//! connection per call, answered by one frame of its own name or a
//! `refused`. Only the drafter evaluator sends it; no serving path does.
//!
//! Its answer is checked before it is believed: it comes from the
//! incarnation it was sent to, under its request's id, as the op's own
//! frame. Any other answer is a cut.
use std::path::Path;

use serde_json::{Value as JsonValue, json};

use super::buffer::InputRegion;
use super::session_ops::OpFault;
use super::transport::Channel;
use super::wire;

/// The op's wire name.
const EVALUATE_OP: &str = "eval.generate";

/// Whether the worker at `socket` advertises the op in its hello
/// (`capabilities.evaluator.ops`).
pub(in crate::models) async fn advertised(socket: &Path) -> bool {
    let Ok(mut channel) = Channel::connect(socket).await else {
        return false;
    };
    let Ok(hello) = channel.ask("hello", json!({})).await else {
        return false;
    };
    hello
        .pointer("/capabilities/evaluator/ops")
        .and_then(JsonValue::as_array)
        .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some(EVALUATE_OP)))
}

/// Sends one `eval.generate` with `body` to the incarnation `epoch` names,
/// `conversation` (`{messages, tools?}`) as its input region, and returns
/// its one answer's body. Nothing here retries.
pub(in crate::models) async fn evaluate(
    socket: &Path,
    epoch: &str,
    body: JsonValue,
    conversation: &JsonValue,
) -> Result<JsonValue, OpFault> {
    let bytes = serde_json::to_vec(conversation).map_err(|_| OpFault::Cut)?;
    let input = InputRegion::new(&bytes).map_err(|_| OpFault::Cut)?;
    let mut channel = Channel::connect(socket).await.map_err(|_| OpFault::Cut)?;
    let frame = channel
        .exchange(EVALUATE_OP, Some(epoch), body, Some(input.outbound()))
        .await
        .map_err(|_| OpFault::Cut)?;
    // The worker holds its own copy of the region once it has answered.
    drop(input);
    if frame.op == "refused" {
        return Err(OpFault::Refused(wire::refusal_code(&frame.body).to_owned()));
    }
    if frame.op != EVALUATE_OP || frame.epoch.as_deref() != Some(epoch) {
        return Err(OpFault::Cut);
    }
    Ok(frame.body)
}
