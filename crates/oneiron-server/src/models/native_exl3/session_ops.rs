//! The session ops of codec v1.1 on the house EXL3 worker's socket
//! (DESIGN-V2 R2), host side: one connection per op, answered by the op's
//! own frame or a `refused`. A worker is asked one only once its hello named
//! the op (`capability`). Nothing here retries or decides; the session
//! coordinator (`worker_host/session`) does.
use std::path::Path;

use oneiron::llm::{SESSION_SCHEMA_MINOR, SESSIONS_CAPABILITY, SessionCapability, SessionOp};
use oneiron_driver::InferenceWorker;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};

use super::buffer::InputRegion;
use super::transport::Channel;
use super::wire;

/// How a session op went wrong.
pub(in crate::models) enum OpFault {
    /// The worker refused it before anything ran, with this code.
    Refused(String),
    /// The channel failed or the answer did not read: it may have run.
    Cut,
}

/// The session ops the worker at `socket` advertises in its hello; `None`
/// when it advertises none at codec v1.1, or does not answer.
pub(in crate::models) async fn capability(socket: &Path) -> Option<SessionCapability> {
    let mut channel = Channel::connect(socket).await.ok()?;
    let hello = channel.ask("hello", json!({})).await.ok()?;
    let advertised = hello.get("capabilities")?.get(SESSIONS_CAPABILITY)?;
    serde_json::from_value::<SessionCapability>(advertised.clone())
        .ok()
        .filter(|capability| capability.minor >= SESSION_SCHEMA_MINOR)
}

/// Sends `op` with `body` to the incarnation `epoch` names, with
/// `conversation` as its input region when it carries one, and reads the
/// answer. The cheap stats an answer carries feed `worker`'s activity, and
/// so its device ledger, as a `final`'s do.
pub(in crate::models) async fn send<B: Serialize, R: DeserializeOwned>(
    socket: &Path,
    epoch: &str,
    op: SessionOp,
    body: &B,
    conversation: Option<&JsonValue>,
    worker: &InferenceWorker,
) -> Result<R, OpFault> {
    let body = serde_json::to_value(body).map_err(|_| OpFault::Cut)?;
    let input = match conversation {
        Some(conversation) => {
            let bytes = serde_json::to_vec(conversation).map_err(|_| OpFault::Cut)?;
            Some(InputRegion::new(&bytes).map_err(|_| OpFault::Cut)?)
        }
        None => None,
    };
    let mut channel = Channel::connect(socket).await.map_err(|_| OpFault::Cut)?;
    let frame = channel
        .exchange(op.wire_name(), Some(epoch), body, input.as_ref())
        .await
        .map_err(|_| OpFault::Cut)?;
    // The worker holds its own copy of the region once it has answered.
    drop(input);
    if frame.op == "refused" {
        return Err(OpFault::Refused(wire::refusal_code(&frame.body).to_owned()));
    }
    if frame.op != op.wire_name() {
        return Err(OpFault::Cut);
    }
    if let Some(activity) = frame.body.get("stats").and_then(super::activity_of) {
        worker.report(activity);
    }
    serde_json::from_value(frame.body).map_err(|_| OpFault::Cut)
}
