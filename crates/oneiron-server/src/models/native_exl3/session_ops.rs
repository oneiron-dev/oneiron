//! The session ops of codec v1.1 on the house EXL3 worker's socket
//! (DESIGN-V2 R2), host side: one connection per op, answered by the op's
//! own frame or a `refused`. A worker is asked one only once its hello named
//! the op (`capability`). Nothing here retries or decides; the session
//! coordinator (`worker_host/session`) does.
//!
//! Codec v1.2's snapshot ops (R3): `export` takes a published checkpoint
//! out as a snapshot region, and `import` sends one back to a new session.
//! Each answer is checked before it is believed: it comes from the
//! incarnation it was sent to, under its request's id, names the checkpoint
//! exactly, and its lengths and SHA-256 are the snapshot's. Any other answer
//! is a cut: the caller drops what it got and goes cold.
use std::path::Path;

use oneiron::llm::{
    SESSION_SCHEMA_MINOR, SESSIONS_CAPABILITY, SessionCapability, SessionExport, SessionExported,
    SessionImport, SessionImported, SessionOp,
};
use oneiron_driver::InferenceWorker;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};

use super::buffer::{InputRegion, SnapshotRegion};
use super::transport::Channel;
use super::wire::{self, Incoming};

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
        .exchange(
            op.wire_name(),
            Some(epoch),
            body,
            input.as_ref().map(InputRegion::outbound),
        )
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
    report(worker, &frame.body);
    serde_json::from_value(frame.body).map_err(|_| OpFault::Cut)
}

/// `session.export` of `body` to the incarnation `epoch` names: its answer
/// and the snapshot region the answer's frame passed, both checked. The
/// answer names `body`'s checkpoint exactly, and a region described as one
/// whole `snapshot_v1` region of `snapshot_bytes` on this request, passed
/// as the frame's one descriptor; the region is immutable, that long, and
/// hashes to `snapshot_sha256`. An export changes nothing on the worker, so
/// a cut may be asked again.
pub(in crate::models) async fn export(
    socket: &Path,
    epoch: &str,
    body: &SessionExport,
    worker: &InferenceWorker,
) -> Result<(SessionExported, SnapshotRegion), OpFault> {
    let op = SessionOp::Export;
    let request = serde_json::to_value(body).map_err(|e| cut(op, &e))?;
    let mut channel = Channel::connect(socket).await.map_err(|e| cut(op, &e))?;
    let (frame, mut fds) = channel
        .exchange_with_fds(op.wire_name(), Some(epoch), request, None)
        .await
        .map_err(|e| cut(op, &e))?;
    let answer: SessionExported = answer_of(op, epoch, &frame)?;
    if answer.checkpoint != body.checkpoint {
        return Err(cut(op, &"the answer names another checkpoint"));
    }
    if answer.output.buffer_id != frame.request_id {
        return Err(cut(op, &"the output names another buffer"));
    }
    let fd = match (fds.pop(), fds.is_empty()) {
        (Some(fd), true) => fd,
        _ => return Err(cut(op, &"the answer passed no single descriptor")),
    };
    let region = SnapshotRegion::received(fd, &answer.output, answer.snapshot_bytes)
        .map_err(|e| cut(op, &e))?;
    if region.sha256().map_err(|e| cut(op, &e))? != answer.snapshot_sha256.0 {
        return Err(cut(op, &"the region's SHA-256 is not the answer's"));
    }
    report(worker, &frame.body);
    Ok((answer, region))
}

/// `session.import` of `body` to the incarnation `epoch` names, with
/// `snapshot` as its input region: the answer, checked. It staged `body`'s
/// checkpoint exactly, and read all of `snapshot_bytes` under the same
/// SHA-256. Anything else is a cut, and the caller drops the session.
pub(in crate::models) async fn import(
    socket: &Path,
    epoch: &str,
    body: &SessionImport,
    snapshot: &SnapshotRegion,
    worker: &InferenceWorker,
) -> Result<SessionImported, OpFault> {
    let op = SessionOp::Import;
    if snapshot.len() != body.snapshot_bytes {
        return Err(cut(op, &"the region is not the snapshot the body names"));
    }
    let request = serde_json::to_value(body).map_err(|e| cut(op, &e))?;
    let mut channel = Channel::connect(socket).await.map_err(|e| cut(op, &e))?;
    let frame = channel
        .exchange(
            op.wire_name(),
            Some(epoch),
            request,
            Some(snapshot.outbound()),
        )
        .await
        .map_err(|e| cut(op, &e))?;
    let answer: SessionImported = answer_of(op, epoch, &frame)?;
    if answer.staged != body.checkpoint {
        return Err(cut(op, &"the answer staged another checkpoint"));
    }
    if answer.imported_bytes != body.snapshot_bytes
        || answer.snapshot_sha256 != body.snapshot_sha256
    {
        return Err(cut(op, &"the answer read other bytes"));
    }
    report(worker, &frame.body);
    Ok(answer)
}

/// The answer `frame` gives `op`: its own frame, from the incarnation
/// `epoch` names, read; or the worker's refusal.
fn answer_of<R: DeserializeOwned>(
    op: SessionOp,
    epoch: &str,
    frame: &Incoming,
) -> Result<R, OpFault> {
    if frame.op == "refused" {
        return Err(OpFault::Refused(wire::refusal_code(&frame.body).to_owned()));
    }
    if frame.op != op.wire_name() {
        return Err(cut(op, &"the worker answered with another op"));
    }
    if frame.epoch.as_deref() != Some(epoch) {
        return Err(cut(op, &"the answer names another incarnation"));
    }
    serde_json::from_value(frame.body.clone()).map_err(|e| cut(op, &e))
}

/// A snapshot op's cut, logged with its cause.
fn cut(op: SessionOp, cause: &dyn std::fmt::Display) -> OpFault {
    tracing::warn!(op = op.wire_name(), %cause, "native EXL3 snapshot op cut");
    OpFault::Cut
}

/// Feeds the cheap stats an answer carries to `worker`'s activity.
fn report(worker: &InferenceWorker, body: &JsonValue) {
    if let Some(activity) = body.get("stats").and_then(super::activity_of) {
        super::worker_host::report_device_activity(worker, activity);
    }
}
