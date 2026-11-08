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
use oneiron::llm::{
    SESSION_SCHEMA_MINOR, SESSIONS_CAPABILITY, SessionAppend, SessionAppended, SessionCapability,
    SessionExport, SessionExported, SessionImport, SessionImported, SessionInvalidation, SessionOp,
    SessionPrepare, SessionPrepared,
};
use oneiron_driver::InferenceWorker;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;

use super::buffer::{InputRegion, SnapshotRegion};
use super::transport::Channel;
use super::wire::{self, Incoming};
use super::worker_host::NativeLaunch;

/// How a session op went wrong.
pub(in crate::models) enum OpFault {
    /// The worker refused it before anything ran, with this code.
    Refused(String),
    /// The channel failed or the answer did not read: it may have run.
    Cut,
}

/// The session ops `launch` advertises in its authenticated hello; `None`
/// when it advertises none at codec v1.1, or does not answer.
pub(in crate::models) async fn capability(
    launch: &NativeLaunch,
    epoch: &str,
) -> Option<SessionCapability> {
    let (_, hello) = Channel::connect_launch(launch, Some(epoch)).await.ok()?;
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
    launch: &NativeLaunch,
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
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|_| OpFault::Cut)?;
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

pub(in crate::models) enum ReleasedOpFault {
    Op(OpFault),
    Release(oneiron::LlmError),
}

pub(in crate::models) async fn send_released<B: Serialize, R: DeserializeOwned>(
    launch: &NativeLaunch,
    epoch: &str,
    op: SessionOp,
    body: &B,
    conversation: &JsonValue,
    worker: &InferenceWorker,
    lease: &oneiron::BudgetLease,
) -> Result<R, ReleasedOpFault> {
    if !lease.has_dispatch_release() {
        return send(launch, epoch, op, body, Some(conversation), worker)
            .await
            .map_err(ReleasedOpFault::Op);
    }
    let body = serde_json::to_value(body).map_err(|_| ReleasedOpFault::Op(OpFault::Cut))?;
    let bytes = serde_json::to_vec(conversation).map_err(|_| ReleasedOpFault::Op(OpFault::Cut))?;
    let input = InputRegion::new(&bytes).map_err(|_| ReleasedOpFault::Op(OpFault::Cut))?;
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|_| ReleasedOpFault::Op(OpFault::Cut))?;
    let frame = channel
        .exchange_released(op.wire_name(), Some(epoch), body, input.outbound(), lease)
        .await
        .map_err(|error| match error {
            super::transport::ReleasedExchangeError::Transport(_) => {
                ReleasedOpFault::Op(OpFault::Cut)
            }
            super::transport::ReleasedExchangeError::Release(error) => {
                ReleasedOpFault::Release(error)
            }
        })?;
    drop(input);
    if frame.op == "refused" {
        return Err(ReleasedOpFault::Op(OpFault::Refused(
            wire::refusal_code(&frame.body).to_owned(),
        )));
    }
    if frame.op != op.wire_name() {
        return Err(ReleasedOpFault::Op(OpFault::Cut));
    }
    report(worker, &frame.body);
    serde_json::from_value(frame.body).map_err(|_| ReleasedOpFault::Op(OpFault::Cut))
}

pub(in crate::models) type ControlSourceFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), SessionInvalidation>> + Send + 'a>,
>;
pub(in crate::models) type ControlSourceCheck<'a> = dyn Fn() -> ControlSourceFuture<'a> + Sync + 'a;

/// A control frame's source rejection is not a worker fault or a live release.
pub(in crate::models) enum ReleasedControlFault {
    Op(OpFault),
    Release(oneiron::LlmError),
    Source(SessionInvalidation),
}

pub(in crate::models) async fn control_source_released<B: Serialize, R: DeserializeOwned>(
    launch: &NativeLaunch,
    epoch: &str,
    op: SessionOp,
    body: &B,
    worker: &InferenceWorker,
    lease: &oneiron::BudgetLease,
    source: &ControlSourceCheck<'_>,
) -> Result<R, ReleasedControlFault> {
    if !lease.has_dispatch_release() {
        return send(launch, epoch, op, body, None, worker)
            .await
            .map_err(ReleasedControlFault::Op);
    }
    let body = serde_json::to_value(body).map_err(|_| ReleasedControlFault::Op(OpFault::Cut))?;
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|_| ReleasedControlFault::Op(OpFault::Cut))?;
    let frame = channel
        .exchange_control_released(op.wire_name(), Some(epoch), body, lease, source)
        .await
        .map_err(|error| match error {
            super::transport::ControlExchangeError::Transport(_) => {
                ReleasedControlFault::Op(OpFault::Cut)
            }
            super::transport::ControlExchangeError::Release(error) => {
                ReleasedControlFault::Release(error)
            }
            super::transport::ControlExchangeError::Source(reason) => {
                ReleasedControlFault::Source(reason)
            }
        })?;
    if frame.op == "refused" {
        return Err(ReleasedControlFault::Op(OpFault::Refused(
            wire::refusal_code(&frame.body).to_owned(),
        )));
    }
    if frame.op != op.wire_name() {
        return Err(ReleasedControlFault::Op(OpFault::Cut));
    }
    report(worker, &frame.body);
    serde_json::from_value(frame.body).map_err(|_| ReleasedControlFault::Op(OpFault::Cut))
}

pub(in crate::models) type AppendSourceFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), SessionInvalidation>> + Send + 'a>,
>;
pub(in crate::models) type AppendSourceCheck<'a> = dyn Fn() -> AppendSourceFuture<'a> + Sync + 'a;

/// The successor authority keeps its rejection separate from a worker fault.
pub(in crate::models) enum ReleasedAppendFault {
    Op(OpFault),
    Release(oneiron::LlmError),
    Source(SessionInvalidation),
}

pub(in crate::models) async fn append_source_released(
    launch: &NativeLaunch,
    epoch: &str,
    body: &SessionAppend,
    conversation: &JsonValue,
    worker: &InferenceWorker,
    lease: &oneiron::BudgetLease,
    source: &AppendSourceCheck<'_>,
) -> Result<SessionAppended, ReleasedAppendFault> {
    let op = SessionOp::Append;
    if !lease.has_dispatch_release() {
        return send(launch, epoch, op, body, Some(conversation), worker)
            .await
            .map_err(ReleasedAppendFault::Op);
    }
    let body = serde_json::to_value(body).map_err(|_| ReleasedAppendFault::Op(OpFault::Cut))?;
    let bytes =
        serde_json::to_vec(conversation).map_err(|_| ReleasedAppendFault::Op(OpFault::Cut))?;
    let input = InputRegion::new(&bytes).map_err(|_| ReleasedAppendFault::Op(OpFault::Cut))?;
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|_| ReleasedAppendFault::Op(OpFault::Cut))?;
    let frame = channel
        .exchange_append_released(
            op.wire_name(),
            Some(epoch),
            body,
            input.outbound(),
            lease,
            source,
        )
        .await
        .map_err(|error| match error {
            super::transport::AppendExchangeError::Transport(_) => {
                ReleasedAppendFault::Op(OpFault::Cut)
            }
            super::transport::AppendExchangeError::Release(error) => {
                ReleasedAppendFault::Release(error)
            }
            super::transport::AppendExchangeError::Source(reason) => {
                ReleasedAppendFault::Source(reason)
            }
        })?;
    drop(input);
    if frame.op == "refused" {
        return Err(ReleasedAppendFault::Op(OpFault::Refused(
            wire::refusal_code(&frame.body).to_owned(),
        )));
    }
    if frame.op != op.wire_name() {
        return Err(ReleasedAppendFault::Op(OpFault::Cut));
    }
    report(worker, &frame.body);
    serde_json::from_value(frame.body).map_err(|_| ReleasedAppendFault::Op(OpFault::Cut))
}

/// A preparation's canonical source or its newly rendered tail changed.
#[derive(Debug)]
pub(in crate::models) enum PrepareSourceMiss {
    Canonical(SessionInvalidation),
    TailChanged,
}

pub(in crate::models) type PrepareSourceFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PrepareSourceMiss>> + Send + 'a>>;
pub(in crate::models) type PrepareSourceCheck<'a> = dyn Fn() -> PrepareSourceFuture<'a> + Sync + 'a;

pub(in crate::models) enum ReleasedPrepareFault {
    Op(OpFault),
    Release(oneiron::LlmError),
    Source(PrepareSourceMiss),
}

pub(in crate::models) async fn prepare_source_released(
    launch: &NativeLaunch,
    epoch: &str,
    body: &SessionPrepare,
    conversation: &JsonValue,
    worker: &InferenceWorker,
    lease: &oneiron::BudgetLease,
    source: &PrepareSourceCheck<'_>,
) -> Result<SessionPrepared, ReleasedPrepareFault> {
    let op = SessionOp::Prepare;
    if !lease.has_dispatch_release() {
        return send(launch, epoch, op, body, Some(conversation), worker)
            .await
            .map_err(ReleasedPrepareFault::Op);
    }
    let body = serde_json::to_value(body).map_err(|_| ReleasedPrepareFault::Op(OpFault::Cut))?;
    let bytes =
        serde_json::to_vec(conversation).map_err(|_| ReleasedPrepareFault::Op(OpFault::Cut))?;
    let input = InputRegion::new(&bytes).map_err(|_| ReleasedPrepareFault::Op(OpFault::Cut))?;
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|_| ReleasedPrepareFault::Op(OpFault::Cut))?;
    let frame = channel
        .exchange_prepare_released(
            op.wire_name(),
            Some(epoch),
            body,
            input.outbound(),
            lease,
            source,
        )
        .await
        .map_err(|error| match error {
            super::transport::PrepareExchangeError::Transport(_) => {
                ReleasedPrepareFault::Op(OpFault::Cut)
            }
            super::transport::PrepareExchangeError::Release(error) => {
                ReleasedPrepareFault::Release(error)
            }
            super::transport::PrepareExchangeError::Source(reason) => {
                ReleasedPrepareFault::Source(reason)
            }
        })?;
    drop(input);
    if frame.op == "refused" {
        return Err(ReleasedPrepareFault::Op(OpFault::Refused(
            wire::refusal_code(&frame.body).to_owned(),
        )));
    }
    if frame.op != op.wire_name() {
        return Err(ReleasedPrepareFault::Op(OpFault::Cut));
    }
    report(worker, &frame.body);
    serde_json::from_value(frame.body).map_err(|_| ReleasedPrepareFault::Op(OpFault::Cut))
}

/// `session.export` of `body` to the incarnation `epoch` names: its answer
/// and the snapshot region the answer's frame passed, both checked. The
/// answer names `body`'s checkpoint exactly, and a region described as one
/// whole `snapshot_v1` region of `snapshot_bytes` on this request, passed
/// as the frame's one descriptor; the region is immutable, that long, and
/// hashes to `snapshot_sha256`. An export changes nothing on the worker, so
/// a cut may be asked again.
pub(in crate::models) async fn export(
    launch: &NativeLaunch,
    epoch: &str,
    body: &SessionExport,
    worker: &InferenceWorker,
) -> Result<(SessionExported, SnapshotRegion), OpFault> {
    let op = SessionOp::Export;
    let request = serde_json::to_value(body).map_err(|e| cut(op, &e))?;
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|e| cut(op, &e))?;
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
    launch: &NativeLaunch,
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
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|e| cut(op, &e))?;
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

/// Why the stored snapshot cannot be written under its original authority.
pub(in crate::models) enum SnapshotSourceMiss {
    /// The admission lapsed; the kept snapshot remains valid.
    Cold,
    /// The snapshot's own authority no longer holds; retire it.
    Retire,
}

pub(in crate::models) type SnapshotSourceFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), SnapshotSourceMiss>> + Send + 'a>,
>;
pub(in crate::models) type SnapshotSourceCheck<'a> =
    dyn Fn() -> SnapshotSourceFuture<'a> + Sync + 'a;

/// A snapshot cache miss is not a worker fault or a live call's release.
pub(in crate::models) enum SnapshotImportFault {
    Op(OpFault),
    Release(oneiron::LlmError),
    Source(SnapshotSourceMiss),
}

/// Imports a kept snapshot under the turn's live conditions and its own
/// stored-source authority, checked again at each descriptor write.
pub(in crate::models) async fn import_released(
    launch: &NativeLaunch,
    epoch: &str,
    body: &SessionImport,
    snapshot: &SnapshotRegion,
    worker: &InferenceWorker,
    lease: &oneiron::BudgetLease,
    source: &SnapshotSourceCheck<'_>,
) -> Result<SessionImported, SnapshotImportFault> {
    if !lease.has_dispatch_release() {
        return import(launch, epoch, body, snapshot, worker)
            .await
            .map_err(SnapshotImportFault::Op);
    }
    let op = SessionOp::Import;
    if snapshot.len() != body.snapshot_bytes {
        return Err(SnapshotImportFault::Op(cut(
            op,
            &"the region is not the snapshot the body names",
        )));
    }
    let request = serde_json::to_value(body).map_err(|e| SnapshotImportFault::Op(cut(op, &e)))?;
    let (mut channel, _) = Channel::connect_launch(launch, Some(epoch))
        .await
        .map_err(|e| SnapshotImportFault::Op(cut(op, &e)))?;
    let frame = channel
        .exchange_snapshot_released(
            op.wire_name(),
            Some(epoch),
            request,
            snapshot.outbound(),
            lease,
            source,
        )
        .await
        .map_err(|error| match error {
            super::transport::SnapshotExchangeError::Transport(error) => {
                SnapshotImportFault::Op(cut(op, &error))
            }
            super::transport::SnapshotExchangeError::Release(error) => {
                SnapshotImportFault::Release(error)
            }
            super::transport::SnapshotExchangeError::Source(miss) => {
                SnapshotImportFault::Source(miss)
            }
        })?;
    let answer: SessionImported = answer_of(op, epoch, &frame).map_err(SnapshotImportFault::Op)?;
    if answer.staged != body.checkpoint {
        return Err(SnapshotImportFault::Op(cut(
            op,
            &"the answer staged another checkpoint",
        )));
    }
    if answer.imported_bytes != body.snapshot_bytes
        || answer.snapshot_sha256 != body.snapshot_sha256
    {
        return Err(SnapshotImportFault::Op(cut(
            op,
            &"the answer read other bytes",
        )));
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
