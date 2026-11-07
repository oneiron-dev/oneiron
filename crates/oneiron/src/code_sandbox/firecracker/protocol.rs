//! Bounded guest-agent framing; no host filesystem or credential capabilities.

use super::refused;
use crate::{
    Result,
    code_sandbox::{
        ProposalSpoolFloor, SandboxCredentialCall, SandboxCredentialHandle,
        SandboxFileDeleteProposal, SandboxFileRenameProposal, SandboxFileWriteProposal,
        SandboxMount, SandboxProposalBody, SandboxProposalBodyWriter, SandboxProposalWrite,
        SandboxVirtualPath,
        microvm::{
            CredentialEgressProxy, CredentialReadTransport, ExecutionBudget, MicroVmExit,
            MicroVmHandle,
        },
    },
    engine_executor::StepCancellation,
};
use oneiron_sandbox_contract::{
    GUEST_PROTOCOL_VERSION, MAX_CHUNK_BYTES, MAX_COMPONENT_BYTES, MAX_PROGRAM_BYTES, WorkspacePath,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Instant,
};

const MAX_FRAME: usize = oneiron_sandbox_contract::MAX_FRAME_BYTES;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum GuestFrame {
    Hello {
        version: u32,
    },
    CredentialRead {
        handle: String,
        operation: String,
        scheme: String,
        host: String,
    },
    /// A proposed file streams in: its path, then its frames, then its end.
    /// One file is open at a time.
    WriteOpen {
        path: String,
    },
    WriteChunk {
        bytes: Vec<u8>,
    },
    WriteClose,
    Delete {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    OutputText {
        target: String,
        start: bool,
        frame: String,
    },
    OutputBytes {
        path: String,
        frame: Vec<u8>,
    },
    StoreBytes {
        start: bool,
        frame: Vec<u8>,
    },
    StepResult {
        result_json: String,
    },
    Finish {
        status: i32,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostFrame<'a> {
    Start {
        version: u32,
        vm_id: &'a str,
        tier: &'a str,
        pids: u32,
        component_bytes: usize,
        source: &'a str,
    },
    Component {
        offset: usize,
        bytes: &'a [u8],
    },
    FileOpen {
        path: &'a str,
        len: u64,
    },
    FileChunk {
        bytes: &'a [u8],
    },
    FileClose,
    Ready,
    Receipt {
        accepted: bool,
    },
    Failure {
        code: &'a str,
        detail: &'a str,
    },
}

pub(in crate::code_sandbox) struct GuestProgram<'a> {
    pub component: &'a [u8],
    pub source: &'a str,
}

/// [`exchange_cancellable`] for a step nothing cancels.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "this file is compiled under two modules, and the tests of only one call it"
)]
pub(in crate::code_sandbox) fn exchange(
    stream: UnixStream,
    vm: &MicroVmHandle,
    program: GuestProgram<'_>,
    budget: ExecutionBudget,
    deadline: Instant,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    exchange_cancellable(
        stream,
        vm,
        program,
        budget,
        deadline,
        proxy,
        transport,
        None,
        &StepCancellation::never(),
    )
}

/// One guest's exchange under its step's token (FIX 600). The token is read
/// before the exchange starts, at each frame boundary and around the host
/// call a credential frame makes. The backend cuts the stream once the token
/// fires; the cut stream's error, and any result that raced the cancel, give
/// way to [`crate::error::CodeError::CodeStepCancelled`]. Its proposed files
/// spool on `spool`, the host's measured disk floor, when one was lent
/// (FIX 7650).
#[expect(
    clippy::too_many_arguments,
    reason = "the exchange takes the guest's stream, program, budget, policies, spool and token"
)]
pub(in crate::code_sandbox) fn exchange_cancellable(
    mut stream: UnixStream,
    vm: &MicroVmHandle,
    program: GuestProgram<'_>,
    budget: ExecutionBudget,
    deadline: Instant,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
    spool: Option<&dyn ProposalSpoolFloor>,
    cancel: &StepCancellation,
    output: &mut dyn crate::code_sandbox::microvm::MicroVmOutputSink,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    let exchanged = (|| {
        cancel.check()?;
        let GuestProgram { component, source } = program;
        if source.len() > MAX_PROGRAM_BYTES {
            return Err(refused("guest source exceeds message budget"));
        }
        if component.is_empty() || component.len() > MAX_COMPONENT_BYTES {
            return Err(refused("guest component size refused"));
        }
        if !matches!(
            read_frame(&mut stream, deadline)?,
            GuestFrame::Hello { version } if version == GUEST_PROTOCOL_VERSION
        ) {
            return Err(refused("guest protocol version mismatch"));
        }
        cancel.check()?;
        write_frame(
            &mut stream,
            &HostFrame::Start {
                version: GUEST_PROTOCOL_VERSION,
                vm_id: vm.id(),
                tier: vm.tier().as_str(),
                pids: budget.pids,
                component_bytes: component.len(),
                source,
            },
            deadline,
        )?;
        for (index, bytes) in component.chunks(256 * 1024).enumerate() {
            write_frame(
                &mut stream,
                &HostFrame::Component {
                    offset: index * 256 * 1024,
                    bytes,
                },
                deadline,
            )?;
        }
        // Snapshot bytes only. There is no host mount device inside the VM
        // and no path from a guest overlay file to the original source
        // directory.
        let base = super::snapshot::files(vm.base_root(), spool, cancel, deadline)?;
        let mut frame = vec![0; MAX_CHUNK_BYTES];
        for file in &base.files {
            cancel.check()?;
            write_frame(
                &mut stream,
                &HostFrame::FileOpen {
                    path: file.path.as_str(),
                    len: file.body.len(),
                },
                deadline,
            )?;
            let mut reader = file.body.reader();
            loop {
                cancel.check()?;
                let read = reader.read(&mut frame)?;
                if read == 0 {
                    break;
                }
                write_frame(
                    &mut stream,
                    &HostFrame::FileChunk {
                        bytes: &frame[..read],
                    },
                    deadline,
                )?;
            }
            write_frame(&mut stream, &HostFrame::FileClose, deadline)?;
        }
        cancel.check()?;
        write_frame(&mut stream, &HostFrame::Ready, deadline)?;
        let (mut exit, writes) = receive_proposals_cancellable(
            stream, vm, &base, deadline, proxy, transport, spool, cancel, output,
        )?;
        let mut edits = Vec::new();
        for write in writes {
            match write {
                SandboxProposalWrite::FileWrite(file) => {
                    let edit = match base.files.iter().find(|entry| entry.path == file.path) {
                        Some(entry) => file.lower_to_edit_spooled(&entry.body, cancel, deadline)?,
                        None => file.lower_to_edit_cancellable(b"", cancel, deadline)?,
                    };
                    if let Some(edit) = edit {
                        edits.push(SandboxProposalWrite::FileEdit(edit));
                    }
                }
                SandboxProposalWrite::FileDelete(_) | SandboxProposalWrite::FileRename(_) => {
                    edits.push(write);
                }
                _ => return Err(refused("unexpected guest proposal kind")),
            }
        }
        exit.overlay_dirty = !edits.is_empty();
        Ok((exit, edits))
    })();
    // A cancel seen by the end wins over the error its cut stream raised, and
    // drops a result and proposals that raced it.
    cancel.check()?;
    exchanged
}

/// [`receive_proposals_cancellable`] for a step nothing cancels.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "this file is compiled under two modules, and the tests of only one call it"
)]
fn receive_proposals(
    stream: UnixStream,
    vm: &MicroVmHandle,
    base: &super::snapshot::Snapshot,
    deadline: Instant,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    receive_proposals_cancellable(
        stream,
        vm,
        base,
        deadline,
        proxy,
        transport,
        None,
        &StepCancellation::never(),
    )
}

/// The guest's proposals. A proposed file spools on `spool`, the host's
/// measured disk floor, when one was lent: each chunk is admitted on the
/// shared floor before it is written, and one that would cross it ends the
/// exchange with [`crate::error::CodeError::SandboxProposalDiskFloor`]
/// (FIX 7650). Without one it spools as before.
#[expect(
    clippy::too_many_arguments,
    reason = "the receiver takes the guest's stream, snapshot, policies, spool and token"
)]
fn receive_proposals_cancellable(
    mut stream: UnixStream,
    vm: &MicroVmHandle,
    base: &super::snapshot::Snapshot,
    deadline: Instant,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
    spool: Option<&dyn ProposalSpoolFloor>,
    cancel: &StepCancellation,
    output: &mut dyn crate::code_sandbox::microvm::MicroVmOutputSink,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    let mut writes = BTreeMap::new();
    let mut result_json = None;
    // One effect per path: a deleted file or a rename endpoint is not
    // written again in the same run.
    let mut occupied = BTreeSet::new();
    // The snapshot tree (empty directories included) with every accepted
    // proposal applied, under the same rules as the guest and the walker.
    let mut shape = base.shape.clone();
    // The file streaming in, if any.
    let mut open: Option<(SandboxVirtualPath, SandboxProposalBodyWriter)> = None;
    // No frame count ends a run: cancellation and the deadline bound it, and
    // each frame is checked as it comes (FIX 8026).
    loop {
        cancel.check()?;
        let frame = read_frame(&mut stream, deadline)?;
        if open.is_some()
            && !matches!(
                frame,
                GuestFrame::WriteChunk { .. }
                    | GuestFrame::WriteClose
                    | GuestFrame::CredentialRead { .. }
                    | GuestFrame::OutputText { .. }
                    | GuestFrame::OutputBytes { .. }
                    | GuestFrame::StoreBytes { .. }
            )
        {
            return Err(refused("guest frame inside an open file proposal"));
        }
        match frame {
            GuestFrame::Hello { .. } => return Err(refused("duplicate guest hello")),
            GuestFrame::CredentialRead {
                handle,
                operation,
                scheme,
                host,
            } => {
                // Operation and destination only. No guest-controlled URL,
                // headers, body, redirects, or request-authority parameters.
                let call = SandboxCredentialCall::read_only(
                    operation,
                    SandboxCredentialHandle::new(handle)?,
                    rmpv::Value::Map(vec![
                        ("scheme".into(), scheme.into()),
                        ("host".into(), host.into()),
                    ]),
                )?;
                // The host call is admitted only while the step runs, and a
                // cancel that lands while it runs drops its answer.
                cancel.check()?;
                let accepted = match transport {
                    Some(transport) => proxy.forward_read(vm, &call, transport).is_ok(),
                    None => {
                        proxy.record_transport_unavailable(vm, &call);
                        false
                    }
                };
                cancel.check()?;
                write_frame(&mut stream, &HostFrame::Receipt { accepted }, deadline)?;
            }
            GuestFrame::WriteOpen { path } => {
                let path = SandboxVirtualPath::try_new(path)?;
                if path.mount() != SandboxMount::Workspace
                    || !occupied.insert(path.as_str().to_owned())
                {
                    return Err(refused("guest proposal path or duplicate refused"));
                }
                shape
                    .replace_file(&workspace_path(&path)?, 0)
                    .map_err(|error| refused(error.reason()))?;
                let body = match spool {
                    Some(floor) => SandboxProposalBody::spool_floored(floor)?,
                    None => SandboxProposalBody::spool()?,
                };
                open = Some((path, body));
                write_frame(
                    &mut stream,
                    &HostFrame::Receipt { accepted: true },
                    deadline,
                )?;
            }
            GuestFrame::WriteChunk { bytes } => {
                let Some((_, body)) = open.as_mut() else {
                    return Err(refused("guest file frame outside a file proposal"));
                };
                if let Err(error) = body.append(&bytes) {
                    if matches!(
                        &error,
                        crate::Error::Code(
                            crate::error::CodeError::SandboxProposalDiskFloor { .. }
                        )
                    ) {
                        drop(open.take());
                        writes.clear();
                        drop(bytes);
                        cancel.check()?;
                        if write_frame(
                            &mut stream,
                            &HostFrame::Failure {
                                code: oneiron_contracts::memory::MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR,
                                detail: &error.to_string(),
                            },
                            deadline,
                        )
                        .is_ok()
                        {
                            // Returning now would let the backend kill the guest before
                            // its chunk call receives the reason. Drop proposals first,
                            // then wait for one frame under the original step bound.
                            cancel.check()?;
                            let _ = read_frame(&mut stream, deadline);
                        }
                    }
                    return Err(error);
                }
                write_frame(
                    &mut stream,
                    &HostFrame::Receipt { accepted: true },
                    deadline,
                )?;
            }
            GuestFrame::WriteClose => {
                let Some((path, body)) = open.take() else {
                    return Err(refused("guest file end outside a file proposal"));
                };
                let body = body.finish()?;
                shape
                    .replace_file(
                        &workspace_path(&path)?,
                        usize::try_from(body.len())
                            .map_err(|_| refused("guest proposal length overflow"))?,
                    )
                    .map_err(|error| refused(error.reason()))?;
                writes.insert(
                    path.as_str().to_owned(),
                    SandboxProposalWrite::FileWrite(SandboxFileWriteProposal::new(path, body)),
                );
                write_frame(
                    &mut stream,
                    &HostFrame::Receipt { accepted: true },
                    deadline,
                )?;
            }
            GuestFrame::Delete { path } => {
                let path = SandboxVirtualPath::try_new(path)?;
                if path.mount() != SandboxMount::Workspace
                    || !base.files.iter().any(|file| file.path == path)
                    || !occupied.insert(path.as_str().to_owned())
                {
                    return Err(refused("guest delete path refused"));
                }
                shape
                    .remove_file(&workspace_path(&path)?)
                    .map_err(|error| refused(error.reason()))?;
                writes.insert(
                    path.as_str().to_owned(),
                    SandboxProposalWrite::FileDelete(SandboxFileDeleteProposal { path }),
                );
                write_frame(
                    &mut stream,
                    &HostFrame::Receipt { accepted: true },
                    deadline,
                )?;
            }
            GuestFrame::Rename { from, to } => {
                let from = SandboxVirtualPath::try_new(from)?;
                let to = SandboxVirtualPath::try_new(to)?;
                if from.mount() != SandboxMount::Workspace
                    || to.mount() != SandboxMount::Workspace
                    || from == to
                    || !base.files.iter().any(|file| file.path == from)
                    || occupied.contains(from.as_str())
                    || occupied.contains(to.as_str())
                {
                    return Err(refused("guest rename path refused"));
                }
                shape
                    .rename_file(&workspace_path(&from)?, &workspace_path(&to)?)
                    .map_err(|error| refused(error.reason()))?;
                occupied.insert(from.as_str().to_owned());
                occupied.insert(to.as_str().to_owned());
                writes.insert(
                    from.as_str().to_owned(),
                    SandboxProposalWrite::FileRename(SandboxFileRenameProposal { from, to }),
                );
                write_frame(
                    &mut stream,
                    &HostFrame::Receipt { accepted: true },
                    deadline,
                )?;
            }
            GuestFrame::OutputText {
                target,
                start,
                frame,
            } => {
                let target = match target.as_str() {
                    "console" => crate::engine_executor::JsCodeModeStream::Console,
                    "finish" => crate::engine_executor::JsCodeModeStream::Finish { start },
                    "store" => crate::engine_executor::JsCodeModeStream::Store { start },
                    _ => return Err(refused("unknown streamed output target")),
                };
                receive_output(
                    &mut stream,
                    deadline,
                    cancel,
                    output,
                    target,
                    frame.into_bytes(),
                )?;
            }
            GuestFrame::OutputBytes { path, frame } => {
                let path = SandboxVirtualPath::try_new(path)?;
                if path.mount() != SandboxMount::Outputs {
                    return Err(refused("component output must be under /mnt/outputs"));
                }
                receive_output(
                    &mut stream,
                    deadline,
                    cancel,
                    output,
                    crate::engine_executor::JsCodeModeStream::File(path.as_str()),
                    frame,
                )?;
            }
            GuestFrame::StoreBytes { start, frame } => {
                receive_output(
                    &mut stream,
                    deadline,
                    cancel,
                    output,
                    crate::engine_executor::JsCodeModeStream::Store { start },
                    frame,
                )?;
            }
            GuestFrame::StepResult {
                result_json: result,
            } => {
                if result_json.is_some() || result.len() > oneiron_sandbox_contract::MAX_FILE_BYTES
                {
                    return Err(refused("duplicate or oversized guest step result"));
                }
                serde_json::from_str::<serde_json::Value>(&result)
                    .map_err(|_| refused("invalid guest result JSON"))?;
                result_json = Some(result);
            }
            GuestFrame::Finish { status } => {
                if status != 0 {
                    return Err(refused("guest run failed; proposals discarded"));
                }
                return Ok((
                    MicroVmExit {
                        status,
                        overlay_dirty: !writes.is_empty(),
                        result_json,
                    },
                    writes.into_values().collect(),
                ));
            }
        }
    }
}

fn receive_output(
    stream: &mut UnixStream,
    deadline: Instant,
    cancel: &StepCancellation,
    output: &mut dyn crate::code_sandbox::microvm::MicroVmOutputSink,
    target: crate::engine_executor::JsCodeModeStream<'_>,
    frame: Vec<u8>,
) -> Result<()> {
    if frame.len() > MAX_CHUNK_BYTES {
        return Err(refused("output frame exceeds one message"));
    }
    cancel.check()?;
    let stored = output.write_output_frame(target, frame);
    cancel.check()?;
    match stored {
        Ok(()) => write_frame(stream, &HostFrame::Receipt { accepted: true }, deadline),
        Err(error) => {
            let code = if matches!(
                &error,
                crate::Error::Code(crate::error::CodeError::SandboxProposalDiskFloor { .. })
            ) {
                oneiron_contracts::memory::MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR
            } else {
                "HOST_OUTPUT_FAILED"
            };
            if write_frame(
                stream,
                &HostFrame::Failure {
                    code,
                    detail: &error.to_string(),
                },
                deadline,
            )
            .is_ok()
            {
                cancel.check()?;
                let _ = read_frame(stream, deadline);
            }
            Err(error)
        }
    }
}

fn set_deadline(stream: &UnixStream, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| refused("guest execution deadline exceeded"))?;
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| refused("guest transport deadline setup failed"))
}
fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<GuestFrame> {
    set_deadline(stream, deadline)?;
    let mut len = [0; 4];
    stream
        .read_exact(&mut len)
        .map_err(|_| refused("guest frame header read failed"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(refused("guest frame size refused"));
    }
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| refused("guest frame read failed"))?;
    serde_json::from_slice(&bytes).map_err(|_| refused("invalid guest frame"))
}
fn write_frame(stream: &mut UnixStream, value: &HostFrame<'_>, deadline: Instant) -> Result<()> {
    set_deadline(stream, deadline)?;
    let bytes = serde_json::to_vec(value).map_err(|_| refused("host frame encoding failed"))?;
    if bytes.len() > MAX_FRAME {
        return Err(refused("host frame size refused"));
    }
    let len = u32::try_from(bytes.len()).map_err(|_| refused("host frame length overflow"))?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .map_err(|_| refused("host frame write failed"))
}

fn workspace_path(path: &SandboxVirtualPath) -> Result<WorkspacePath> {
    WorkspacePath::parse(path.as_str()).map_err(|error| refused(error.reason()))
}

#[cfg(test)]
mod tests;
