//! Bounded guest-agent framing; no host filesystem or credential capabilities.

use super::refused;
use crate::{
    Result,
    code_sandbox::{
        SandboxCredentialCall, SandboxCredentialHandle, SandboxFileDeleteProposal,
        SandboxFileRenameProposal, SandboxFileWriteProposal, SandboxMount, SandboxProposalWrite,
        SandboxVirtualPath,
        microvm::{
            CredentialEgressProxy, CredentialReadTransport, ExecutionBudget, MicroVmExit,
            MicroVmHandle,
        },
    },
};
use oneiron_sandbox_contract::{MAX_COMPONENT_BYTES, MAX_PROGRAM_BYTES, WorkspacePath};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Instant,
};

const MAX_FRAME: usize = oneiron_sandbox_contract::MAX_FRAME_BYTES;
const MAX_REQUESTS: usize = oneiron_sandbox_contract::MAX_REQUESTS;

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
    Write {
        path: String,
        bytes: Vec<u8>,
    },
    Delete {
        path: String,
    },
    Rename {
        from: String,
        to: String,
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
    File {
        path: &'a str,
        bytes: &'a [u8],
    },
    Ready,
    Receipt {
        accepted: bool,
    },
}

pub(super) struct GuestProgram<'a> {
    pub component: &'a [u8],
    pub source: &'a str,
}

pub(super) fn exchange(
    mut stream: UnixStream,
    vm: &MicroVmHandle,
    program: GuestProgram<'_>,
    budget: ExecutionBudget,
    deadline: Instant,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    let GuestProgram { component, source } = program;
    if source.len() > MAX_PROGRAM_BYTES {
        return Err(refused("guest source exceeds message budget"));
    }
    if component.is_empty() || component.len() > MAX_COMPONENT_BYTES {
        return Err(refused("guest component size refused"));
    }
    if !matches!(
        read_frame(&mut stream, deadline)?,
        GuestFrame::Hello { version: 1 }
    ) {
        return Err(refused("guest protocol version mismatch"));
    }
    write_frame(
        &mut stream,
        &HostFrame::Start {
            version: 1,
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
    // Snapshot bytes only. There is no host mount device inside the VM and
    // no path from a guest overlay file to the original source directory.
    let base = super::snapshot::files(vm.base_root())?;
    for file in &base.files {
        write_frame(
            &mut stream,
            &HostFrame::File {
                path: file.path.as_str(),
                bytes: &file.bytes,
            },
            deadline,
        )?;
    }
    write_frame(&mut stream, &HostFrame::Ready, deadline)?;
    let (mut exit, writes) = receive_proposals(stream, vm, &base, deadline, proxy, transport)?;
    let mut edits = Vec::new();
    for write in writes {
        match write {
            SandboxProposalWrite::FileWrite(file) => {
                let old = base
                    .files
                    .iter()
                    .find(|entry| entry.path == file.path)
                    .map_or(b"".as_slice(), |entry| entry.bytes.as_slice());
                if let Some(edit) = file.lower_to_edit(old)? {
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
}

fn receive_proposals(
    mut stream: UnixStream,
    vm: &MicroVmHandle,
    base: &super::snapshot::Snapshot,
    deadline: Instant,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    let mut writes = BTreeMap::new();
    // One effect per path: a deleted file or a rename endpoint is not
    // written again in the same run.
    let mut occupied = BTreeSet::new();
    // The snapshot tree (empty directories included) with every accepted
    // proposal applied, under the same rules as the guest and the walker.
    let mut shape = base.shape.clone();
    for _ in 0..MAX_REQUESTS {
        match read_frame(&mut stream, deadline)? {
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
                let accepted = transport
                    .is_some_and(|transport| proxy.forward_read(vm, &call, transport).is_ok());
                write_frame(&mut stream, &HostFrame::Receipt { accepted }, deadline)?;
            }
            GuestFrame::Write { path, bytes } => {
                let path = SandboxVirtualPath::try_new(path)?;
                if path.mount() != SandboxMount::Workspace
                    || !occupied.insert(path.as_str().to_owned())
                {
                    return Err(refused("guest proposal path or duplicate refused"));
                }
                shape
                    .replace_file(&workspace_path(&path)?, bytes.len())
                    .map_err(|error| refused(error.reason()))?;
                writes.insert(
                    path.as_str().to_owned(),
                    SandboxProposalWrite::FileWrite(SandboxFileWriteProposal::new(path, bytes)),
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
            GuestFrame::Finish { status } => {
                if status != 0 {
                    return Err(refused("guest run failed; proposals discarded"));
                }
                return Ok((
                    MicroVmExit {
                        status,
                        overlay_dirty: !writes.is_empty(),
                    },
                    writes.into_values().collect(),
                ));
            }
        }
    }
    Err(refused("guest protocol request budget exhausted"))
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
