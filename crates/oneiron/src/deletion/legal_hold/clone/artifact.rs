//! A finite Messages capture from ONE of this vault's own backup artifacts,
//! the order's explicit choice (LEGAL-HOLD-USE = B as a clone, FIX 13863).
//! Its case: a still-live message's edge rows a later edit removed, which
//! only an earlier backup still holds; the live capture carries the earlier
//! rows the revision ledger keeps. The HOST hands the artifact's file over
//! on this same connection right after its request. Before anything is
//! accepted, the source checks the file against the request (whole length
//! and BLAKE3), opens it through the real opener under this vault's own
//! checkpoint key, checks its verified identity and reads the selected
//! messages under the custody guard, which it holds to the exact
//! acknowledgement. What an erase or purge retired since the cut stays shut.

use std::fs::File;
use std::io::{self, BufReader, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::legal_clone::SourceComponent;
use oneiron_vault_contract::host_legal::{
    ARTIFACT_FILE_MARKER, ArtifactMessages, CaptureExtent, CaptureRequest, CaptureSource,
};

use super::collector::{Collector, SummaryCounts};
use super::messages::{RESULT_BODY_FAMILY, holds_output, result_attachment};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::recovery::checkpoint::{
    ArtifactComponent, ArtifactMessage, ArtifactRead, ArtifactRefusal, LegalReadError,
    VerifiedArtifact, inspect_backup, open_artifact_read,
};
use crate::store::owned_body::BODY;
use crate::store::result_body_rows::RAW_OUTPUTS;
use crate::store::{PadObjectsCapture, UncapturedPadObjects};

/// `recvmsg` flags: the descriptor arrives close-on-exec where the kernel
/// can set it in the same call; elsewhere it is set right after.
#[cfg(any(target_os = "linux", target_os = "android"))]
const RECEIVE_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const RECEIVE_FLAGS: libc::c_int = 0;

/// Captures `selection` out of the artifact the HOST hands over next on
/// `stream`.
pub(super) fn capture(
    stream: &mut UnixStream,
    vault: &Vault,
    request: &CaptureRequest,
    public: &HybridPublicKey,
    selection: &ArtifactMessages,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    let file = File::from(receive_artifact_file(stream)?);
    let artifact = &selection.artifact;
    if artifact.vault_id != *vault.vault_id().as_bytes() {
        return Err(refused("legal capture artifact is another vault's"));
    }
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != artifact.file_len {
        return Err(refused("legal capture artifact file length"));
    }
    // The descriptor shares the HOST's file offset, which its own check
    // may have left anywhere: read from the start.
    (&file).seek(SeekFrom::Start(0))?;
    let evidence = inspect_backup(BufReader::new(&file))
        .map_err(|_| refused("legal capture artifact file does not inspect"))?;
    if evidence.outer_blake3 != artifact.file_blake3 || evidence.size != artifact.file_len {
        return Err(refused("legal capture artifact file digest"));
    }
    check()?;
    // From the key this handle holds: a locked vault refuses, and nothing
    // is unlocked, provisioned or written.
    let key = vault.held_checkpoint_key()?;
    // The custody guard BEFORE the live custody read, held to the exact
    // ACK: no retirement finishes while the artifact's compartments open.
    let _custody = vault.store.gate_custody_read_guard()?;
    let live = vault
        .store
        .live_custody(|_| PadObjectsCapture::NotCaptured {
            reason: UncapturedPadObjects::LegalRead,
        })?;
    let expected = VerifiedArtifact {
        vault_id: artifact.vault_id,
        checkpoint_id: artifact.checkpoint_id,
        commitment_digest: artifact.commitment_digest,
    };
    let mut read = match open_artifact_read(file, &key, &expected, &live, &selection.ids) {
        Ok(read) => read,
        Err(LegalReadError::Refused(ArtifactRefusal::IdentityMismatch)) => {
            return Err(refused("legal capture artifact identity"));
        }
        Err(LegalReadError::Failed(error)) => return Err(error),
    };
    check()?;
    let mut collector = Collector::pinned(stream, public, request)?;
    let mut captured = 0_u64;
    let mut missed_messages = Vec::new();
    let mut absent_result_bodies = Vec::new();
    for id in &selection.ids {
        check()?;
        let rows = match read.message(id)? {
            ArtifactMessage::Missed => {
                missed_messages.push(*id);
                continue;
            }
            ArtifactMessage::Held(rows) => rows,
        };
        // Every component of one message carries the revision of its row,
        // as the artifact holds it.
        let revision = *blake3::hash(&rows[0].value).as_bytes();
        for row in &rows {
            collector.component(
                source_component(row.component),
                CaptureSource::Message(*id),
                row.family,
                &row.key,
                revision,
                row.value.len() as u64,
                *blake3::hash(&row.value).as_bytes(),
                &mut &row.value[..],
                &check,
            )?;
        }
        captured += 1;
        if !result_body(
            &mut read,
            &mut collector,
            id,
            &rows[0].value,
            revision,
            &check,
        )? {
            absent_result_bodies.push(*id);
        }
    }
    check()?;
    collector.finish_counted(
        SummaryCounts {
            // Captured messages only; with `missed_messages` they are
            // exactly the selected ids.
            messages: captured,
            missed_messages,
            absent_result_bodies,
            ..SummaryCounts::default()
        },
        CaptureExtent::ArtifactMessages,
        &check,
    )?;
    // The custody guard ends after the exact durable HOST acknowledgement.
    Ok(())
}

/// Streams the result body the artifact's row `row` of message `id` names,
/// when that message's attachment occurrence (its own compartment, opened)
/// holds exactly that output and the artifact carries it under an instance
/// current custody still opens: component 11, as the live capture streams
/// it. `true` when there was no attachment or its body streamed; `false`
/// when the body stays uncaptured.
fn result_body(
    read: &mut ArtifactRead<'_>,
    collector: &mut Collector<'_>,
    id: &[u8; 16],
    row: &[u8],
    revision: [u8; 32],
    check: &impl Fn() -> Result<()>,
) -> Result<bool> {
    let Some(attachment) = result_attachment(row) else {
        return Ok(true);
    };
    let message = EntityId::from_bytes(*id)?;
    let output = attachment.output()?;
    let occurrence = attachment.message_occurrence(message)?;
    let hold = read
        .result_descriptor(&message, &occurrence)?
        .map(|bytes| BODY.decode_value(&bytes))
        .transpose()?;
    if !holds_output(hold, &output, &attachment) {
        return Ok(false);
    }
    let key = RAW_OUTPUTS.key_bytes(&output.handle);
    let Some(mut input) = read.result_body(&key, output.raw_blake3, output.raw_len) else {
        return Ok(false);
    };
    collector.component(
        SourceComponent::MessageResultBody,
        CaptureSource::Message(*id),
        RESULT_BODY_FAMILY,
        &key,
        revision,
        output.raw_len,
        output.raw_blake3,
        &mut *input,
        check,
    )?;
    Ok(true)
}

fn source_component(component: ArtifactComponent) -> SourceComponent {
    match component {
        ArtifactComponent::Row => SourceComponent::MessageRow,
        ArtifactComponent::Document => SourceComponent::MessageDocument,
        ArtifactComponent::Edge => SourceComponent::MessageEdge,
        ArtifactComponent::Revision => SourceComponent::MessageRevision,
    }
}

fn refused(reason: &'static str) -> crate::error::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason).into()
}

/// The artifact's file: exactly one byte, [`ARTIFACT_FILE_MARKER`], with
/// exactly one SCM_RIGHTS descriptor. Every descriptor the message carried
/// is owned at once, so each closes on every refusal; a truncated control
/// message, another control message, another byte or any other descriptor
/// count refuses. The request before it was read with exact reads, so no
/// buffered read took this byte or lost its descriptor.
fn receive_artifact_file(stream: &UnixStream) -> Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Room for several descriptors, so an extra one arrives (and closes)
    // instead of truncating the message.
    let mut control = [0_u64; 16];
    // SAFETY: an all-zero msghdr is valid; its pointers are set below to
    // the live `iov` and `control` buffers, which outlive the call.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: recvmsg writes only into the buffers `message` names, all
    // live and sized as stated.
    let read = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, RECEIVE_FLAGS) };
    if read < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut descriptors = Vec::new();
    let mut other_control = false;
    // SAFETY: the cmsg walk stays inside the control buffer recvmsg filled,
    // through the CMSG macros, and reads each descriptor unaligned. Every
    // descriptor an SCM_RIGHTS message carries is newly this process's, and
    // is owned exactly once.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                #[allow(
                    clippy::unnecessary_cast,
                    reason = "cmsg_len is usize on Linux and u32 on other Unix targets"
                )]
                let bytes =
                    ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                for index in 0..bytes / std::mem::size_of::<RawFd>() {
                    descriptors.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                        data.add(index),
                    )));
                }
            } else {
                other_control = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if read != 1
        || byte[0] != ARTIFACT_FILE_MARKER
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || other_control
        || descriptors.len() != 1
    {
        return Err(refused("legal capture artifact descriptor"));
    }
    let descriptor = descriptors
        .pop()
        .ok_or_else(|| refused("legal capture artifact descriptor"))?;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    set_close_on_exec(&descriptor)?;
    Ok(descriptor)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_close_on_exec(descriptor: &OwnedFd) -> Result<()> {
    // SAFETY: fcntl on a descriptor this process owns; F_SETFD takes an int.
    if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
