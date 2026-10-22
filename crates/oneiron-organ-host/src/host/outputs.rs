//! A call's reply, checked: its outputs mapped, hashed and kept in the
//! call's room, which grows to hold them (FIX 5284), and its receipt
//! written. No output is refused for its size or the call's booking (Rule
//! 5): what the outputs hold, their names, and the organ's notes are
//! `[limits]` rows, which ask whether everything is okay.

use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;
use oneiron_organ_protocol::{Hash32, MAX_FDS_PER_FRAME, MappedRegion, Output, Payload, Proposal};

use super::Resolved;
use crate::budget::{CallRoom, Grown, Lease};
use crate::clock::Clock;
use crate::error::HostError;
use crate::measure::install_row;
use crate::outcome::{OrganOutcome, OrganOutput, OutputBytes};
use crate::process::OrganProcess;
use crate::receipt::{
    AskReceipt, CallReceipt, ReceiptInput, ReceiptOutput, digest, measured_notes,
};
use crate::spec::{OrganCall, OrganSpec};

/// A reply as it came back, with what `finish` needs to check it.
pub(super) struct Replied {
    pub(super) proposal: Proposal,
    pub(super) fds: Vec<OwnedFd>,
    /// The budget room the reply's frame holds until the reply is done.
    pub(super) frame: Lease,
    pub(super) queued: Duration,
    pub(super) sent_at: Instant,
    /// The call's deadline as its waits for room had moved it when the
    /// reply came (FIX 8020).
    pub(super) deadline: Instant,
    pub(super) asks: Vec<AskReceipt>,
    /// The host's budget: what the soft-target exception passes.
    pub(super) budget: u64,
}

/// What `finish` needs of the call beside its reply.
pub(super) struct Called<'a> {
    pub(super) vault: &'a Vault,
    pub(super) call: &'a OrganCall,
    pub(super) spec: &'a OrganSpec,
    pub(super) process: &'a OrganProcess,
    pub(super) inputs: &'a [Resolved],
    pub(super) room: &'a CallRoom,
    /// Whether the call's grant is revoked: what ends a wait for room.
    pub(super) revoked: &'a dyn Fn() -> bool,
}

/// Checks a proposal, hashes its outputs and writes the receipt.
pub(super) fn finish(called: &Called<'_>, reply: Replied) -> Result<OrganOutcome, HostError> {
    let Called {
        vault,
        call,
        process,
        inputs,
        room,
        ..
    } = *called;
    let Replied {
        proposal,
        fds,
        frame,
        queued,
        sent_at,
        deadline,
        asks,
        budget,
    } = reply;
    if let (Some(base), Some(next)) = (&call.body, &proposal.body)
        && base.kind != next.kind
    {
        return Err(HostError::ReplyInvalid(format!(
            "a {} body came back as {}",
            base.kind, next.kind
        )));
    }
    let outputs = take_outputs(called, proposal.outputs, fds, deadline)?;
    // The reply's frame and the call's own growth, as the receipt names
    // them: past the budget only when every live call waited to grow.
    let grown = grown_total(&[room.grown(), frame.grown()]);
    if grown.overcommit > 0 {
        vault.measure_limit_at(EngineLimit::OrganMemoryBytes, budget, grown.peak);
    }
    drop(frame);
    let receipt = CallReceipt {
        organ: process.hello.organ.clone(),
        protocol: process.session,
        verb: call.verb.clone(),
        schema: call.schema,
        args_digest: digest(&call.args),
        inputs: inputs
            .iter()
            .map(|resolved| ReceiptInput {
                artifact: resolved
                    .input
                    .map(|input| input.artifact.to_hex())
                    .unwrap_or_default(),
                version: resolved.input.map_or(0, |input| input.version),
                content_hash: resolved.hash,
                len: resolved.len,
                lent: resolved.input.is_none(),
            })
            .collect(),
        base_body: call.body.as_ref().map(digest),
        result_body: proposal.body.as_ref().map(digest),
        outputs: outputs
            .iter()
            .map(|output| ReceiptOutput {
                name: output.name.clone(),
                media_type: output.media_type.clone(),
                content_hash: output.content_hash,
                len: output.len() as u64,
            })
            .collect(),
        notes: measured_notes(vault, proposal.notes),
        class: call.class,
        grant: call.grant.clone(),
        queue_us: u64::try_from(queued.as_micros()).unwrap_or(u64::MAX),
        run_us: u64::try_from(sent_at.elapsed().as_micros()).unwrap_or(u64::MAX),
        asks,
        overcommit_bytes: grown.overcommit,
        room_wait_us: u64::try_from(grown.waited.as_micros()).unwrap_or(u64::MAX),
    };
    Ok(OrganOutcome {
        body: proposal.body,
        outputs,
        report: proposal.report,
        receipt,
    })
}

/// Hashes in pieces, so a large output cannot run the call past its
/// deadline: the one its reply came back with, which already counts every
/// earlier wait for room, moved on by each wait since, once (FIX 8020).
fn hash_until(bytes: &[u8], clock: Clock<'_>) -> Result<Hash32, HostError> {
    const PIECE: usize = 32 * 1024 * 1024;
    let mut hasher = blake3::Hasher::new();
    for piece in bytes.chunks(PIECE) {
        if clock.passed() {
            return Err(HostError::DeadlineExceeded);
        }
        hasher.update(piece);
    }
    Ok(Hash32(*hasher.finalize().as_bytes()))
}

/// Maps and hashes the outputs. Region outputs must be sealed; each
/// output's size is read before it is mapped, and the call's room grows to
/// hold it first, so its bytes keep that much of the budget until they
/// drop and outputs a caller holds on to stay counted. Past the install
/// grant's output bytes the row asks; nothing is refused for its size.
fn take_outputs(
    called: &Called<'_>,
    outputs: Vec<Output>,
    fds: Vec<OwnedFd>,
    deadline: Instant,
) -> Result<Vec<OrganOutput>, HostError> {
    if outputs.len() > MAX_FDS_PER_FRAME {
        return Err(HostError::ReplyInvalid("more than 16 outputs".into()));
    }
    let Called {
        vault, spec, room, ..
    } = *called;
    // From the reply's own moved deadline: only the waits from here on.
    let clock = Clock::new(deadline, room.waits());
    let mut slots: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
    let mut total = 0u64;
    let taken = outputs
        .into_iter()
        .map(|output| {
            let (bytes, len) = output_bytes(called, output.data, &mut slots)?;
            total = total.saturating_add(len);
            let content_hash = match &bytes {
                OutputBytes::Inline(inline) => hash_until(inline, clock)?,
                OutputBytes::Mapped(region) => hash_until(region, clock)?,
            };
            vault.measure_limit(EngineLimit::OrganOutputNameBytes, output.name.len() as u64);
            vault.measure_limit(
                EngineLimit::OrganMediaTypeBytes,
                output.media_type.len() as u64,
            );
            Ok(OrganOutput {
                name: output.name,
                media_type: output.media_type,
                content_hash,
                bytes,
                _kept: Some(room.keep(len)),
            })
        })
        .collect::<Result<Vec<_>, HostError>>()?;
    install_row(
        vault,
        EngineLimit::OrganOutputBytes,
        spec.max_output_bytes,
        total,
    );
    Ok(taken)
}

/// One output's bytes, with room held for them in the call's room before
/// they are kept: an inline output's as it came, a region's by its sealed
/// size before it is mapped.
fn output_bytes(
    called: &Called<'_>,
    data: Payload,
    slots: &mut [Option<OwnedFd>],
) -> Result<(OutputBytes, u64), HostError> {
    let hold = |len: u64| {
        if called.room.hold(len, called.revoked) {
            Ok(())
        } else {
            Err(HostError::Revoked)
        }
    };
    match data {
        Payload::Inline(bytes) => {
            let len = bytes.len() as u64;
            hold(len)?;
            Ok((OutputBytes::Inline(bytes.into_vec()), len))
        }
        Payload::Slot(slot) => {
            let fd = slots
                .get_mut(usize::from(slot))
                .and_then(Option::take)
                .ok_or_else(|| HostError::ReplyInvalid("output slot".into()))?;
            let invalid =
                |err: std::io::Error| HostError::ReplyInvalid(format!("output region: {err}"));
            let len = MappedRegion::sealed_len(&fd).map_err(invalid)?;
            hold(len)?;
            let region = MappedRegion::map_sealed(fd, len).map_err(invalid)?;
            Ok((OutputBytes::Mapped(region), len))
        }
    }
}

/// What a frame's room and a call's growth took together.
fn grown_total(grown: &[Grown]) -> Grown {
    Grown {
        overcommit: grown.iter().map(|grown| grown.overcommit).sum(),
        peak: grown.iter().map(|grown| grown.peak).max().unwrap_or(0),
        waited: grown.iter().map(|grown| grown.waited).sum(),
    }
}
