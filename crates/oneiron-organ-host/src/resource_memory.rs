//! `memory.grow` (FIX 7654), the host's own handler: an organ reserves the
//! memory its own buffers are about to take, before it allocates them.
//!
//! The handler leases the bytes from the machine's memory floor
//! ([`MachineFloor`]: in the server, its one machine memory line) within the
//! call's deadline, then holds them in the call's room as native memory. That
//! is a class of its own, apart from the bytes answers hold, so no answer's
//! arithmetic gives it back. Both stay until the call ends: its room drops at
//! its return, its revocation, a failed send or the organ's death. Nothing is
//! given back earlier; the protocol has no release.
//!
//! The answer is typed: granted, the machine's floor, or the deadline. The
//! handler refuses outright where it has no room to hold the bytes in (a mesh
//! call's asking node: the organ's own host answers this ask) and on a host
//! built with no floor. No count or size of the ask refuses it (Rule 5).

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use oneiron_organ_protocol::{AskCode, AskRefusal, MemoryAnswer, MemoryAsk};

use crate::budget::NativeRefusal;
use crate::handlers::{Answered, AskHandler, AskRequest};

/// The machine's memory, as the host leases it to organs' own buffers. The
/// server's implementation is its machine memory line, shared with every
/// other lease it gives.
pub trait MachineFloor: Send + Sync {
    /// A lease of `bytes` of the machine's memory, held until what it returns
    /// drops: admitted as soon as they fit, waiting no later than `deadline`
    /// and no longer than `stopped` allows.
    ///
    /// # Errors
    /// The machine's floor, when the bytes cannot fit even with nothing else
    /// leased; [`FloorRefusal::Deadline`] when they did not fit before the
    /// deadline, or `stopped` said so first.
    fn lease(
        &self,
        bytes: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Box<dyn Send>, FloorRefusal>;
}

/// Why a [`MachineFloor`] leased nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorRefusal {
    /// `needed` bytes do not fit even with nothing else leased: past the
    /// memory the machine keeps free, it has `available` at most.
    Floor { needed: u64, available: u64 },
    /// The bytes did not fit before the deadline, or the wait was stopped.
    Deadline,
}

/// The floor a host's calls lease native memory from, shared by them all.
#[derive(Clone)]
pub(crate) struct SharedFloor(pub(crate) Arc<dyn MachineFloor>);

impl fmt::Debug for SharedFloor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedFloor")
    }
}

/// The `memory.grow` handler. It holds nothing: what it leases is the
/// call's room's, until the call ends.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryGrow;

impl AskHandler for MemoryGrow {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let Some(room) = ask.room else {
            return Err(AskRefusal::new(
                AskCode::NotGranted,
                "memory is reserved where the organ runs; this node holds no room for the call",
            ));
        };
        let MemoryAsk { bytes } = decode(ask.value)?;
        let answer = match room.grow_native(bytes, ask.deadline, ask.revoked.0) {
            Ok(()) => MemoryAnswer::Granted,
            Err(NativeRefusal::NoFloor) => {
                return Err(AskRefusal::new(
                    AskCode::NotGranted,
                    "this host has no machine memory floor to reserve from",
                ));
            }
            Err(NativeRefusal::Floor { needed, available }) => {
                MemoryAnswer::Floor { needed, available }
            }
            // A revocation ended the wait: the call is ending, as a fetch's
            // revoked wait ends.
            Err(NativeRefusal::Deadline) if (ask.revoked.0)() => {
                return Err(AskRefusal::new(
                    AskCode::Cancelled,
                    "the call's grant was revoked",
                ));
            }
            Err(NativeRefusal::Deadline) => MemoryAnswer::Deadline,
        };
        Ok(Answered {
            value: encode(&answer)?,
            data: None,
            fetch: None,
        })
    }
}

/// A `memory.grow` ask's value, as the wire names its fields.
fn decode(value: &rmpv::Value) -> Result<MemoryAsk, AskRefusal> {
    let bad = |err: &dyn fmt::Display| {
        AskRefusal::new(AskCode::BadRequest, format!("not a memory ask: {err}"))
    };
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|err| bad(&err))?;
    rmp_serde::from_slice(&bytes).map_err(|err| bad(&err))
}

/// The answer as a wire value, with named fields.
fn encode(answer: &MemoryAnswer) -> Result<rmpv::Value, AskRefusal> {
    let failed =
        |err: &dyn fmt::Display| AskRefusal::new(AskCode::Failed, format!("answer: {err}"));
    let bytes = rmp_serde::to_vec_named(answer).map_err(|err| failed(&err))?;
    rmpv::decode::read_value(&mut bytes.as_slice()).map_err(|err| failed(&err))
}
