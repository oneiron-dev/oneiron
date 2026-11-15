//! Door for `tests/scratchpad_wake.rs` (OF-548): an agent's own memory
//! facade with its writes bound to a durable code run, as a run's
//! dispatcher binds them (`code_run/dispatcher/agent_verb.rs`), so a test
//! writes the pad a run writes; and a race point in a first line's append,
//! between its pointer read and its pad's birth, so a test commits a racing
//! first line in that gap.

use std::cell::{Cell, RefCell};

use crate::error::Result;
use crate::memory::{HostWriteOrigin, Memory, MemoryResult};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

thread_local! {
    /// The line the armed race appends.
    static RACE_LINE: RefCell<Option<String>> = const { RefCell::new(None) };
    /// The pad the armed race's line landed in, once it ran.
    static RACED_PAD: Cell<Option<EntityId>> = const { Cell::new(None) };
}

/// Agent `agent`'s own memory facade, its writes bound to durable code run
/// `run` through a host write origin.
///
/// # Errors
///
/// A provenance the envelope refuses.
pub fn run_bound_memory(vault: &Vault, agent: EntityId, run: EntityId) -> Result<Memory<'_>> {
    let envelope = WriteEnvelope::new(
        WriteActor::new(agent, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::Map(Vec::new()))?,
        ClaimApprovalStatus::Proposed,
    );
    Ok(vault
        .memory(agent, EdgeActorClass::Agent)
        .with_host_origin(HostWriteOrigin::new(envelope).with_bound_run(Some(run))))
}

/// Arms this thread's next scratchpad append that reads no pad: after that
/// read and before its pad's birth, the same caller appends `line` on the
/// same session, as a racing first line that commits in that gap does.
/// [`raced_pad`] then answers the pad `line` landed in.
pub fn race_next_pad_birth(line: &str) {
    RACE_LINE.with(|race| *race.borrow_mut() = Some(line.to_owned()));
    RACED_PAD.with(|pad| pad.set(None));
}

/// The pad the line [`race_next_pad_birth`] armed landed in, once it ran.
#[must_use]
pub fn raced_pad() -> Option<EntityId> {
    RACED_PAD.with(Cell::get)
}

/// The race point; a no-op unless [`race_next_pad_birth`] armed this thread.
pub(crate) fn at_pad_birth(memory: &Memory<'_>, session: &str) -> MemoryResult<()> {
    let Some(line) = RACE_LINE.with(|race| race.borrow_mut().take()) else {
        return Ok(());
    };
    let receipt = memory.scratchpad_append(session, &line, None, false)?;
    RACED_PAD.with(|pad| pad.set(Some(receipt.pad)));
    Ok(())
}
