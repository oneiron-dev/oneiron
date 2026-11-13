//! Door for `tests/scratchpad_wake.rs` (OF-548): an agent's own memory
//! facade with its writes bound to a durable code run, as a run's
//! dispatcher binds them (`code_run/dispatcher/agent_verb.rs`), so a test
//! writes the pad a run writes.

use crate::error::Result;
use crate::memory::{HostWriteOrigin, Memory};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

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
