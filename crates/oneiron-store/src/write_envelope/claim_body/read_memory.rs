//! A canonical claim read's relationship backing and its memory custody.

use super::ClaimBody;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::Error;
use oneiron_contracts::host_memory::{MachineMemory, MemoryLease, MemoryRefusal};
use rmpv::Value;
use std::mem::size_of;
use std::ops::Deref;

/// Native validation/store failures remain distinct from memory admission.
#[derive(Debug)]
pub enum ClaimBodyReadError {
    Body(Error),
    Refused(MemoryRefusal),
}

impl From<Error> for ClaimBodyReadError {
    fn from(error: Error) -> Self {
        Self::Body(error)
    }
}

impl ClaimBodyReadError {
    pub fn into_unbound_error(self) -> Error {
        match self {
            Self::Body(error) => error,
            Self::Refused(_) => unreachable!("an unbound claim read never admits memory"),
        }
    }
}

/// The caller's original memory line and cancellation signal; never global.
#[derive(Clone, Copy)]
pub struct ClaimScopeReadMemory<'a> {
    memory: &'a MachineMemory,
    stopped: &'a dyn Fn() -> bool,
}

impl<'a> ClaimScopeReadMemory<'a> {
    pub fn new(memory: &'a MachineMemory, stopped: &'a dyn Fn() -> bool) -> Self {
        Self { memory, stopped }
    }

    pub(super) fn admit(self, count: usize) -> Result<MemoryLease, MemoryRefusal> {
        let mut lease = self.memory.empty_lease();
        let bytes = relationship_bytes(count);
        if bytes != 0 {
            lease.grow_untimed(bytes, self.stopped)?;
        }
        Ok(lease)
    }
}

/// Payload fields drop before the guard that accounts for their backing.
pub struct ClaimBodyRead {
    body: ClaimBody,
    _memory: Option<MemoryLease>,
}

impl ClaimBodyRead {
    pub(super) fn new(body: ClaimBody, memory: Option<MemoryLease>) -> Self {
        Self {
            body,
            _memory: memory,
        }
    }

    /// Records a final projected body's backing after native history selection.
    /// History decoding, folding and projection allocations are not admitted here.
    pub fn retained(body: ClaimBody, memory: Option<ClaimScopeReadMemory<'_>>) -> Self {
        let memory = memory.map(|memory| {
            let mut lease = memory.memory.empty_lease();
            let bytes = body
                .rel
                .as_ref()
                .map_or(0, |ids| relationship_bytes(ids.capacity()));
            lease.materialized(0, bytes);
            lease
        });
        Self::new(body, memory)
    }

    /// Extracts a body only when no relationship backing is leased.
    pub fn try_into_unbound_body(self) -> Result<ClaimBody, Self> {
        if self._memory.is_some() {
            return Err(self);
        }
        Ok(self.body)
    }

    pub fn into_value(self) -> Value {
        self.body.value
    }
}

impl Deref for ClaimBodyRead {
    type Target = ClaimBody;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

pub(super) fn relationship_bytes(count: usize) -> u64 {
    (count as u64).saturating_mul(size_of::<EntityId>() as u64)
}
