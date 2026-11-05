//! A canonical claim read's relationship and value backing with separate memory custody.

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
    pinned: u64,
}

impl<'a> ClaimScopeReadMemory<'a> {
    /// `pinned` is distinct caller-held input that cannot drop during this read.
    pub fn new(memory: &'a MachineMemory, stopped: &'a dyn Fn() -> bool, pinned: u64) -> Self {
        Self {
            memory,
            stopped,
            pinned,
        }
    }

    /// Adds distinct retained inputs that remain live through this read.
    pub fn with_additional_pinned(self, bytes: u64) -> Self {
        Self {
            pinned: self.pinned.saturating_add(bytes),
            ..self
        }
    }

    pub(super) fn value_lease(self) -> MemoryLease {
        self.memory.empty_lease()
    }

    pub(super) fn admit(self, count: usize) -> Result<MemoryLease, MemoryRefusal> {
        let mut lease = self.memory.empty_lease();
        let bytes = relationship_bytes(count);
        if bytes != 0 {
            lease.check_irreducible_peak(self.pinned, bytes)?;
            lease.grow_untimed(bytes, self.stopped)?;
        }
        Ok(lease)
    }
}

/// Payload fields drop before the guard that accounts for their backing.
pub struct ClaimBodyRead {
    body: ClaimBody,
    _memory: Option<MemoryLease>,
    value_memory: Option<MemoryLease>,
}

impl ClaimBodyRead {
    pub(super) fn new(
        body: ClaimBody,
        memory: Option<MemoryLease>,
        value_memory: Option<MemoryLease>,
    ) -> Self {
        Self {
            body,
            _memory: memory,
            value_memory,
        }
    }

    /// Records a final projected body's backing after native history selection.
    /// History decoding, folding and projection allocations are not admitted here.
    pub fn retained(body: ClaimBody, memory: Option<ClaimScopeReadMemory<'_>>) -> Self {
        let value_memory = memory.map(|memory| {
            let mut lease = memory.value_lease();
            lease.materialized(0, value_storage_bytes(&body.value));
            lease
        });
        let memory = memory.map(|memory| {
            let mut lease = memory.memory.empty_lease();
            let bytes = body
                .rel
                .as_ref()
                .map_or(0, |ids| relationship_bytes(ids.capacity()));
            lease.materialized(0, bytes);
            lease
        });
        Self::new(body, memory, value_memory)
    }

    /// Extracts a body only when neither relationship nor value backing is leased.
    pub fn try_into_unbound_body(self) -> Result<ClaimBody, Self> {
        if self._memory.is_some() || self.value_memory.is_some() {
            return Err(self);
        }
        Ok(self.body)
    }

    /// Moves only the value and its guard; unused relationships drop here.
    pub fn into_value(self) -> ClaimValueRead {
        ClaimValueRead {
            value: self.body.value,
            _memory: self.value_memory,
        }
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

/// A canonical value whose charge follows its last borrowed consumer.
/// No paid value can be extracted without the guard.
pub struct ClaimValueRead {
    value: Value,
    _memory: Option<MemoryLease>,
}

impl ClaimValueRead {
    /// The bytes charged to this field, or zero for a genuinely unbound read.
    pub fn retained_bytes(&self) -> u64 {
        self._memory.as_ref().map_or(0, MemoryLease::bytes)
    }
}

impl Deref for ClaimValueRead {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

pub(super) fn value_storage_bytes(value: &Value) -> u64 {
    match value {
        Value::Nil | Value::Boolean(_) | Value::Integer(_) | Value::F32(_) | Value::F64(_) => 0,
        Value::String(value) => value.capacity() as u64,
        Value::Binary(bytes) | Value::Ext(_, bytes) => bytes.capacity() as u64,
        Value::Array(values) => values.iter().fold(
            (values.capacity() as u64).saturating_mul(size_of::<Value>() as u64),
            |bytes, value| bytes.saturating_add(value_storage_bytes(value)),
        ),
        Value::Map(entries) => entries.iter().fold(
            (entries.capacity() as u64).saturating_mul(size_of::<(Value, Value)>() as u64),
            |bytes, (key, value)| {
                bytes
                    .saturating_add(value_storage_bytes(key))
                    .saturating_add(value_storage_bytes(value))
            },
        ),
    }
}
