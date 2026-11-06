//! A canonical claim read's relationship and value backing with separate memory custody.

use super::{ClaimBody, ClaimLifecycleStatus};
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
    predicate_memory: Option<MemoryLease>,
    metadata_memory: Option<MemoryLease>,
}

impl ClaimBodyRead {
    pub(super) fn new(
        body: ClaimBody,
        memory: Option<MemoryLease>,
        value_memory: Option<MemoryLease>,
        predicate_memory: Option<MemoryLease>,
        metadata_memory: Option<MemoryLease>,
    ) -> Self {
        Self {
            body,
            _memory: memory,
            value_memory,
            predicate_memory,
            metadata_memory,
        }
    }

    /// Extracts a body only when all of its backing guards are absent.
    pub fn try_into_unbound_body(self) -> Result<ClaimBody, Self> {
        if self._memory.is_some()
            || self.value_memory.is_some()
            || self.predicate_memory.is_some()
            || self.metadata_memory.is_some()
        {
            return Err(self);
        }
        Ok(self.body)
    }

    /// Moves live-head metadata and the guarded value; unused relationships drop here.
    pub fn into_value_head(self) -> ClaimValueHead {
        ClaimValueHead::new(
            self.body.predicate,
            self.body.lifecycle,
            self.body.stale,
            self.body.value,
            self.value_memory,
            self.predicate_memory,
        )
    }
}

impl Deref for ClaimBodyRead {
    type Target = ClaimBody;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

/// Storage charges for the unchanged value and predicate of a selected birth.
/// This records allocated backing; it does not admit history allocations.
pub struct ClaimValueHeadStorage {
    value_memory: Option<MemoryLease>,
    predicate_memory: Option<MemoryLease>,
}

impl ClaimValueHeadStorage {
    pub fn retained(body: &ClaimBody, memory: Option<ClaimScopeReadMemory<'_>>) -> Self {
        let value_memory = memory.map(|memory| {
            let mut lease = memory.value_lease();
            lease.materialized(0, value_storage_bytes(&body.value));
            lease
        });
        let predicate_memory = memory.map(|memory| {
            let mut lease = memory.value_lease();
            lease.materialized(0, body.predicate.capacity() as u64);
            lease
        });
        Self {
            value_memory,
            predicate_memory,
        }
    }

    /// The body must still own the exact value and predicate backing recorded above.
    pub fn into_value_head(self, body: ClaimBody) -> ClaimValueHead {
        ClaimValueHead::new(
            body.predicate,
            body.lifecycle,
            body.stale,
            body.value,
            self.value_memory,
            self.predicate_memory,
        )
    }
}

/// Only the fields a value-head reader uses, after full canonical validation.
/// Its value cannot be extracted without its memory custody.
pub struct ClaimValueHead {
    predicate: String,
    lifecycle: ClaimLifecycleStatus,
    stale: bool,
    value: ClaimValueRead,
    _predicate_memory: Option<MemoryLease>,
}

impl ClaimValueHead {
    pub(super) fn new(
        predicate: String,
        lifecycle: ClaimLifecycleStatus,
        stale: bool,
        value: Value,
        memory: Option<MemoryLease>,
        predicate_memory: Option<MemoryLease>,
    ) -> Self {
        Self {
            predicate,
            lifecycle,
            stale,
            value: ClaimValueRead {
                value,
                _memory: memory,
            },
            _predicate_memory: predicate_memory,
        }
    }

    pub fn predicate(&self) -> &str {
        &self.predicate
    }

    pub fn lifecycle(&self) -> ClaimLifecycleStatus {
        self.lifecycle
    }

    pub fn stale(&self) -> bool {
        self.stale
    }

    pub fn into_value(self) -> ClaimValueRead {
        self.value
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
    /// Whether this value retains caller-bound memory custody, even at zero bytes.
    pub fn is_memory_bound(&self) -> bool {
        self._memory.is_some()
    }

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

impl ClaimValueRead {
    /// Moves a valid UTF-8 string and its existing memory custody without copying.
    /// Other values, including invalid UTF-8 strings, retain their original owner.
    pub fn try_into_string(self) -> Result<ClaimStringRead, Self> {
        let Self { value, _memory } = self;
        match value {
            Value::String(value) if value.is_str() => Ok(ClaimStringRead {
                value: value.into_str().expect("validated UTF-8 string"),
                _memory,
            }),
            value => Err(Self { value, _memory }),
        }
    }
}

/// An owned canonical string whose original charge follows its backing.
pub struct ClaimStringRead {
    value: String,
    _memory: Option<MemoryLease>,
}

impl ClaimStringRead {
    pub fn is_memory_bound(&self) -> bool {
        self._memory.is_some()
    }

    pub fn retained_bytes(&self) -> u64 {
        self._memory.as_ref().map_or(0, MemoryLease::bytes)
    }

    /// Restores the value representation without copying or releasing its charge.
    pub fn into_value(self) -> ClaimValueRead {
        ClaimValueRead {
            value: Value::from(self.value),
            _memory: self._memory,
        }
    }

    /// Only a genuinely unbound string may leave without memory custody.
    pub fn try_into_unbound_string(self) -> Result<String, Self> {
        if self._memory.is_some() {
            return Err(self);
        }
        Ok(self.value)
    }
}

impl Deref for ClaimStringRead {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

pub(super) fn metadata_storage_bytes(
    evidence: Option<&Value>,
    scope: Option<&Value>,
    session_tag: Option<&String>,
) -> u64 {
    evidence
        .map_or(0, value_storage_bytes)
        .saturating_add(scope.map_or(0, value_storage_bytes))
        .saturating_add(session_tag.map_or(0, |tag| tag.capacity() as u64))
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

impl ClaimScopeReadMemory<'_> {
    pub(super) fn decode_value(
        self,
        rd: &mut impl std::io::Read,
        lease: &mut MemoryLease,
    ) -> std::result::Result<Value, ClaimBodyReadError> {
        let mut allocation = ClaimValueAllocation { read: self, lease };
        rmpv::decode::value::read_value_with_allocation(rd, &mut allocation).map_err(|error| {
            match error {
                rmpv::decode::value::allocation::DecodeError::Decode(_) => {
                    ClaimBodyReadError::Body(Error::InvalidClaimBody(
                        "body is not valid MessagePack",
                    ))
                }
                rmpv::decode::value::allocation::DecodeError::Allocation(refusal) => {
                    ClaimBodyReadError::Refused(refusal)
                }
            }
        })
    }
}

struct ClaimValueAllocation<'read, 'lease> {
    read: ClaimScopeReadMemory<'read>,
    lease: &'lease mut MemoryLease,
}

impl rmpv::decode::value::allocation::Allocation for ClaimValueAllocation<'_, '_> {
    type Error = MemoryRefusal;

    fn reserve(&mut self, bytes: u64) -> std::result::Result<(), Self::Error> {
        if bytes != 0 {
            self.lease.check_irreducible_peak(self.read.pinned, bytes)?;
            self.lease.grow_untimed(bytes, self.read.stopped)?;
        }
        Ok(())
    }

    fn materialized(&mut self, reserved: u64, old: u64, actual: u64) {
        self.lease.materialized(reserved, actual);
        self.lease.shrink(old);
    }
}
