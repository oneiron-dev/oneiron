//! Shared memory ownership for original and isolated federation payload bytes.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

use oneiron_contracts::host_memory::{MachineMemory, MemoryLease, MemoryRefusal};
use serde::{Deserialize, Serialize};

/// Immutable payload bytes. Clones share both the buffer and its admission.
#[derive(Clone, schemars::JsonSchema)]
#[schemars(transparent)]
pub struct FederationPayloadBytes {
    #[schemars(with = "Vec<u8>")]
    bytes: Arc<Vec<u8>>,
    // Every clone drops its byte reference before its reservation reference.
    #[schemars(skip)]
    _memory: Option<Arc<MemoryLease>>,
}

impl FederationPayloadBytes {
    pub(super) fn copy_from_slice(source: &[u8]) -> crate::Result<Self> {
        let size = source.len() as u64;
        let mut memory = reserve_memory(size)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.len()).map_err(|error| {
            crate::Error::Io(std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))
        })?;
        memory.materialized(size, bytes.capacity() as u64);
        bytes.extend_from_slice(source);
        Ok(Self {
            bytes: Arc::new(bytes),
            _memory: Some(Arc::new(memory)),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(super) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub(super) fn attach_memory(&mut self, memory: MemoryLease) {
        self._memory = Some(Arc::new(memory));
    }
}

pub(super) fn reserve_memory(size: u64) -> crate::Result<MemoryLease> {
    MachineMemory::process()
        .lease(size, Instant::now())
        .map_err(|refusal| {
            let kind = match refusal {
                MemoryRefusal::Floor { .. } => std::io::ErrorKind::OutOfMemory,
                MemoryRefusal::WaitedOut { .. } => std::io::ErrorKind::WouldBlock,
            };
            crate::Error::Io(std::io::Error::new(
                kind,
                format!("federation payload memory: {refusal:?}"),
            ))
        })
}

impl Serialize for FederationPayloadBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bytes.serialize(serializer)
    }
}

// A wire receiver admits these bytes before native use. The review decoder
// reserves each payload before this decode and attaches its lease before return.
impl<'de> Deserialize<'de> for FederationPayloadBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PayloadVisitor;

        impl<'de> serde::de::Visitor<'de> for PayloadVisitor {
            type Value = FederationPayloadBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a federation payload byte array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // MessagePack supplies the exact array length, already checked
                // and reserved by the native review decoder's projection.
                let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(FederationPayloadBytes {
                    bytes: Arc::new(bytes),
                    _memory: None,
                })
            }
        }

        deserializer.deserialize_seq(PayloadVisitor)
    }
}

impl Deref for FederationPayloadBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for FederationPayloadBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for FederationPayloadBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl fmt::Debug for FederationPayloadBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(formatter)
    }
}
