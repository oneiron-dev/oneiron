//! Custody of context disclosure buffers and serialized HTTP bytes.

use crate::machine::{MachineMemory, MemoryLease};
use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::fmt;
use std::io::{self, Write};

/// Already-materialized storage owned by a pack's disclosure fields.
pub(super) struct RetainedDisclosureOutput(MemoryLease);

impl RetainedDisclosureOutput {
    pub(super) fn new(memory: &MachineMemory) -> Self {
        Self(memory.empty_lease())
    }

    pub(super) fn retain(
        &mut self,
        stamps: Option<&Vec<oneiron::InterlocutorStamp>>,
        assembly: Option<&oneiron::DisclosureAssembly>,
    ) {
        let bytes = stamps
            .map_or(0, stamp_storage_bytes)
            .saturating_add(assembly.map_or(0, |assembly| {
                (assembly.emit_stamp.capacity() as u64)
                    .saturating_add(assembly.mode.capacity() as u64)
                    .saturating_add(
                        assembly
                            .notice
                            .as_ref()
                            .map_or(0, |notice| notice.capacity() as u64),
                    )
                    .saturating_add(stamp_storage_bytes(&assembly.interlocutors))
            }));
        let held = self.0.bytes();
        if bytes > held {
            self.0.materialized(0, bytes - held);
        } else {
            self.0.shrink(held - bytes);
        }
    }
}

impl fmt::Debug for RetainedDisclosureOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RetainedDisclosureOutput")
            .field(&self.0.bytes())
            .finish()
    }
}

fn stamp_storage_bytes(stamps: &Vec<oneiron::InterlocutorStamp>) -> u64 {
    let slots = (stamps.capacity() as u64)
        .saturating_mul(std::mem::size_of::<oneiron::InterlocutorStamp>() as u64);
    stamps.iter().fold(slots, |bytes, stamp| {
        bytes.saturating_add(stamp.speaker.capacity() as u64)
    })
}

/// The encoded buffer drops before its capacity charge. Transport clones share
/// this same owner; they do not copy a lease onto different bytes.
pub(crate) struct ContextJsonBytes {
    bytes: Vec<u8>,
    storage: MemoryLease,
}

impl ContextJsonBytes {
    pub(crate) fn serialize(
        value: &impl Serialize,
        memory: &MachineMemory,
    ) -> serde_json::Result<Self> {
        let mut output = Self::from_vec(Vec::new(), memory);
        serde_json::to_writer(&mut output, value)?;
        Ok(output)
    }

    fn from_vec(bytes: Vec<u8>, memory: &MachineMemory) -> Self {
        let mut storage = memory.empty_lease();
        storage.materialized(0, bytes.capacity() as u64);
        Self { bytes, storage }
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("serialized JSON is UTF-8")
    }
}

impl AsRef<[u8]> for ContextJsonBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for ContextJsonBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        let growth = (self.bytes.capacity() as u64).saturating_sub(self.storage.bytes());
        self.storage.materialized(0, growth);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Matches axum Json's wire and serialization-error responses, but the body
/// owns the exact encoded backing together with its capacity charge.
pub(crate) fn context_json_response(value: &impl Serialize, memory: &MachineMemory) -> Response {
    match ContextJsonBytes::serialize(value, memory) {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "application/json")],
            Bytes::from_owner(bytes),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            Bytes::from_owner(ContextJsonBytes::from_vec(
                error.to_string().into_bytes(),
                memory,
            )),
        )
            .into_response(),
    }
}
