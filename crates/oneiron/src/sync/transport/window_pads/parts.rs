//! A window pad envelope put back together on its socket (KS-5, FIX 7107):
//! the first frame, then its `WINDOW_PAD_PART` frames in order, each at its
//! offset past the header, a payload past one frame included (FIX 8247). The bytes
//! are held in memory for that delivery alone. A part that names no envelope
//! here, or breaks one, ends the delivery as a lost frame would; a first
//! frame for a window whose earlier envelope is still incomplete takes its
//! place. Nothing waits on a part, and no part is asked for again.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;
use std::time::Instant;

use oneiron_contracts::host_memory::{MachineMemory, MemoryLease};

use super::{
    Header, PART_LEAD, WINDOW_PAD_HEADER_BYTES, WindowPadEnvelope, WindowPadKind,
    decode_window_pad_envelope, invalid, window_pad_part_id,
};
use crate::sync::transport::{TransportError, window_sub_tags};

/// The envelopes still coming in on one socket, by window.
#[derive(Default)]
pub struct WindowPadAssembly {
    pending: HashMap<String, Pending>,
}

/// One envelope whose parts still come.
struct Pending {
    sub_tag: u8,
    id: [u8; 32],
    bytes: Vec<u8>,
    total: usize,
    memory: MemoryLease,
}

/// What one window frame was.
pub enum WindowPadArrival {
    /// A frame that carries no envelope: a notice, as it was.
    Notice,
    /// An envelope's first frame or part, its parts still to come.
    Streaming,
    /// A part this socket holds no envelope for, or that breaks the one it
    /// names: that delivery is incomplete.
    Broken,
    /// A whole envelope, with the sub-tag its first frame came under.
    Envelope(u8, ReceivedWindowPadEnvelope),
}

/// A decoded delivery whose owned buffers keep their physical-memory admission.
pub struct ReceivedWindowPadEnvelope {
    envelope: WindowPadEnvelope,
    memory: MemoryLease,
}

impl Deref for ReceivedWindowPadEnvelope {
    type Target = WindowPadEnvelope;

    fn deref(&self) -> &Self::Target {
        &self.envelope
    }
}

impl ReceivedWindowPadEnvelope {
    /// Keeps the payload's admission after its references and capsule are used.
    pub(crate) fn into_payload(self) -> WindowPadPayload<'static> {
        let mut memory = self.memory;
        let WindowPadEnvelope {
            payload,
            refs,
            sidecar,
            ..
        } = self.envelope;
        drop(refs);
        drop(sidecar);
        memory.shrink(memory.bytes().saturating_sub(payload.capacity() as u64));
        WindowPadPayload {
            bytes: Cow::Owned(payload),
            memory: Some(memory),
        }
    }
}

/// A notice borrowed from its frame, or an admitted delivery kept through import.
pub struct WindowPadPayload<'a> {
    bytes: Cow<'a, [u8]>,
    memory: Option<MemoryLease>,
}

impl<'a> WindowPadPayload<'a> {
    pub(crate) fn borrowed(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
            memory: None,
        }
    }

    /// Keeps the delivery's lease through its existing native projection.
    /// Projection's internal allocations remain the projection's responsibility.
    pub(crate) fn try_map_owned(
        self,
        project: impl FnOnce(Vec<u8>) -> Result<Option<Vec<u8>>, TransportError>,
    ) -> Result<Option<Self>, TransportError> {
        let mut memory = self.memory;
        let Some(bytes) = project(self.bytes.into_owned())? else {
            return Ok(None);
        };
        if let Some(memory) = &mut memory {
            let actual = bytes.capacity() as u64;
            if actual > memory.bytes() {
                memory.materialized(0, actual - memory.bytes());
            } else {
                memory.shrink(memory.bytes() - actual);
            }
        }
        Ok(Some(Self {
            bytes: Cow::Owned(bytes),
            memory,
        }))
    }
}

impl Deref for WindowPadPayload<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

fn reserve(bytes: usize) -> Result<MemoryLease, TransportError> {
    MachineMemory::process()
        .lease(bytes as u64, Instant::now())
        .map_err(|error| TransportError::Storage(format!("window pad memory: {error:?}")))
}

fn decoded_capacity(envelope: &WindowPadEnvelope) -> u64 {
    envelope.payload.capacity() as u64
        + (envelope.refs.capacity() * size_of::<[u8; 40]>()) as u64
        + envelope
            .sidecar
            .as_ref()
            .map_or(0, |sidecar| sidecar.capsule.capacity() as u64)
}

impl WindowPadAssembly {
    /// Takes one window frame of `window_key` under `sub_tag`.
    ///
    /// # Errors
    ///
    /// A frame of an envelope's sub-tag that is no envelope of that kind.
    pub fn accept(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<WindowPadArrival, TransportError> {
        let arrival = if sub_tag == window_sub_tags::WINDOW_PAD_PART {
            self.part(window_key, payload)
        } else {
            self.first(window_key, sub_tag, payload)
        };
        if arrival.is_err() {
            self.pending.remove(window_key);
        }
        arrival
    }

    fn first(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<WindowPadArrival, TransportError> {
        let Some(kind) = WindowPadKind::of_sub_tag(sub_tag) else {
            return Ok(WindowPadArrival::Notice);
        };
        let header = Header::read(payload)?;
        let total = header
            .total()
            .ok_or_else(|| invalid("window pad envelope length"))?;
        if header.kind != kind {
            return Err(invalid("window pad envelope of another kind"));
        }
        // The first frame may end inside the payload: the rest of it comes in
        // parts (FIX 8247).
        if payload.len() > total {
            return Err(invalid("window pad envelope length"));
        }
        self.pending.remove(window_key);
        if payload.len() == total {
            let mut memory = reserve(total)?;
            let envelope = decode_window_pad_envelope(payload)?;
            memory.materialized(total as u64, decoded_capacity(&envelope));
            return Ok(WindowPadArrival::Envelope(
                sub_tag,
                ReceivedWindowPadEnvelope { envelope, memory },
            ));
        }
        // The joined wire bytes and the decoded fields coexist at completion.
        let peak = total
            .checked_add(total)
            .ok_or_else(|| invalid("window pad allocation length"))?;
        let mut memory = reserve(peak)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total)
            .map_err(|error| TransportError::Storage(format!("window pad allocation: {error}")))?;
        memory.materialized(total as u64, bytes.capacity() as u64);
        bytes.extend_from_slice(payload);
        self.pending.insert(
            window_key.to_owned(),
            Pending {
                sub_tag,
                id: *blake3::hash(&payload[..WINDOW_PAD_HEADER_BYTES]).as_bytes(),
                bytes,
                total,
                memory,
            },
        );
        Ok(WindowPadArrival::Streaming)
    }

    fn part(
        &mut self,
        window_key: &str,
        payload: &[u8],
    ) -> Result<WindowPadArrival, TransportError> {
        let id = window_pad_part_id(payload).ok_or_else(|| invalid("short window pad part"))?;
        let mut offset = [0u8; 8];
        offset.copy_from_slice(&payload[32..PART_LEAD]);
        let offset = u64::from_be_bytes(offset);
        let bytes = &payload[PART_LEAD..];
        let Some(pending) = self.pending.get_mut(window_key) else {
            return Ok(WindowPadArrival::Broken);
        };
        if pending.id != id
            || offset != (pending.bytes.len() - WINDOW_PAD_HEADER_BYTES) as u64
            || pending.bytes.len() + bytes.len() > pending.total
        {
            self.pending.remove(window_key);
            return Ok(WindowPadArrival::Broken);
        }
        pending.bytes.extend_from_slice(bytes);
        if pending.bytes.len() < pending.total {
            return Ok(WindowPadArrival::Streaming);
        }
        let Some(done) = self.pending.remove(window_key) else {
            return Ok(WindowPadArrival::Broken);
        };
        let mut memory = done.memory;
        let bytes = done.bytes;
        let envelope = decode_window_pad_envelope(&bytes)?;
        memory.materialized(done.total as u64, decoded_capacity(&envelope));
        let joined_capacity = bytes.capacity() as u64;
        drop(bytes);
        memory.shrink(joined_capacity);
        Ok(WindowPadArrival::Envelope(
            done.sub_tag,
            ReceivedWindowPadEnvelope { envelope, memory },
        ))
    }

    /// Drops every envelope still coming in: the socket is gone.
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}
