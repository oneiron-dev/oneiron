//! A window pad envelope put back together on its socket (KS-5, FIX 7107):
//! the first frame, then its `WINDOW_PAD_PART` frames in order, each at its
//! offset past the header, a payload past one frame included (FIX 8247). The bytes
//! are held in memory for that delivery alone. A part that names no envelope
//! here, or breaks the required prefix, ends the delivery as a lost frame
//! would. Canonical bytes leave once their required pads are whole; a late
//! optional copy tail never delivers them twice or asks for them again. A
//! new first frame for the window replaces its previous unfinished envelope.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;
use std::time::Instant;

use oneiron_contracts::host_memory::{MachineMemory, MemoryLease};

use super::{
    Header, PART_LEAD, WINDOW_PAD_HEADER_BYTES, WindowPadEnvelope, WindowPadKind,
    decode_required_window_pads, decode_window_pad_envelope, invalid, window_pad_part_id,
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
    required: usize,
    total: usize,
    received: usize,
    delivered: bool,
    // None discards only this delivery's optional tail after a memory miss.
    memory: Option<MemoryLease>,
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
    /// The canonical payload and all required pads, delivered exactly once.
    Envelope(u8, ReceivedWindowPadEnvelope),
    /// Optional copies completed after canonical delivery. Never import its
    /// payload again, install pads again, or answer it with a canonical receipt.
    Copies(ReceivedWindowPadEnvelope),
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
            home_claim_copies,
            ..
        } = self.envelope;
        drop(refs);
        drop(sidecar);
        drop(home_claim_copies);
        memory.shrink(memory.bytes().saturating_sub(payload.capacity() as u64));
        let delivery_digest = Some(*blake3::hash(&payload).as_bytes());
        WindowPadPayload {
            bytes: Cow::Owned(payload),
            memory: Some(memory),
            delivery_digest,
        }
    }
}

/// A notice borrowed from its frame, or an admitted delivery kept through import.
pub struct WindowPadPayload<'a> {
    bytes: Cow<'a, [u8]>,
    memory: Option<MemoryLease>,
    delivery_digest: Option<[u8; 32]>,
}

impl<'a> WindowPadPayload<'a> {
    pub(crate) fn borrowed(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
            memory: None,
            delivery_digest: None,
        }
    }

    pub(crate) fn delivery_digest(&self) -> Option<[u8; 32]> {
        self.delivery_digest
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
            delivery_digest: self.delivery_digest,
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
        + envelope.home_claim_copies.capacity() as u64
}

fn buffered(payload: &[u8], capacity: usize) -> Result<(Vec<u8>, MemoryLease), TransportError> {
    let mut memory = reserve(capacity)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| TransportError::Storage(format!("window pad allocation: {error}")))?;
    memory.materialized(capacity as u64, bytes.capacity() as u64);
    bytes.extend_from_slice(payload);
    Ok((bytes, memory))
}

fn decode_required_admitted(bytes: &[u8]) -> Result<ReceivedWindowPadEnvelope, TransportError> {
    decode_with_admission(bytes, decode_required_window_pads)
}

fn decode_admitted(bytes: &[u8]) -> Result<ReceivedWindowPadEnvelope, TransportError> {
    decode_with_admission(bytes, decode_window_pad_envelope)
}

fn decode_with_admission(
    bytes: &[u8],
    decode: fn(&[u8]) -> Result<WindowPadEnvelope, TransportError>,
) -> Result<ReceivedWindowPadEnvelope, TransportError> {
    let mut memory = reserve(bytes.len())?;
    let envelope = decode(bytes)?;
    memory.materialized(bytes.len() as u64, decoded_capacity(&envelope));
    Ok(ReceivedWindowPadEnvelope { envelope, memory })
}

fn add_inline_copies(decoded: &mut ReceivedWindowPadEnvelope, header: &Header, copies: &[u8]) {
    if copies.is_empty()
        || copies.len() != header.copies_len
        || *blake3::hash(copies).as_bytes() != header.copies_digest
    {
        return;
    }
    let len = copies.len() as u64;
    if decoded
        .memory
        .grow_pending(len, Instant::now(), &|| false)
        .is_err()
    {
        return;
    }
    let mut owned = Vec::new();
    if owned.try_reserve_exact(copies.len()).is_err() {
        decoded.memory.shrink(len);
        return;
    }
    decoded.memory.materialized(len, owned.capacity() as u64);
    owned.extend_from_slice(copies);
    decoded.envelope.home_claim_copies = owned;
}

impl Pending {
    fn optional(sub_tag: u8, id: [u8; 32], required: usize, total: usize, payload: &[u8]) -> Self {
        let (bytes, memory) = match buffered(payload, payload.len()) {
            Ok((bytes, memory)) => (bytes, Some(memory)),
            Err(_) => (Vec::new(), None),
        };
        Self {
            sub_tag,
            id,
            bytes,
            required,
            total,
            received: payload.len(),
            delivered: true,
            memory,
        }
    }

    fn discard_copies(&mut self) {
        self.bytes = Vec::new();
        self.memory = None;
    }

    fn append_copies(&mut self, bytes: &[u8]) {
        let Some(memory) = &mut self.memory else {
            return;
        };
        let old_capacity = self.bytes.capacity();
        let more = (self.bytes.len() + bytes.len()).saturating_sub(old_capacity) as u64;
        if memory
            .grow_pending(more, Instant::now(), &|| false)
            .is_err()
            || self.bytes.try_reserve_exact(bytes.len()).is_err()
        {
            self.discard_copies();
            return;
        }
        memory.materialized(more, (self.bytes.capacity() - old_capacity) as u64);
        self.bytes.extend_from_slice(bytes);
    }
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
        let required = header
            .required()
            .ok_or_else(|| invalid("window pad envelope length"))?;
        let total = header
            .total()
            .ok_or_else(|| invalid("window pad envelope length"))?;
        if header.kind != kind {
            return Err(invalid("window pad envelope of another kind"));
        }
        if payload.len() > total {
            return Err(invalid("window pad envelope length"));
        }
        self.pending.remove(window_key);
        let id = *blake3::hash(&payload[..WINDOW_PAD_HEADER_BYTES]).as_bytes();
        if payload.len() >= required {
            let mut decoded = decode_required_admitted(&payload[..required])?;
            if payload.len() == total {
                add_inline_copies(&mut decoded, &header, &payload[required..]);
            } else {
                // Keeping a late derived copy is optional, including its RAM.
                self.pending.insert(
                    window_key.to_owned(),
                    Pending::optional(sub_tag, id, required, total, payload),
                );
            }
            return Ok(WindowPadArrival::Envelope(sub_tag, decoded));
        }
        let (bytes, memory) = buffered(payload, required)?;
        self.pending.insert(
            window_key.to_owned(),
            Pending {
                sub_tag,
                id,
                bytes,
                required,
                total,
                received: payload.len(),
                delivered: false,
                memory: Some(memory),
            },
        );
        Ok(WindowPadArrival::Streaming)
    }

    fn part(
        &mut self,
        window_key: &str,
        payload: &[u8],
    ) -> Result<WindowPadArrival, TransportError> {
        let Some(pending) = self.pending.get_mut(window_key) else {
            return Ok(WindowPadArrival::Broken);
        };
        let Some(id) = window_pad_part_id(payload) else {
            if pending.delivered {
                pending.discard_copies();
                return Ok(WindowPadArrival::Streaming);
            }
            return Err(invalid("short window pad part"));
        };
        let offset = u64::from_be_bytes(payload[32..PART_LEAD].try_into().expect("part lead"));
        let bytes = &payload[PART_LEAD..];
        let end = pending.received.checked_add(bytes.len());
        if pending.id != id
            || offset != (pending.received - WINDOW_PAD_HEADER_BYTES) as u64
            || end.is_none_or(|end| end > pending.total)
        {
            if pending.delivered {
                pending.discard_copies();
                return Ok(WindowPadArrival::Streaming);
            }
            self.pending.remove(window_key);
            return Ok(WindowPadArrival::Broken);
        }
        let end = end.expect("checked part length");
        if !pending.delivered {
            let needed = (pending.required - pending.received).min(bytes.len());
            pending.bytes.extend_from_slice(&bytes[..needed]);
            pending.received += needed;
            if pending.received < pending.required {
                return Ok(WindowPadArrival::Streaming);
            }
            let mut decoded = decode_required_admitted(&pending.bytes)?;
            let sub_tag = pending.sub_tag;
            pending.delivered = true;
            let tail = &bytes[needed..];
            if end == pending.total {
                let header = Header::read(&pending.bytes)?;
                add_inline_copies(&mut decoded, &header, tail);
                self.pending.remove(window_key);
            } else {
                pending.append_copies(tail);
                pending.received = end;
            }
            return Ok(WindowPadArrival::Envelope(sub_tag, decoded));
        }
        pending.append_copies(bytes);
        pending.received = end;
        if end < pending.total {
            return Ok(WindowPadArrival::Streaming);
        }
        let Some(done) = self.pending.remove(window_key) else {
            return Ok(WindowPadArrival::Streaming);
        };
        if done.memory.is_none() {
            return Ok(WindowPadArrival::Streaming);
        }
        // A late optional allocation/decoding miss cannot turn a delivered
        // canonical frame into a broken delivery or request it again.
        match decode_admitted(&done.bytes) {
            Ok(envelope) if !envelope.home_claim_copies.is_empty() => {
                Ok(WindowPadArrival::Copies(envelope))
            }
            _ => Ok(WindowPadArrival::Streaming),
        }
    }

    /// Drops every envelope still coming in: the socket is gone.
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}
