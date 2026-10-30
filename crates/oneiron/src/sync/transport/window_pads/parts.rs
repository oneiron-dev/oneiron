//! A window pad envelope put back together on its socket (KS-5, FIX 7107):
//! the first frame, then its `WINDOW_PAD_PART` frames in order, each at its
//! offset past the header, a payload past one frame included (FIX 8247). The bytes
//! are held in memory for that delivery alone. A part that names no envelope
//! here, or breaks one, ends the delivery as a lost frame would; a first
//! frame for a window whose earlier envelope is still incomplete takes its
//! place. Nothing waits on a part, and no part is asked for again.

use std::collections::HashMap;

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
    Envelope(u8, WindowPadEnvelope),
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
        if sub_tag == window_sub_tags::WINDOW_PAD_PART {
            return self.part(window_key, payload);
        }
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
            return decode_window_pad_envelope(payload)
                .map(|envelope| WindowPadArrival::Envelope(sub_tag, envelope));
        }
        self.pending.insert(
            window_key.to_owned(),
            Pending {
                sub_tag,
                id: *blake3::hash(&payload[..WINDOW_PAD_HEADER_BYTES]).as_bytes(),
                bytes: payload.to_vec(),
                total,
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
        decode_window_pad_envelope(&done.bytes)
            .map(|envelope| WindowPadArrival::Envelope(done.sub_tag, envelope))
    }

    /// Drops every envelope still coming in: the socket is gone.
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}
