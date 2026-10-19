//! An input whose body passes one envelope's plaintext bound (FIX 5521;
//! Rule 5: split, never refuse). The envelope codec seals at most
//! `oneiron_crypto::MAX_PLAINTEXT_LEN` bytes, the input label included, so
//! such a body seals as numbered envelopes, each the label and the next run
//! of the body, and travels as one frame: its label, the envelope count,
//! each envelope's length and bytes in order, then a closing mark. Each
//! envelope's key id is the one-envelope key id with its index and the
//! count after it, so none opens at another place, in a frame that counts
//! another number, as a one-envelope input, or as another change's.
//!
//! The frame is the input: the request's one digest is over it, or over its
//! parts' digests once it travels in parts (`super`), so it commits to every
//! envelope in order, the count and the closing mark, over ciphertext
//! alone. The holder opens and verifies every envelope at its place before
//! it hands the joined body on; one that does not open leaves nothing, and
//! what was joined is wiped. A missing envelope is a missing part: the
//! request stays pending.
//!
//! A body that fits one envelope keeps the one-envelope form it has always
//! had, so a surface that seals its own input needs nothing new; the
//! numbered form carries two envelopes or more, and a surface may seal one
//! too. Those are an input's only two forms.

use oneiron_crypto::{HybridPublicKey, MAX_PLAINTEXT_LEN};
use zeroize::Zeroizing;

use super::{INPUT_LABEL, InputBinding, refused};
use crate::error::Result;
use crate::world_keys::MachineSecret;

/// The label a numbered input's frame opens with.
const ENVELOPES_LABEL: &[u8] = b"oneiron/custody-input-envelopes/v1\0";
/// The mark that closes a numbered input's frame, after its last envelope.
const ENVELOPES_END: &[u8] = b"oneiron/custody-input-envelopes-end/v1\0";
/// The most body bytes one envelope holds: the codec's own bound on one
/// plaintext, less the input label each one opens with.
const ENVELOPE_BODY_BYTES: usize = MAX_PLAINTEXT_LEN - INPUT_LABEL.len();

/// Whether `body` seals as one envelope.
pub(super) fn fits_one(body: &[u8]) -> bool {
    body.len() <= ENVELOPE_BODY_BYTES
}

/// A numbered input's frame after its label; `None` for one envelope.
pub(super) fn numbered_frame(input: &[u8]) -> Option<&[u8]> {
    input.strip_prefix(ENVELOPES_LABEL)
}

impl InputBinding<'_> {
    /// The key id of envelope `index` of `count`: the one-envelope key id,
    /// then the index and the count, within the envelope's 64-byte id.
    fn numbered_key_id(&self, index: u32, count: u32) -> Vec<u8> {
        let mut key_id = self.key_id();
        key_id.extend_from_slice(&index.to_be_bytes());
        key_id.extend_from_slice(&count.to_be_bytes());
        key_id
    }

    /// Seals `body`, past one envelope's bound, to the holder's `key` as
    /// numbered envelopes in one frame. Refused only past the frame's own
    /// codec bounds: a count or an envelope's length past a `u32`.
    pub(super) fn seal_numbered(&self, key: &HybridPublicKey, body: &[u8]) -> Result<Vec<u8>> {
        let count = u32::try_from(body.len().div_ceil(ENVELOPE_BODY_BYTES)).map_err(|_| {
            refused("the custody input seals as more envelopes than its frame counts")
        })?;
        let mut frame =
            Vec::with_capacity(ENVELOPES_LABEL.len() + 4 + body.len() + ENVELOPES_END.len());
        frame.extend_from_slice(ENVELOPES_LABEL);
        frame.extend_from_slice(&count.to_be_bytes());
        for (run, index) in body.chunks(ENVELOPE_BODY_BYTES).zip(0_u32..) {
            let envelope = self.seal_one(key, run, &self.numbered_key_id(index, count))?;
            let len = u32::try_from(envelope.len())
                .map_err(|_| refused("a custody input envelope is longer than its frame states"))?;
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&envelope);
        }
        frame.extend_from_slice(ENVELOPES_END);
        Ok(frame)
    }

    /// The body a numbered input's `frame` holds, opened with the holder's
    /// `secret`: every envelope opened and verified at its place, in order,
    /// then the body joined. `None` for a malformed frame or any envelope
    /// that does not open at its place.
    pub(super) fn open_numbered(
        &self,
        frame: &[u8],
        secret: &MachineSecret,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let envelopes = split_frame(frame)?;
        let count = u32::try_from(envelopes.len()).ok()?;
        // Each run is shorter than its envelope, so the joined body never
        // moves and leaves no unwiped copy behind.
        let mut body = Zeroizing::new(Vec::with_capacity(
            envelopes.iter().copied().map(<[u8]>::len).sum(),
        ));
        for (envelope, index) in envelopes.into_iter().zip(0_u32..) {
            let run = self.open_one(envelope, secret, &self.numbered_key_id(index, count))?;
            body.extend_from_slice(&run);
        }
        Some(body)
    }
}

/// Each envelope a numbered frame holds, in order: its count, two at least,
/// each envelope's length and bytes, then the closing mark with nothing
/// after it. `None` for anything else.
fn split_frame(frame: &[u8]) -> Option<Vec<&[u8]>> {
    let (count, mut rest) = frame.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count);
    if count < 2 {
        return None;
    }
    let mut envelopes = Vec::new();
    for _ in 0..count {
        let (len, after) = rest.split_first_chunk::<4>()?;
        let (envelope, after) =
            after.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)?;
        envelopes.push(envelope);
        rest = after;
    }
    (rest == ENVELOPES_END).then_some(envelopes)
}
