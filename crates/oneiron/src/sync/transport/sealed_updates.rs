//! Sealed world-update frames (DEC-0005 fix 8, CLIP-SYNC = A, FIX 12586): a
//! home that may not read a my-machines world stores its sealed updates and
//! relays them between the owner's machines.
//!
//! `[TAG_SEALED_UPDATE][sub tag][fields]`, scalars big-endian. A home sends
//! [`sealed_update_sub_tags::OFFER`] only to a socket whose hello listed the
//! frame kind ([`super::codec::frame_kind_ids::SEALED_WORLD_UPDATES`]) and
//! whose machine stands as one of the owner's own; a machine sends the other
//! machine-to-home frames only on a connection whose home offered. So a peer
//! of an older build never sees one. Every sealed payload is opaque here.

use super::TransportError;

/// Top-level tag of every sealed world-update frame.
pub const TAG_SEALED_UPDATE: u8 = 32;

/// Sub tags after [`TAG_SEALED_UPDATE`].
pub mod sealed_update_sub_tags {
    /// Home to machine: `[queue epoch:16][head seq:8]`. The home keeps a
    /// queue of sealed updates for this vault; its epoch changes when the
    /// queue starts again from nothing.
    pub const OFFER: u8 = 0;
    /// Machine to home: `[epoch:16][after:8]`. Every stored update after
    /// `after` in `epoch` (from the queue's start when `epoch` is not the
    /// queue's), one page, then [`CAUGHT_UP`]; and from now on, each update
    /// stored live.
    pub const SINCE: u8 = 1;
    /// Home to machine, live: `[epoch:16][seq:8][sealed]`, one update just
    /// stored.
    pub const ENTRY: u8 = 2;
    /// Home to machine, a page answering [`SINCE`]: `[epoch:16][seq:8][sealed]`.
    pub const PAGE_ENTRY: u8 = 3;
    /// Home to machine: `[epoch:16][through:8][more:1]`, the end of one page.
    pub const CAUGHT_UP: u8 = 4;
    /// Machine to home: `[id:16][sealed]`, one update to store and relay once.
    pub const PUT: u8 = 5;
    /// Home to machine: `[id:16][epoch:16][seq:8]`, the update `id` is stored.
    pub const STORED: u8 = 6;
}

/// The length of a home's queue epoch.
pub const SEALED_UPDATE_EPOCH_LEN: usize = 16;
/// The length of an update's id.
pub const SEALED_UPDATE_FRAME_ID_LEN: usize = 16;

/// One decoded sealed world-update frame, borrowing its sealed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedUpdateFrame<'a> {
    Offer {
        epoch: [u8; SEALED_UPDATE_EPOCH_LEN],
        head: u64,
    },
    Since {
        epoch: [u8; SEALED_UPDATE_EPOCH_LEN],
        after: u64,
    },
    Entry {
        epoch: [u8; SEALED_UPDATE_EPOCH_LEN],
        seq: u64,
        sealed: &'a [u8],
    },
    PageEntry {
        epoch: [u8; SEALED_UPDATE_EPOCH_LEN],
        seq: u64,
        sealed: &'a [u8],
    },
    CaughtUp {
        epoch: [u8; SEALED_UPDATE_EPOCH_LEN],
        through: u64,
        more: bool,
    },
    Put {
        id: [u8; SEALED_UPDATE_FRAME_ID_LEN],
        sealed: &'a [u8],
    },
    Stored {
        id: [u8; SEALED_UPDATE_FRAME_ID_LEN],
        epoch: [u8; SEALED_UPDATE_EPOCH_LEN],
        seq: u64,
    },
}

/// The whole frame, tag included.
#[must_use]
pub fn encode_sealed_update_frame(frame: &SealedUpdateFrame<'_>) -> Vec<u8> {
    use sealed_update_sub_tags as sub;
    let mut out = vec![TAG_SEALED_UPDATE];
    match frame {
        SealedUpdateFrame::Offer { epoch, head } => {
            out.push(sub::OFFER);
            out.extend_from_slice(epoch);
            out.extend_from_slice(&head.to_be_bytes());
        }
        SealedUpdateFrame::Since { epoch, after } => {
            out.push(sub::SINCE);
            out.extend_from_slice(epoch);
            out.extend_from_slice(&after.to_be_bytes());
        }
        SealedUpdateFrame::Entry { epoch, seq, sealed } => {
            out.reserve(1 + 16 + 8 + sealed.len());
            out.push(sub::ENTRY);
            out.extend_from_slice(epoch);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(sealed);
        }
        SealedUpdateFrame::PageEntry { epoch, seq, sealed } => {
            out.reserve(1 + 16 + 8 + sealed.len());
            out.push(sub::PAGE_ENTRY);
            out.extend_from_slice(epoch);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(sealed);
        }
        SealedUpdateFrame::CaughtUp {
            epoch,
            through,
            more,
        } => {
            out.push(sub::CAUGHT_UP);
            out.extend_from_slice(epoch);
            out.extend_from_slice(&through.to_be_bytes());
            out.push(u8::from(*more));
        }
        SealedUpdateFrame::Put { id, sealed } => {
            out.reserve(1 + 16 + sealed.len());
            out.push(sub::PUT);
            out.extend_from_slice(id);
            out.extend_from_slice(sealed);
        }
        SealedUpdateFrame::Stored { id, epoch, seq } => {
            out.push(sub::STORED);
            out.extend_from_slice(id);
            out.extend_from_slice(epoch);
            out.extend_from_slice(&seq.to_be_bytes());
        }
    }
    out
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], TransportError> {
    let (head, rest) = bytes
        .split_first_chunk::<N>()
        .ok_or(TransportError::InvalidPayload(
            "sealed update frame too short",
        ))?;
    *bytes = rest;
    Ok(*head)
}

/// Decodes the bytes after [`TAG_SEALED_UPDATE`].
///
/// # Errors
/// [`TransportError::InvalidPayload`] for an unknown sub tag, a frame too
/// short or too long for its sub tag, an empty sealed payload, or a `more`
/// byte other than 0 or 1.
pub fn decode_sealed_update_frame(payload: &[u8]) -> Result<SealedUpdateFrame<'_>, TransportError> {
    use sealed_update_sub_tags as sub;
    let (&sub_tag, mut rest) = payload
        .split_first()
        .ok_or(TransportError::InvalidPayload("empty sealed update frame"))?;
    let exact = |rest: &[u8]| {
        if rest.is_empty() {
            Ok(())
        } else {
            Err(TransportError::InvalidPayload(
                "trailing bytes on a sealed update frame",
            ))
        }
    };
    let sealed = |rest: &[u8]| {
        if rest.is_empty() {
            Err(TransportError::InvalidPayload(
                "a sealed update with no bytes",
            ))
        } else {
            Ok(())
        }
    };
    match sub_tag {
        sub::OFFER => {
            let epoch = take::<16>(&mut rest)?;
            let head = u64::from_be_bytes(take::<8>(&mut rest)?);
            exact(rest)?;
            Ok(SealedUpdateFrame::Offer { epoch, head })
        }
        sub::SINCE => {
            let epoch = take::<16>(&mut rest)?;
            let after = u64::from_be_bytes(take::<8>(&mut rest)?);
            exact(rest)?;
            Ok(SealedUpdateFrame::Since { epoch, after })
        }
        sub::ENTRY | sub::PAGE_ENTRY => {
            let epoch = take::<16>(&mut rest)?;
            let seq = u64::from_be_bytes(take::<8>(&mut rest)?);
            sealed(rest)?;
            Ok(if sub_tag == sub::ENTRY {
                SealedUpdateFrame::Entry {
                    epoch,
                    seq,
                    sealed: rest,
                }
            } else {
                SealedUpdateFrame::PageEntry {
                    epoch,
                    seq,
                    sealed: rest,
                }
            })
        }
        sub::CAUGHT_UP => {
            let epoch = take::<16>(&mut rest)?;
            let through = u64::from_be_bytes(take::<8>(&mut rest)?);
            let [more] = take::<1>(&mut rest)?;
            exact(rest)?;
            let more = match more {
                0 => false,
                1 => true,
                _ => {
                    return Err(TransportError::InvalidPayload(
                        "a caught-up frame's more byte is 0 or 1",
                    ));
                }
            };
            Ok(SealedUpdateFrame::CaughtUp {
                epoch,
                through,
                more,
            })
        }
        sub::PUT => {
            let id = take::<16>(&mut rest)?;
            sealed(rest)?;
            Ok(SealedUpdateFrame::Put { id, sealed: rest })
        }
        sub::STORED => {
            let id = take::<16>(&mut rest)?;
            let epoch = take::<16>(&mut rest)?;
            let seq = u64::from_be_bytes(take::<8>(&mut rest)?);
            exact(rest)?;
            Ok(SealedUpdateFrame::Stored { id, epoch, seq })
        }
        _ => Err(TransportError::InvalidPayload(
            "unknown sealed update sub tag",
        )),
    }
}
