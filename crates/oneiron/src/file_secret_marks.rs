//! Value-free file-mask paths, read visibility, and byte-span transformations.

use crate::error::{Error, Result, SecretError};

/// The byte a key's span reads as in a masked copy. A run of it is the
/// door's own mask shape (`********`), never secret material.
pub(crate) const FILLER: u8 = b'*';

/// One step from a container into a member it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberStep {
    /// A ZIP entry, by its place in the central directory.
    Zip { entry: u32 },
    /// A gzip file's payload: every member it chains, read as one.
    Gzip,
    /// A tar entry, by its place in archive order (FIX 2471).
    Tar { entry: u32 },
    /// An xz file's decompressed payload (FIX 2471).
    Xz,
    /// A PDF stream other than an object stream, by its object's id (FIX
    /// 11550): a page content stream and the like.
    PdfStream { object: u32, generation: u16 },
    /// A PDF object stream's decoded bytes, by its object's id (FIX 11550):
    /// its header names each object by byte offset.
    PdfObjectStream { object: u32, generation: u16 },
    /// A PDF object's text strings, each decoded, in the object's order
    /// (FIX 2469), by the object's id.
    PdfStrings { object: u32, generation: u16 },
}

/// Where a file's keys sit, without their records: one entry per place, the
/// stored bytes' own (an empty path) and each member's, with its spans.
pub(crate) type KeyPlaces = Vec<(Vec<MemberStep>, Vec<(u64, u64)>)>;

/// The handle text each key in [`KeyPlaces`] stands as in a text member of a
/// masked copy (FIX 7944), place for place and span for span; `None` where
/// custody names no handle, and the filler stands in.
pub(crate) type PlaceHandles = Vec<Vec<Option<String>>>;

/// How a serving door hands a file's bytes to its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSight {
    /// The vault owner, verified at the door, and the owner's own export:
    /// the stored bytes.
    Owner,
    /// Every other reader (an agent, a contact, a link): each key's span
    /// overwritten, in the file or in the member that holds it.
    Masked,
    /// An agent whose standing or approve-once grant covers the file's keys,
    /// with the read's receipt already written: the stored bytes.
    Granted,
}

/// `bytes` with each span in `spans` overwritten by the filler.
pub(crate) fn filled(bytes: &[u8], spans: impl IntoIterator<Item = (u64, u64)>) -> Result<Vec<u8>> {
    let mut copy = bytes.to_vec();
    for (start, end) in spans {
        usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| copy.get_mut(start..end))
            .ok_or(Error::CorruptedIndex("masked file key span"))?
            .fill(FILLER);
    }
    Ok(copy)
}

/// `bytes` with each span in `spans` replaced by its handle text, or by the
/// filler at the span's length where it has none (FIX 7944): a key in a text
/// member reads as the handle custody holds it under. `spans` in byte
/// order; one that overlaps the span before it replaces what is left of it.
pub(crate) fn filled_with(bytes: &[u8], spans: &[((u64, u64), Option<&str>)]) -> Result<Vec<u8>> {
    let mut copy = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for &((start, end), handle) in spans {
        let (start, end) = usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .filter(|&(start, end)| start <= end && end <= bytes.len())
            .ok_or(Error::CorruptedIndex("masked file key span"))?;
        let start = start.max(at);
        if end <= start {
            continue;
        }
        copy.extend_from_slice(&bytes[at..start]);
        match handle {
            Some(text) => copy.extend_from_slice(text.as_bytes()),
            None => copy.resize(copy.len() + (end - start), FILLER),
        }
        at = end;
    }
    copy.extend_from_slice(&bytes[at..]);
    Ok(copy)
}

/// A serving door's refusal of a file it cannot serve masked (FIX 2475):
/// `reason` is the scan's code (a hit, or why the walk read no further).
pub(crate) fn masked_copy_withheld(reason: &'static str) -> Error {
    Error::Secret(SecretError::MaskedCopyWithheld { reason })
}

