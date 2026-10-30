//! A custody input read where it lies, never joined in one buffer (FIX
//! 11140). A door hands on the envelope its owner's surface sealed as it
//! arrived, in a file or a buffer, between the head and tail its recorder
//! attached: it reads the input once for the digest its request names, part
//! by part, and once more to keep it row by row, each numbered part read in
//! turn. The holder reads the kept rows the same way, in order and one at a
//! time, opening each envelope as it completes, so only the opened body is
//! ever whole. Every bound stays: a row's [`PART_BYTES`], the part list's
//! [`MAX_PARTS`], the frame and envelope codecs.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use zeroize::Zeroizing;

use super::attached::{ATTACHED_HEAD_MAX, Attached, Attachment, attached_head, attached_tail};
use super::{
    InputBinding, InputPart, MAX_PARTS, PART_BYTES, PART_LABEL, RelayedInput, held_input_in_txn,
    input_digest, part_digest, part_key, parts_digest, refused,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::world_keys::MachineSecret;

/// A sealed custody input as its door reads it (FIX 11140): bytes in one
/// buffer, or `len` bytes from a file's start, which the door reads twice,
/// once for the digest its request names and once to keep it row by row.
/// Neither is joined in memory past one row.
#[derive(Clone, Copy)]
pub enum SealedInput<'a> {
    /// The input in one buffer.
    Slice(&'a [u8]),
    /// The input in a file: `len` bytes from its start.
    File { file: &'a File, len: u64 },
}

// Never print the ciphertext.
impl std::fmt::Debug for SealedInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedInput")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl SealedInput<'_> {
    /// The input's length in bytes.
    pub fn len(&self) -> u64 {
        match self {
            Self::Slice(bytes) => bytes.len() as u64,
            Self::File { len, .. } => *len,
        }
    }

    /// Whether the input holds no byte.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> SealedInput<'a> {
    /// The input's bytes from its start.
    fn reader(self) -> io::Result<Box<dyn Read + 'a>> {
        let reader: Box<dyn Read + 'a> = match self {
            Self::Slice(bytes) => Box::new(bytes),
            Self::File { mut file, len } => {
                file.seek(SeekFrom::Start(0))?;
                Box::new(file.take(len))
            }
        };
        Ok(reader)
    }
}

/// A sealed input as a door hands it on: the head its recorder attached
/// before the envelope, the envelope where it lies, and the tail attached
/// after it. An input a door seals itself is one buffer, nothing attached.
#[derive(Clone, Copy)]
pub(crate) struct SealedFrame<'a> {
    head: &'a [u8],
    envelope: SealedInput<'a>,
    tail: &'a [u8],
}

/// The digest a request names of an input, and every part's digest, in
/// order, when it travels in parts.
pub(crate) struct InputDigests {
    pub(crate) digest: [u8; 32],
    parts: Option<Vec<[u8; 32]>>,
}

impl<'a> SealedFrame<'a> {
    /// `envelope` inside what its recorder `attached`, if anything.
    pub(crate) fn new(attached: Option<&'a Attachment>, envelope: SealedInput<'a>) -> Self {
        match attached {
            Some(attached) => Self {
                head: &attached.head,
                envelope,
                tail: &attached.tail,
            },
            None => Self {
                head: &[],
                envelope,
                tail: &[],
            },
        }
    }

    /// An input whole in one buffer, nothing attached.
    pub(crate) fn whole(input: &'a [u8]) -> Self {
        Self::new(None, SealedInput::Slice(input))
    }

    /// The input's length: its head, envelope and tail.
    fn len(self) -> u64 {
        self.head.len() as u64 + self.envelope.len() + self.tail.len() as u64
    }

    /// The input's bytes from its start: its head, envelope and tail.
    fn reader(self) -> io::Result<impl Read + 'a> {
        Ok(self.head.chain(self.envelope.reader()?).chain(self.tail))
    }

    /// The digest the request names of this input, as [`input_digest`]
    /// takes it of the joined bytes, read part by part, with every part's
    /// digest when it travels in parts. Refused only past the part list's
    /// own bound, as [`RelayedInput::parts`] refuses.
    pub(crate) fn digests(&self) -> Result<InputDigests> {
        let mut reader = self.reader()?;
        let mut left = self.len();
        let mut part = Vec::new();
        let mut parts = Vec::new();
        loop {
            read_part(&mut reader, &mut part, &mut left)?;
            parts.push(part_digest(&part));
            if parts.len() > MAX_PARTS {
                return Err(refused(
                    "the custody input splits into more parts than one part list names",
                ));
            }
            if left == 0 {
                break;
            }
        }
        // One part is the whole input, unless its own bytes read as a part.
        Ok(if parts.len() > 1 || part.starts_with(PART_LABEL) {
            InputDigests {
                digest: parts_digest(&parts),
                parts: Some(parts),
            }
        } else {
            InputDigests {
                digest: input_digest(&part),
                parts: None,
            }
        })
    }

    /// Each row this input is kept in, read in turn from its start and
    /// handed to `keep`: the whole input in one row, or each numbered part
    /// with every part's digest in `digests`, this input's, as
    /// [`RelayedInput::parts`] makes them of joined bytes. `row` holds what
    /// every row carries beside its bytes.
    pub(crate) fn each_row(
        &self,
        row: &RelayedInput,
        digests: &InputDigests,
        mut keep: impl FnMut(RelayedInput) -> Result<()>,
    ) -> Result<()> {
        let mut reader = self.reader()?;
        let mut left = self.len();
        let mut index = 0_u32;
        loop {
            let mut bytes = Vec::new();
            read_part(&mut reader, &mut bytes, &mut left)?;
            keep(RelayedInput {
                sealed_at: row.sealed_at,
                request: row.request,
                witness: row.witness.clone(),
                part: digests.parts.as_ref().map(|digests| InputPart {
                    index,
                    digests: digests.clone(),
                }),
                envelope: bytes,
            })?;
            if left == 0 {
                return Ok(());
            }
            index = index.saturating_add(1);
        }
    }
}

/// Reads the next part of an input with `left` bytes still to read into
/// `part`: at most [`PART_BYTES`], the rest of it when less.
fn read_part(reader: &mut impl Read, part: &mut Vec<u8>, left: &mut u64) -> io::Result<()> {
    let take = usize::try_from(*left).map_or(PART_BYTES, |left| left.min(PART_BYTES));
    part.clear();
    part.resize(take, 0);
    reader.read_exact(part)?;
    *left -= take as u64;
    Ok(())
}

/// The input a request names, as this vault keeps it: every row here and
/// at its place, read again in order when it is opened.
pub(crate) struct KeptInput<'a, 't> {
    store: &'a Store,
    txn: &'a heed::RoTxn<'t>,
    digest: [u8; 32],
    /// Its part count; `None` while it is one whole row.
    parts: Option<u32>,
    /// Every row's bytes, summed.
    len: u64,
}

/// The input the request names `digest` of, as this vault keeps it: its
/// whole row, or every part of it in order, each checked against the part
/// list `digest` is over, each read and let go. `None` while it, or any
/// part of it, is not here: the request stays pending.
pub(crate) fn kept_input_in_txn<'a, 't>(
    store: &'a Store,
    txn: &'a heed::RoTxn<'t>,
    digest: &[u8; 32],
) -> Result<Option<KeptInput<'a, 't>>> {
    let kept = |parts, len| KeptInput {
        store,
        txn,
        digest: *digest,
        parts,
        len,
    };
    if let Some(whole) = held_input_in_txn(store, txn, digest)?
        && whole.part.is_none()
        && whole.digest() == *digest
    {
        return Ok(Some(kept(None, whole.envelope.len() as u64)));
    }
    let mut len = 0_u64;
    let mut index = 0_u32;
    loop {
        let Some((bytes, count)) = kept_part_in_txn(store, txn, digest, index)? else {
            return Ok(None);
        };
        len = len.saturating_add(bytes.len() as u64);
        index += 1;
        if usize::try_from(index).is_ok_and(|done| done == count) {
            return Ok(Some(kept(Some(index), len)));
        }
    }
}

/// Part `index` of the input the request names `digest` of, kept here at
/// its place in the part list `digest` is over: its bytes and the part
/// count. `None` otherwise.
fn kept_part_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
    index: u32,
) -> Result<Option<(Vec<u8>, usize)>> {
    let Some(row) = held_input_in_txn(store, txn, &part_key(digest, index))? else {
        return Ok(None);
    };
    let Some(part) = &row.part else {
        return Ok(None);
    };
    if part.index != index || parts_digest(&part.digests) != *digest {
        return Ok(None);
    }
    let count = part.digests.len();
    Ok(Some((row.envelope, count)))
}

impl KeptInput<'_, '_> {
    /// The body this input holds, opened with the holder's `secret` under
    /// `binding`, and what its recorder attached beside the envelope, if
    /// anything: its rows read in order and let go, its head read first,
    /// then its envelope, each one opened as it completes, then its tail.
    /// `None` for a malformed frame or an envelope that does not open.
    ///
    /// # Errors
    /// Storage errors reading a row.
    pub(crate) fn open(
        &self,
        binding: &InputBinding<'_>,
        secret: &MachineSecret,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, Option<Attached>)>> {
        let mut rows = KeptRows {
            store: self.store,
            txn: self.txn,
            digest: self.digest,
            parts: self.parts,
            next: 0,
            row: Vec::new(),
            at: 0,
            fault: None,
        };
        let opened = open_framed(binding, &mut rows, self.len, secret);
        match rows.fault {
            Some(fault) => Err(fault),
            None => Ok(opened),
        }
    }
}

/// The body an input of `len` bytes read from `reader` holds, opened under
/// `binding`, and what its recorder attached: its head when it opens with
/// one, then the envelope that head counts, or the whole input, then the
/// tail after it.
fn open_framed(
    binding: &InputBinding<'_>,
    mut reader: impl Read,
    len: u64,
    secret: &MachineSecret,
) -> Option<(Zeroizing<Vec<u8>>, Option<Attached>)> {
    let mut prefix = vec![0; usize::try_from(len.min(ATTACHED_HEAD_MAX as u64)).ok()?];
    reader.read_exact(&mut prefix).ok()?;
    let (form, taken, envelope_len) = match attached_head(&prefix)? {
        Some((form, envelope_len)) => (Some(form), form.head_len(), u64::from(envelope_len)),
        None => (None, 0, len),
    };
    let mut rest = prefix.get(taken..)?.chain(reader);
    let body = binding.open(&mut rest, envelope_len, secret)?;
    let Some(form) = form else {
        return Some((body, None));
    };
    let mut tail = Vec::new();
    rest.read_to_end(&mut tail).ok()?;
    Some((body, Some(attached_tail(form, &tail)?)))
}

/// A kept input's bytes in order, each row read as the one before it is
/// used up.
struct KeptRows<'a, 't> {
    store: &'a Store,
    txn: &'a heed::RoTxn<'t>,
    digest: [u8; 32],
    parts: Option<u32>,
    /// The next row's place.
    next: u32,
    /// The row being read, and how far.
    row: Vec<u8>,
    at: usize,
    /// A storage error a row met, which the opener returns.
    fault: Option<Error>,
}

impl KeptRows<'_, '_> {
    /// The next row's bytes, in order; `None` past the last.
    fn next_row(&mut self) -> Result<Option<Vec<u8>>> {
        let index = self.next;
        self.next = self.next.saturating_add(1);
        match self.parts {
            None if index == 0 => {
                Ok(held_input_in_txn(self.store, self.txn, &self.digest)?
                    .map(|whole| whole.envelope))
            }
            Some(count) if index < count => {
                Ok(kept_part_in_txn(self.store, self.txn, &self.digest, index)?
                    .map(|(bytes, _)| bytes))
            }
            None | Some(_) => Ok(None),
        }
    }
}

impl Read for KeptRows<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.at == self.row.len() {
            match self.next_row() {
                Ok(Some(row)) => {
                    self.row = row;
                    self.at = 0;
                }
                Ok(None) => return Ok(0),
                Err(fault) => {
                    self.fault = Some(fault);
                    return Err(io::Error::other("a kept custody input row did not read"));
                }
            }
        }
        let read = out.len().min(self.row.len() - self.at);
        out[..read].copy_from_slice(&self.row[self.at..self.at + read]);
        self.at += read;
        Ok(read)
    }
}
