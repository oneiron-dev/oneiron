//! A surface's custody input past one row, sealed under its carrier key in
//! numbered parts (FIX 12148): input v2's parts layer.
//!
//! The door reads a surface's sealed input where it lies and joins none
//! past one row (FIX 11140), so one past it is never sealed under the key
//! whole. It is sealed part by part as it is read instead: each run of at
//! most [`PART_PLAIN_BYTES`] under the request's one carrier key, at its own
//! nonce, bound to the key's reference, its index and the part count
//! ([`CarrierRef::seal_part`]), so a sealed part is at most one row. No part
//! opens in another's place, past its count or as another carrier's.
//!
//! After the leaf-sealed input's head, the layer is the part count, a
//! big-endian `u32`, then each part in order: its nonce, then its
//! ciphertext and tag. It rides the input's numbered rows (Rule 5) like any
//! input past one row, the request's digest over theirs, so a row not yet
//! here keeps the request pending.
//!
//! The door reads the input once (FIX 12177, [`read_leaf_rows_in_txn`]): it
//! stages each row of the parts as it seals them, digests each row as it is
//! staged, and digests the input's own bytes, which the same input sent
//! again is found by, as they go by. The head row, which carries that
//! digest, is held until the input is read through.
//!
//! The holder reads the parts in order, opens each whole before any of its
//! bytes go on, and opens the surface's input from them as one kept as it
//! lies: every part must open at its place, and none may be missing or left
//! over.

use std::cell::Cell;
use std::io::{self, Read};

use zeroize::Zeroizing;

use super::super::super::super::carrier_custody::{
    CARRIER_SEAL_BYTES, CarrierPart, CarrierPartNonces, CarrierRef,
};
use super::super::door_rows::{DoorInput, RowStage, StreamedDigest};
use super::super::stream::{open_framed, read_part};
use super::super::{Attached, InputBinding, PART_BYTES, SealedFrame, refused};
use super::{LEAF_HEAD_BYTES, LEAF_RETRY_AT};
use crate::Vault;
use crate::error::Result;
use crate::store::CredentialLeaf;
use crate::world_keys::MachineSecret;

/// The most bytes of a surface's input one part seals: a sealed part is at
/// most one row's bytes.
const PART_PLAIN_BYTES: usize = PART_BYTES - CARRIER_SEAL_BYTES;

/// The parts layer's own head: the part count.
const COUNT_BYTES: usize = 4;

/// A surface's input past one row as the door keeps it, sealed under its
/// carrier key in numbered parts: the leaf-sealed input's head and the part
/// count, then each part, sealed as the input is read.
pub(crate) struct LeafParts {
    /// The leaf-sealed input's head, then the part count.
    head: Vec<u8>,
    carrier: CarrierRef,
    leaf: CredentialLeaf,
    nonces: CarrierPartNonces,
    count: u32,
    /// The surface's input's length.
    plain: u64,
    /// The surface's input's own digest, taken as its last read went
    /// through it: what the same input sent again is found by (CALLS
    /// CUSTODY_RETRY, FIX 12177).
    retry: Cell<Option<[u8; 32]>>,
}

/// The part count a surface's input of `len` bytes seals into.
///
/// # Errors
/// An empty input, or one past the count's codec.
pub(super) fn part_count(len: u64) -> Result<u32> {
    u32::try_from(len.div_ceil(PART_PLAIN_BYTES as u64))
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| refused("the custody input does not fit a numbered carrier part count"))
}

impl LeafParts {
    /// The `count` parts ([`part_count`]) a surface's input of `plain`
    /// bytes seals into under `carrier`'s key `leaf`, after the leaf-sealed
    /// input's `head`, at nonces drawn now.
    pub(super) fn new(
        mut head: Vec<u8>,
        carrier: CarrierRef,
        leaf: CredentialLeaf,
        count: u32,
        plain: u64,
    ) -> Self {
        head.extend_from_slice(&count.to_be_bytes());
        Self {
            head,
            carrier,
            leaf,
            nonces: CarrierPartNonces::draw(),
            count,
            plain,
            retry: Cell::new(None),
        }
    }

    /// Its length as kept: the head and the part count, then the surface's
    /// input with each part's seal.
    pub(crate) fn sealed_len(&self) -> u64 {
        self.head.len() as u64 + self.plain + u64::from(self.count) * CARRIER_SEAL_BYTES as u64
    }

    /// Its bytes from its start, each part sealed as `input`, the surface's
    /// input, is read, and that input's own digest taken as it goes by.
    pub(crate) fn reader<'a>(&'a self, input: impl Read + 'a) -> impl Read + 'a {
        self.retry.set(None);
        self.head.as_slice().chain(SealingParts {
            parts: self,
            input,
            next: 0,
            left: self.plain,
            sealed: Vec::new(),
            at: 0,
            retry: Some(StreamedDigest::new(self.plain)),
        })
    }
}

/// A surface's input read as its numbered parts, each run sealed as it is
/// read.
struct SealingParts<'a, R> {
    parts: &'a LeafParts,
    input: R,
    /// The next part's index.
    next: u32,
    /// The input's bytes still to read.
    left: u64,
    /// The part being read out, and how far.
    sealed: Vec<u8>,
    at: usize,
    /// The input's own digest, until it is read through.
    retry: Option<StreamedDigest>,
}

impl<R: Read> Read for SealingParts<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.sealed.len() {
            if self.left == 0 {
                return Ok(0);
            }
            let take = usize::try_from(self.left)
                .map_or(PART_PLAIN_BYTES, |left| left.min(PART_PLAIN_BYTES));
            let mut run = vec![0; take];
            self.input.read_exact(&mut run)?;
            self.left -= take as u64;
            if let Some(retry) = &mut self.retry {
                retry.update(&run);
            }
            if self.left == 0
                && let Some(retry) = self.retry.take()
            {
                self.parts.retry.set(Some(retry.finish()));
            }
            let part = CarrierPart {
                index: self.next,
                count: self.parts.count,
            };
            self.sealed = self
                .parts
                .carrier
                .seal_part(&self.parts.leaf, &self.parts.nonces, part, &run)
                .map_err(|_| io::Error::other("a custody input part did not seal"))?;
            self.next = self.next.saturating_add(1);
            self.at = 0;
        }
        let read = out.len().min(self.sealed.len() - self.at);
        out[..read].copy_from_slice(&self.sealed[self.at..self.at + read]);
        self.at += read;
        Ok(read)
    }
}

/// Reads the surface's input `frame` once, as the door keeps it under
/// `parts` (FIX 12177): each row of its numbered carrier parts is staged in
/// `wtxn` as it is sealed and digested as it is staged, while the input's
/// own digest is taken as it goes by. The head row is held until the input
/// is read through, the input's own digest set in it, then staged last.
///
/// # Errors
/// A fault reading the input from its file; one past the part list's
/// bound; storage errors.
pub(super) fn read_leaf_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    frame: SealedFrame<'_>,
    parts: &LeafParts,
) -> Result<DoorInput<'static>> {
    let mut left = parts.sealed_len();
    let mut stage = RowStage::new(&parts.carrier.encode(), left)?;
    let mut reader = frame.under_leaf_parts(parts).reader()?;
    let mut head = Vec::new();
    read_part(&mut reader, &mut head, &mut left)?;
    let mut index = 0_u32;
    while left > 0 {
        let mut row = Vec::new();
        read_part(&mut reader, &mut row, &mut left)?;
        index += 1;
        stage.stage_in_txn(vault, wtxn, index, row)?;
    }
    let retry = parts
        .retry
        .get()
        .ok_or_else(|| refused("the custody input was not read through"))?;
    head.get_mut(LEAF_RETRY_AT..LEAF_HEAD_BYTES)
        .ok_or_else(|| refused("the custody input's head outgrows its first row"))?
        .copy_from_slice(&retry);
    stage.stage_in_txn(vault, wtxn, 0, head)?;
    Ok(DoorInput::Staged(stage.finish()))
}

/// The body the parts layer of `len` bytes read from `rows` holds, with
/// what its recorder attached: each part opened under `carrier`'s key
/// `leaf` at its place, and the surface's input they join opened under
/// `binding` with the holder's `secret`, as one kept as it lies. `None`
/// when the layer's length is not its part count's, a part does not open
/// at its place, one is left over, or the input does not open.
pub(super) fn open_parts(
    rows: &mut dyn Read,
    len: u64,
    carrier: &CarrierRef,
    leaf: &CredentialLeaf,
    binding: &InputBinding<'_>,
    secret: &MachineSecret,
) -> Option<(Zeroizing<Vec<u8>>, Option<Attached>)> {
    let mut count = [0; COUNT_BYTES];
    rows.read_exact(&mut count).ok()?;
    let count = u32::from_be_bytes(count);
    let sealed = len.checked_sub(COUNT_BYTES as u64)?;
    let plain = plain_len(count, sealed)?;
    let mut parts = OpeningParts {
        carrier,
        leaf,
        rows,
        count,
        next: 0,
        left: sealed,
        opened: Zeroizing::new(Vec::new()),
        at: 0,
    };
    let opened = open_framed(binding, &mut parts, plain, secret)?;
    // Every part opened and read out: none missing, none left over.
    (parts.next == count && parts.at == parts.opened.len()).then_some(opened)
}

/// The surface's input's length under `count` parts that seal into
/// `sealed` bytes: every part but the last a full row, the last sealing at
/// least one byte. `None` for any other length.
fn plain_len(count: u32, sealed: u64) -> Option<u64> {
    let full = u64::from(count.checked_sub(1)?).checked_mul(PART_BYTES as u64)?;
    let last = sealed.checked_sub(full)?;
    if last <= CARRIER_SEAL_BYTES as u64 || last > PART_BYTES as u64 {
        return None;
    }
    sealed.checked_sub(u64::from(count) * CARRIER_SEAL_BYTES as u64)
}

/// A parts layer read as the surface's input it seals: each part opened
/// whole, at its place, before any of its bytes go on.
struct OpeningParts<'a, R> {
    carrier: &'a CarrierRef,
    leaf: &'a CredentialLeaf,
    rows: R,
    count: u32,
    /// The next part's index.
    next: u32,
    /// The layer's bytes still to read.
    left: u64,
    /// The part opened, and how far it is read.
    opened: Zeroizing<Vec<u8>>,
    at: usize,
}

impl<R: Read> Read for OpeningParts<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.opened.len() {
            if self.next == self.count {
                return Ok(0);
            }
            let take = usize::try_from(self.left).map_or(PART_BYTES, |left| left.min(PART_BYTES));
            let mut sealed = vec![0; take];
            self.rows.read_exact(&mut sealed)?;
            self.left -= take as u64;
            let part = CarrierPart {
                index: self.next,
                count: self.count,
            };
            self.opened = self
                .carrier
                .open(self.leaf, Some(part), &sealed)
                .map_err(|_| io::Error::other("a custody input part did not open"))?;
            self.next += 1;
            self.at = 0;
        }
        let read = out.len().min(self.opened.len() - self.at);
        out[..read].copy_from_slice(&self.opened[self.at..self.at + read]);
        self.at += read;
        Ok(read)
    }
}
