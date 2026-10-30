//! A custody input as its door keeps it, with the digest its request names
//! (FIX 12177). A frame read where it lies is read again row by row as it is
//! kept (FIX 11140, `stream`). A surface's input past one row that the door
//! seals in numbered carrier parts (FIX 12148, `carrier_seal`) is read once
//! instead: each row is staged in the door's writer as it is sealed, its
//! digest taken as it is staged, and the input's own digest, which the same
//! input sent again is found by, taken as the input goes by. The staged rows
//! wait under keys of their own until the request that names their digest
//! is recorded; each then moves to its own key with what every kept row
//! carries beside its bytes. None outlives the writer that staged it. Only
//! the row being read is held in memory, and the head row until the input
//! is read through.

use super::{
    INPUTS, InputDigests, InputPart, MAX_PARTS, PART_BYTES, PART_LABEL, RelayedInput, SealedFrame,
    input_digest, part_digest, part_hasher, parts_digest, refused,
};
use crate::Vault;
use crate::error::{Error, Result};

const STAGE_DOMAIN: &[u8] = b"oneiron/custody-input-stage/v1";
const UNSTAGED: &str = "a custody input row its door staged is not in its writer";

/// An input as its door keeps it, with the digest its request names.
pub(crate) enum DoorInput<'a> {
    /// Read where it lies, its digest taken; read again row by row as it
    /// is kept.
    Frame(SealedFrame<'a>, InputDigests),
    /// Read once into rows staged in the door's writer (FIX 12177).
    Staged(DoorRows),
}

impl<'a> DoorInput<'a> {
    /// `frame`, read once for the digest its request names.
    ///
    /// # Errors
    /// A fault reading the input from its file; one past the part list's
    /// bound.
    pub(crate) fn read(frame: SealedFrame<'a>) -> Result<Self> {
        let digests = frame.digests()?;
        Ok(Self::Frame(frame, digests))
    }
}

impl DoorInput<'_> {
    /// The digest the request names of this input.
    pub(crate) fn digest(&self) -> [u8; 32] {
        match self {
            Self::Frame(_, digests) => digests.digest,
            Self::Staged(rows) => rows.digest,
        }
    }

    /// Forgets the rows staged for this input, in `wtxn`, when no request is
    /// recorded for them.
    ///
    /// # Errors
    /// Storage errors.
    pub(crate) fn discard_in_txn(&self, vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
        match self {
            Self::Frame(..) => Ok(()),
            Self::Staged(rows) => {
                for index in 0..rows.count() {
                    INPUTS.delete(&vault.store, wtxn, &stage_key(&rows.stage, index))?;
                }
                Ok(())
            }
        }
    }

    /// Keeps each row of this input in `wtxn` under its own key, in order:
    /// each carries `row`'s sealing second, request and witness beside its
    /// bytes, with its place in the part list when it is one of several, and
    /// `stamp` sets what else it carries before it is kept.
    ///
    /// # Errors
    /// A fault reading the input from its file; a staged row not there;
    /// storage errors.
    pub(super) fn keep_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        row: &RelayedInput,
        mut stamp: impl FnMut(&mut RelayedInput),
    ) -> Result<()> {
        match self {
            Self::Frame(frame, digests) => frame.each_row(row, digests, |mut kept| {
                stamp(&mut kept);
                INPUTS.put(&vault.store, wtxn, &kept.row_key(), &kept.encode())
            }),
            Self::Staged(rows) => {
                for index in 0..rows.count() {
                    let staged = stage_key(&rows.stage, index);
                    let bytes = INPUTS
                        .get(&vault.store, wtxn, &staged)?
                        .ok_or_else(|| Error::InvalidConfig(UNSTAGED.to_owned()))?;
                    INPUTS.delete(&vault.store, wtxn, &staged)?;
                    let mut kept = RelayedInput {
                        sealed_at: row.sealed_at,
                        request: row.request,
                        witness: row.witness.clone(),
                        part: rows.parts.as_ref().map(|digests| InputPart {
                            index,
                            digests: digests.clone(),
                        }),
                        envelope: bytes,
                    };
                    stamp(&mut kept);
                    INPUTS.put(&vault.store, wtxn, &kept.row_key(), &kept.encode())?;
                }
                Ok(())
            }
        }
    }
}

/// The rows a door read an input into once, staged in its writer under
/// keys of their own, and the digest the request names of them.
pub(crate) struct DoorRows {
    /// What every staged row's key is taken from.
    stage: [u8; 32],
    /// The digest the request names of the input.
    digest: [u8; 32],
    /// Every row's digest, in order, when it travels in parts.
    parts: Option<Vec<[u8; 32]>>,
}

impl DoorRows {
    /// How many rows are staged.
    fn count(&self) -> u32 {
        self.parts.as_ref().map_or(1, |digests| {
            u32::try_from(digests.len()).unwrap_or(u32::MAX)
        })
    }
}

/// The key row `index` of the rows staged under `stage` waits under.
fn stage_key(stage: &[u8; 32], index: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STAGE_DOMAIN);
    hasher.update(stage);
    hasher.update(&index.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// The rows of an input of a known length as its door stages them, each
/// digested as it is staged, in any order.
pub(super) struct RowStage {
    stage: [u8; 32],
    /// Every row's digest, by its place.
    digests: Vec<[u8; 32]>,
    /// The digest of an input in one row that does not read as a part, as
    /// [`input_digest`] takes it, once that row is staged.
    whole: Option<[u8; 32]>,
}

impl RowStage {
    /// The rows of an input of `len` bytes, staged under keys taken from
    /// `seed`, unique to the input.
    ///
    /// # Errors
    /// An input past the part list's own bound, as [`SealedFrame::digests`]
    /// refuses.
    pub(super) fn new(seed: &[u8], len: u64) -> Result<Self> {
        let count = usize::try_from(len.div_ceil(PART_BYTES as u64))
            .ok()
            .filter(|count| *count <= MAX_PARTS)
            .ok_or_else(|| {
                refused("the custody input splits into more parts than one part list names")
            })?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(STAGE_DOMAIN);
        hasher.update(seed);
        Ok(Self {
            stage: *hasher.finalize().as_bytes(),
            digests: vec![[0; 32]; count.max(1)],
            whole: None,
        })
    }

    /// Stages `row`, the row at `index`, in `wtxn`, its digest taken.
    ///
    /// # Errors
    /// A place past the input's rows; storage errors.
    pub(super) fn stage_in_txn(
        &mut self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        index: u32,
        row: Vec<u8>,
    ) -> Result<()> {
        let one = self.digests.len() == 1;
        let slot = usize::try_from(index)
            .ok()
            .and_then(|at| self.digests.get_mut(at))
            .ok_or_else(|| Error::InvalidConfig(UNSTAGED.to_owned()))?;
        *slot = part_digest(&row);
        if one && !row.starts_with(PART_LABEL) {
            self.whole = Some(input_digest(&row));
        }
        INPUTS.put(&vault.store, wtxn, &stage_key(&self.stage, index), &row)
    }

    /// The rows staged, with the digest the request names of them, as
    /// [`SealedFrame::digests`] takes it of the same bytes: over their part
    /// list, or of the one row that does not read as a part.
    pub(super) fn finish(self) -> DoorRows {
        match self.whole {
            Some(digest) => DoorRows {
                stage: self.stage,
                digest,
                parts: None,
            },
            None => DoorRows {
                stage: self.stage,
                digest: parts_digest(&self.digests),
                parts: Some(self.digests),
            },
        }
    }
}

/// [`input_digest`] of an input of a known length, taken as its bytes go
/// by in runs of any length (FIX 12177): part by part, each part digested
/// as it is read and none held. An input within one part is held, at most
/// one row, and digested whole.
pub(super) struct StreamedDigest {
    /// The part being read, and how many of its bytes are read.
    part: blake3::Hasher,
    at: usize,
    /// Every part read through, digested.
    digests: Vec<[u8; 32]>,
    /// The input, when it is within one part.
    whole: Option<Vec<u8>>,
}

impl StreamedDigest {
    /// The digest of an input of `len` bytes, none of them read yet.
    pub(super) fn new(len: u64) -> Self {
        Self {
            part: part_hasher(),
            at: 0,
            digests: Vec::new(),
            whole: (len <= PART_BYTES as u64).then(Vec::new),
        }
    }

    /// Takes `bytes`, the next run of the input.
    pub(super) fn update(&mut self, mut bytes: &[u8]) {
        if let Some(whole) = &mut self.whole {
            whole.extend_from_slice(bytes);
            return;
        }
        while !bytes.is_empty() {
            let (now, rest) = bytes.split_at(bytes.len().min(PART_BYTES - self.at));
            self.part.update(now);
            self.at += now.len();
            if self.at == PART_BYTES {
                let part = std::mem::replace(&mut self.part, part_hasher());
                self.digests.push(*part.finalize().as_bytes());
                self.at = 0;
            }
            bytes = rest;
        }
    }

    /// The digest of the input's first part, as [`part_digest`] takes it of
    /// its first [`PART_BYTES`] (FIX 12297): the whole input's when it is
    /// within one part, else that part's once it is read through, or of what
    /// of it is read so far.
    pub(super) fn first_part(&self) -> [u8; 32] {
        match (&self.whole, self.digests.first()) {
            (Some(whole), _) => part_digest(whole),
            (None, Some(first)) => *first,
            (None, None) => *self.part.finalize().as_bytes(),
        }
    }

    /// The digest of the input read through.
    pub(super) fn finish(mut self) -> [u8; 32] {
        if let Some(whole) = &self.whole {
            return input_digest(whole);
        }
        if self.at > 0 {
            self.digests.push(*self.part.finalize().as_bytes());
        }
        parts_digest(&self.digests)
    }
}
