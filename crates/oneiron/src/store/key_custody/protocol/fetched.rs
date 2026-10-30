//! A lineage's custody as its residence home holds it, read with the kit
//! (FIX 5846): the page the home's kit door serves, and the source a
//! restore on a new host reads in place of the folder beside the backup.
//!
//! The home serves the sealed head in slices and then the log frames after
//! a sequence number through the head's, a page at a time, each page read
//! under the lineage's lock so its head and frames are one pair. A page that
//! is not the last names its cursor: the head offset and the last sequence
//! number it reached. The fetched bytes are never trusted here: the restore
//! opens the head and chains the frames through the validator it runs on
//! the folder's.

use std::collections::BTreeMap;

use crate::error::Result;

use super::{CustodySource, Lineage};

/// Where the next page of a home's custody starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyHomeCursor {
    /// The head's bytes the next page starts at.
    pub head_offset: u64,
    /// The last log sequence number the pages before reached: the next page
    /// holds the frames after it.
    pub after_seq: u64,
}

/// One page of a lineage's custody as its residence home holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyHomePage {
    /// The BLAKE3 of the whole head the page was read with.
    pub head_object_id: [u8; 32],
    /// The whole head's length in bytes.
    pub head_len: u64,
    /// The log sequence number the head's position names.
    pub head_seq: u64,
    /// Where the page's slice of the head starts.
    pub head_offset: u64,
    /// The head's bytes from `head_offset`; empty once the head is whole.
    pub head_part: Vec<u8>,
    /// Log frames after the cursor's sequence number, in order, through the
    /// head's at most: each with its sequence number.
    pub frames: Vec<(u64, Vec<u8>)>,
    /// Where the next page starts; `None` on the last, and where the home
    /// lacks the next frame.
    pub next: Option<CustodyHomeCursor>,
}

/// A lineage's sealed head and log frames fetched from its residence home
/// (FIX 5846), read by a restore in place of the folder beside the backup:
/// a head or frame it does not hold is missing, never read elsewhere.
pub struct FetchedCustodySource {
    lineage: Lineage,
    head: Vec<u8>,
    frames: BTreeMap<u64, Vec<u8>>,
}

impl FetchedCustodySource {
    /// `lineage`'s `head` and its `frames` by log sequence number, as fetched.
    #[must_use]
    pub fn new(lineage: Lineage, head: Vec<u8>, frames: BTreeMap<u64, Vec<u8>>) -> Self {
        Self {
            lineage,
            head,
            frames,
        }
    }
}

impl CustodySource for FetchedCustodySource {
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>> {
        Ok((lineage == self.lineage).then(|| self.head.clone()))
    }

    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .frames
            .get(&seq)
            .filter(|_| lineage == self.lineage)
            .cloned())
    }
}
