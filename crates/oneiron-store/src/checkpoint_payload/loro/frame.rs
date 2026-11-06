//! A Loro row's content as the shared projection frames it: the framing
//! version, the family, the slice, each hole's address and the no-one
//! history, every length a u32be.

use ::loro::IdSpan;

use crate::checkpoint_payload::loro::Atom;
use crate::checkpoint_payload::loro::Slice;
use oneiron_base::error::Result;

/// The content framing's version.
pub const FRAME_VERSION: u8 = 1;
pub const SNAPSHOT: u8 = 0;
pub const UPDATES: u8 = 1;

/// A row's content, read back.
pub struct Frame {
    pub slice: Slice,
    pub holes: Vec<String>,
    pub history: Vec<u8>,
}
