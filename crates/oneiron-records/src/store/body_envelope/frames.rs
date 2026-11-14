//! Moved from `crates/oneiron/src/store/body_envelope/frames.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use getrandom::SysRng;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The format version a file's head, its chunks and its key row carry.
pub const FORMAT_VERSION: u16 = 1;
