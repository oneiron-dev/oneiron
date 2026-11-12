//! Moved from `crates/oneiron/src/store/body_envelope/frames.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use getrandom::SysRng;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use zeroize::Zeroizing;

/// What one envelope of a file is.
#[derive(Clone, Copy)]
pub enum Role {
    Chunk = 0,
    Last = 1,
    Terminal = 2,
}
