//! Where [`super::mnemonic`] finds each recovery phrase in `text` (FIX 1099).

use std::ops::Range;

pub struct Seg {
    pub indices: Vec<u16>,
    pub start: usize,
    pub end: usize,
}

