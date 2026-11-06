//! The release scan over a body read as it streams (FIX 5392, FIX 3677):
//! what [`super::scan_file_content`] finds in the whole body, read a frame at
//! a time, so a door that copies a body on never holds it whole for its
//! scan. It is the release reading only, whatever the owner's ingest switch
//! says, and never the write door's exhaust policy.
//!
//! Each release text rule is read where it lives: a private-key header on
//! its line, the blocklist anywhere (a window keeps the longest entry's
//! length), the recovery-phrase rule over the whole text, and the provider
//! tokens and credential assignments inside a segment (the text between
//! `\n`, `\r`, `,`, `;`, `{` and `}`), which no token or assignment crosses.
//! The text is the body read as the whole scan reads it, lossy UTF-8, a
//! sequence an edge cuts carried to the next frame. The reason is the one
//! the whole scan names: its rules in their order. A container, whose walk
//! reads its members, and a framed carrier, whose body is decoded whole, are
//! read whole and judged as the whole scan judges them. No size skips a
//! body or refuses it (Rule 5).

use std::io::{Read, Seek, SeekFrom};

use crate::batch::secret_scan::container::is_container;
use oneiron_base::error::Result;

/// The head a container's or a framed carrier's leading bytes are read
/// from: the longest of them, a carrier's magic and its two ids, fits.
pub const HEAD_BYTES: u64 = 64;

/// The release private-key rule as the text streams: the first `-----BEGIN
/// ` of a line, then whether `PRIVATE KEY` comes before the first `-----`
/// after it, as [`shapes::private_key_header`] reads each line.
#[derive(Default)]
pub struct HeaderLine {
    /// How much of `-----BEGIN ` the line ends in, before it is found.
    pub begin: usize,
    /// Inside the marker after it: the run of `-` the text ends in and how
    /// much of `PRIVATE KEY` it ends in, or whether that was found.
    pub marker: Option<(usize, usize, bool)>,
    /// The line's marker is closed: nothing else on the line counts.
    pub closed: bool,
}

const BEGIN: &[u8] = b"-----BEGIN ";
const PRIVATE_KEY: &[u8] = b"PRIVATE KEY";

impl HeaderLine {
    /// Reads `bytes` on; `true` once a line holds a private-key header.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        for &byte in bytes {
            if byte == b'\n' {
                *self = Self::default();
                continue;
            }
            if self.closed {
                continue;
            }
            if self.marker.is_none() {
                self.begin = advance(BEGIN, self.begin, byte);
                if self.begin == BEGIN.len() {
                    self.marker = Some((0, 0, false));
                }
                continue;
            }
            let Some((dashes, key, found)) = &mut self.marker else {
                continue;
            };
            *dashes = if byte == b'-' { *dashes + 1 } else { 0 };
            if *dashes == 5 {
                if *found {
                    return true;
                }
                self.closed = true;
                continue;
            }
            if !*found {
                *key = advance(PRIVATE_KEY, *key, byte);
                *found = *key == PRIVATE_KEY.len();
            }
        }
        false
    }
}

/// How much of `pattern` the text ends in once `byte` follows a text that
/// ended in its first `matched` bytes. After a whole match the next byte
/// is read on from the pattern's longest border.
pub fn advance(pattern: &[u8], matched: usize, byte: u8) -> usize {
    let mut matched = matched;
    loop {
        if pattern.get(matched) == Some(&byte) {
            return matched + 1;
        }
        if matched == 0 {
            return 0;
        }
        matched = (1..matched)
            .rev()
            .find(|&len| pattern[..len] == pattern[matched - len..matched])
            .unwrap_or(0);
    }
}
