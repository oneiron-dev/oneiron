//! One lowercase-hex bulk member decoded into an anonymous file as it is read.
//! The widen accept's `expected_delta` lands here on the large path, so a body
//! of any length never becomes one hex string in memory. Decoding keeps the
//! whole decode's rules: `0-9a-f` only (uppercase never decodes), even length,
//! and the empty string decodes to no bytes. The file's room is the body
//! spool's own stored-copy room, kept by the caller through the last read;
//! this sink claims nothing itself.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use super::json::StringSink;

/// Decoded bytes the sink stages before they flush to the file. Pairs collect
/// in the one fixed stage across input runs and land only when it is full or
/// the string ends: no heap, and short runs never write the file each.
const HEX_STACK_BYTES: usize = 64 * 1024;

/// How a hex member's bytes failed to land.
#[derive(Debug)]
pub(in crate::api) enum HexRefusal {
    /// The string is not even-length lowercase hex.
    InvalidHex,
    /// The vault's disk refused a write for want of room.
    NoRoom,
    /// Its file could not be written or read.
    Failed,
}

/// A hex member's decoded bytes in an anonymous file, read from its start.
pub(in crate::api) struct SpooledHex {
    file: File,
    len: u64,
}

impl SpooledHex {
    /// The field's file and its decoded length, for a door that reads the
    /// bytes where they lie, from the file's start, never as one buffer.
    pub(in crate::api) fn file(&self) -> (&File, u64) {
        (&self.file, self.len)
    }
}

/// A lowercase-hex string decoded into an anonymous file as it is read.
pub(in crate::api) struct HexFileSink {
    file: File,
    staged: [u8; HEX_STACK_BYTES],
    used: usize,
    len: u64,
    carry: Option<u8>,
    refusal: Option<HexRefusal>,
}

impl HexFileSink {
    pub(in crate::api) fn new(file: File) -> Self {
        Self {
            file,
            staged: [0; HEX_STACK_BYTES],
            used: 0,
            len: 0,
            carry: None,
            refusal: None,
        }
    }

    /// The decoded field, or why it did not land.
    pub(in crate::api) fn into_field(mut self) -> Result<SpooledHex, HexRefusal> {
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| HexRefusal::Failed)?;
        Ok(SpooledHex {
            file: self.file,
            len: self.len,
        })
    }

    /// Stages one nibble after the carried one, flushing the stage when it
    /// is full; `false` with the refusal kept.
    fn push(&mut self, nibble: u8) -> bool {
        let Some(high) = self.carry.take() else {
            self.carry = Some(nibble);
            return true;
        };
        if self.used == self.staged.len() && !self.flush() {
            return false;
        }
        self.staged[self.used] = high << 4 | nibble;
        self.used += 1;
        true
    }

    /// Lands the staged bytes; `false` with the refusal kept.
    fn flush(&mut self) -> bool {
        if let Err(error) = self.file.write_all(&self.staged[..self.used]) {
            self.refusal = Some(if error.kind() == std::io::ErrorKind::StorageFull {
                HexRefusal::NoRoom
            } else {
                HexRefusal::Failed
            });
            return false;
        }
        self.len = self.len.saturating_add(self.used as u64);
        self.used = 0;
        true
    }
}

/// One hex digit's value; uppercase is not hex here, as in the whole decode.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl StringSink for HexFileSink {
    fn write(&mut self, run: &[u8]) -> bool {
        for byte in run {
            let Some(nibble) = hex_nibble(*byte) else {
                self.refusal = Some(HexRefusal::InvalidHex);
                return false;
            };
            if !self.push(nibble) {
                return false;
            }
        }
        true
    }

    fn finish(&mut self) -> bool {
        if self.carry.is_some() {
            self.refusal = Some(HexRefusal::InvalidHex);
            return false;
        }
        self.flush()
    }
}
