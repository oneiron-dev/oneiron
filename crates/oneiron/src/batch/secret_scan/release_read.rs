//! Core half of `batch::secret_scan::release_read`: its store-layer items live in `oneiron_store::batch::secret_scan::release_read` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::release_read::*;

use super::shapes::{self, Door, MnemonicStream};
use super::{REASON_MNEMONIC, REASON_PRIVATE_KEY, classify_token, framed_payload, is_container};
use crate::error::Result;
use std::io::{Read, Seek, SeekFrom};

/// The bytes one read of the body takes: a buffer, not a bound on the body.
const FRAME_BYTES: usize = crate::store::LINE_INDEX_BLOCK_BYTES as usize;

/// [`super::scan_file_content`] over the body `source` holds, read from its
/// start ([`scan_file_content_reader`]).
///
/// # Errors
///
/// `source`'s errors.
pub(crate) fn scan_file_content_from<R: Read + Seek>(
    path: &str,
    source: &mut R,
) -> Result<Option<&'static str>> {
    source.seek(SeekFrom::Start(0))?;
    scan_file_content_reader(path, source)
}

/// [`super::scan_file_content`] over the body `source` reads out, read to
/// its end a frame at a time (but past a private-key header, which no other
/// rule outranks).
///
/// # Errors
///
/// `source`'s errors.
pub(crate) fn scan_file_content_reader(
    path: &str,
    source: &mut dyn Read,
) -> Result<Option<&'static str>> {
    let mut head = Vec::new();
    Read::take(&mut *source, HEAD_BYTES).read_to_end(&mut head)?;
    if is_container(&head) || framed_payload(&head).is_some() {
        // The container walk and the carrier's decode read the body whole,
        // as the whole scan does.
        source.read_to_end(&mut head)?;
        return Ok(super::scan_file_content(path, &head));
    }
    let mut text = TextScan::new();
    text.feed_bytes(&head);
    let mut frame = vec![0; FRAME_BYTES];
    while !text.private_key {
        let read = match source.read(&mut frame) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        text.feed_bytes(&frame[..read]);
    }
    Ok(text.finish())
}

/// The release text rules over a body's text as it streams.
struct TextScan {
    /// The bytes of a UTF-8 sequence the last frame ended inside.
    carry: Vec<u8>,
    /// The text of the segment not yet ended.
    pending: String,
    /// The end of the text the segment rules read, where a blocklist entry
    /// the next window ends could start.
    tail: String,
    /// How much of that end is kept: one byte short of the longest entry.
    keep: usize,
    header: HeaderLine,
    phrases: MnemonicStream,
    private_key: bool,
    blocklisted: bool,
    phrase: bool,
    provider: Option<&'static str>,
    assignment: bool,
}

impl TextScan {
    fn new() -> Self {
        Self {
            carry: Vec::new(),
            pending: String::new(),
            tail: String::new(),
            keep: shapes::blocklist_longest().saturating_sub(1),
            header: HeaderLine::default(),
            phrases: MnemonicStream::default(),
            private_key: false,
            blocklisted: false,
            phrase: false,
            provider: None,
            assignment: false,
        }
    }

    /// Reads `bytes` on, as the lossy UTF-8 text the whole scan reads: an
    /// invalid sequence is one replacement character, and one the frame
    /// ends inside waits for the next.
    fn feed_bytes(&mut self, bytes: &[u8]) {
        let mut joined = std::mem::take(&mut self.carry);
        joined.extend_from_slice(bytes);
        let mut text = String::with_capacity(joined.len());
        let mut rest = joined.as_slice();
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    text.push_str(valid);
                    break;
                }
                Err(error) => {
                    let (valid, after) = rest.split_at(error.valid_up_to());
                    text.push_str(std::str::from_utf8(valid).unwrap_or_default());
                    let Some(len) = error.error_len() else {
                        self.carry = after.to_vec();
                        break;
                    };
                    text.push(char::REPLACEMENT_CHARACTER);
                    rest = after.get(len..).unwrap_or_default();
                }
            }
        }
        self.feed_text(&text);
    }

    /// Reads `text` on: the line and whole-text rules as it passes, and the
    /// segment rules over each run of whole segments it ends.
    fn feed_text(&mut self, text: &str) {
        self.private_key |= self.header.feed(text.as_bytes());
        self.phrase |= self.phrases.feed(text);
        let from = self.pending.len();
        self.pending.push_str(text);
        if let Some(at) = self.pending[from..].rfind(SEGMENT_BREAKS) {
            // Each edge is one byte, so the cut is a char boundary.
            let window: String = self.pending.drain(..from + at + 1).collect();
            self.segments(&window);
        }
    }

    /// The segment rules over `window`, whole segments in order.
    fn segments(&mut self, window: &str) {
        if !self.blocklisted {
            let joined = format!("{}{window}", self.tail);
            self.blocklisted = shapes::blocklisted(&joined);
            let mut start = joined.len().saturating_sub(self.keep);
            while !joined.is_char_boundary(start) {
                start -= 1;
            }
            self.tail = joined[start..].to_owned();
        }
        if self.provider.is_none() {
            self.provider = window
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
                .find_map(classify_token);
        }
        if !self.assignment {
            self.assignment = shapes::sensitive_assignment(window, Door::Release);
        }
    }

    /// Reads the end of the text: a sequence it ends inside is one
    /// replacement character, and the last segment ends with it. The hit is
    /// the whole scan's, its rules in its order.
    fn finish(mut self) -> Option<&'static str> {
        if !self.carry.is_empty() {
            self.carry.clear();
            self.feed_text("\u{fffd}");
        }
        let last = std::mem::take(&mut self.pending);
        self.segments(&last);
        self.phrase |= self.phrases.finish();
        if self.private_key {
            Some(REASON_PRIVATE_KEY)
        } else if self.blocklisted {
            Some("gate.secret_scan.blocklist")
        } else if self.phrase {
            Some(REASON_MNEMONIC)
        } else if self.provider.is_some() {
            self.provider
        } else if self.assignment {
            Some("gate.secret_scan.sensitive_env")
        } else {
            None
        }
    }
}
