//! Core half of `batch::secret_scan::release_read`: its store-layer items live in `oneiron_store::batch::secret_scan::release_read` and are
//! re-exported here; the items below stay in the engine.
//!
//! The release scan over a body read as it streams (FIX 5392, FIX 3677):
//! what [`super::scan_file_content`] finds in the whole body, read a frame at
//! a time, so a door that copies a body on never holds it whole for its
//! scan. It is the release reading only, whatever the owner's ingest switch
//! says, and never the write door's exhaust policy.
//!
//! Each release text rule is read where it lives: a private-key header on
//! its line, the blocklist anywhere (a window keeps the longest entry's
//! length), the recovery-phrase rule over the whole text, the provider rule
//! in each token, and the assignment rule in each segment (the text between
//! `\n`, `\r`, `,`, `;`, `{` and `}`). The text is the body read as the
//! whole scan reads it, lossy UTF-8, a sequence an edge cuts carried to the
//! next frame. The reason is the one the whole scan names: its rules in
//! their order. A container, whose walk reads its members, and a framed
//! carrier, whose body is decoded whole, are read whole and judged as the
//! whole scan judges them (FIX 7199). No size skips a body or refuses it
//! (Rule 5).
//!
//! FIX 7200: the reader holds no segment and no token whole, so a body that
//! is one long segment is not held whole either. The blocklist reads each
//! frame. A token keeps only the window its rules read ([`tokens`]). A
//! segment keeps small states, not its text ([`assignment`]). Each rule
//! decides where the whole rule decides, and only memory differs.

mod assignment;
mod tokens;

pub(crate) use oneiron_store::batch::secret_scan::release_read::*;

use std::io::{Read, Seek, SeekFrom};

use self::assignment::AssignmentSegment;
use self::tokens::ProviderTokens;
use super::shapes::{self, MnemonicStream, SEGMENT_BREAKS};
use super::{REASON_MNEMONIC, REASON_PRIVATE_KEY, framed_payload, is_container};
use crate::error::Result;

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
    /// The end of the text the blocklist read, where an entry the next
    /// frame ends could start.
    tail: String,
    /// How much of that end is kept: one byte short of the longest entry.
    keep: usize,
    header: HeaderLine,
    phrases: MnemonicStream,
    tokens: ProviderTokens,
    segment: AssignmentSegment,
    private_key: bool,
    blocklisted: bool,
    phrase: bool,
    assignment: bool,
}

impl TextScan {
    fn new() -> Self {
        Self {
            carry: Vec::new(),
            tail: String::new(),
            keep: shapes::blocklist_longest().saturating_sub(1),
            header: HeaderLine::default(),
            phrases: MnemonicStream::default(),
            tokens: ProviderTokens::default(),
            segment: AssignmentSegment::default(),
            private_key: false,
            blocklisted: false,
            phrase: false,
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

    /// Reads `text` on: the line, blocklist and whole-text rules over it as
    /// it passes, then the token and segment rules a character at a time.
    fn feed_text(&mut self, text: &str) {
        self.private_key |= self.header.feed(text.as_bytes());
        self.phrase |= self.phrases.feed(text);
        self.blocklist(text);
        if self.tokens.found().is_some() && self.assignment {
            return;
        }
        for ch in text.chars() {
            self.tokens.feed(ch);
            if self.assignment {
                continue;
            }
            if SEGMENT_BREAKS.contains(&ch) {
                self.assignment = self.segment.finish();
            } else {
                self.segment.feed(ch);
            }
        }
    }

    /// The blocklist over `text` and the end of the text before it, so an
    /// entry a frame edge cuts is read whole.
    fn blocklist(&mut self, text: &str) {
        if self.blocklisted {
            return;
        }
        let joined = format!("{}{text}", self.tail);
        self.blocklisted = shapes::blocklisted(&joined);
        let mut start = joined.len().saturating_sub(self.keep);
        while !joined.is_char_boundary(start) {
            start -= 1;
        }
        self.tail = joined[start..].to_owned();
    }

    /// Reads the end of the text: a sequence it ends inside is one
    /// replacement character, and the last token and segment end with it.
    /// The hit is the whole scan's, its rules in its order.
    fn finish(mut self) -> Option<&'static str> {
        if !self.carry.is_empty() {
            self.carry.clear();
            self.feed_text("\u{fffd}");
        }
        self.tokens.end_token();
        self.assignment |= self.segment.finish();
        self.phrase |= self.phrases.finish();
        let provider = self.tokens.found();
        if self.private_key {
            Some(REASON_PRIVATE_KEY)
        } else if self.blocklisted {
            Some("gate.secret_scan.blocklist")
        } else if self.phrase {
            Some(REASON_MNEMONIC)
        } else if provider.is_some() {
            provider
        } else if self.assignment {
            Some("gate.secret_scan.sensitive_env")
        } else {
            None
        }
    }
}
