//! An mbox file's messages, one at a time (FIX 12559: mbox and Google
//! Takeout intake). A message starts at a `From ` separator line: the first
//! line, one after a blank line, or one shaped like a separator (`From <who>
//! <date>`). A body line escaped as `>From ` reads as `From ` again (mboxrd).
//! The reader keeps its byte offset, so an import goes on from where the
//! last call stopped.

use std::io::{self, BufRead};

/// The largest message read; a larger one is skipped whole.
pub(super) const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// One message of an mbox file.
#[derive(Debug, Clone)]
pub(super) struct MboxMessage {
    /// Its separator line, without its line break.
    pub(super) separator: String,
    /// The message, separator excluded, `>From ` lines unescaped.
    pub(super) raw: Vec<u8>,
    /// Whether it was larger than [`MAX_MESSAGE_BYTES`]; `raw` is then
    /// empty.
    pub(super) oversized: bool,
}

/// Reads an mbox stream message by message.
pub(super) struct MboxReader<R: BufRead> {
    reader: R,
    /// The stream offset of the next byte read.
    offset: u64,
    /// The next message's separator and its offset, read already.
    pending: Option<(String, u64)>,
}

fn is_blank(line: &[u8]) -> bool {
    line == b"\n" || line == b"\r\n"
}

fn separator_text(line: &[u8]) -> String {
    String::from_utf8_lossy(line)
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

/// Whether a `From ` line has a separator's shape: a sender word, then a
/// date with a clock time and a four-digit year.
fn looks_like_separator(line: &[u8]) -> bool {
    let text = String::from_utf8_lossy(line);
    let mut words = text.split_whitespace().skip(1);
    let Some(sender) = words.next() else {
        return false;
    };
    let rest: Vec<&str> = words.collect();
    !sender.is_empty()
        && rest.iter().any(|word| word.contains(':'))
        && rest
            .iter()
            .any(|word| word.len() == 4 && word.bytes().all(|byte| byte.is_ascii_digit()))
}

/// A body line escaped as `>From ` (any number of `>`) loses one `>`.
fn unescape(line: &[u8]) -> &[u8] {
    let quoted = line.iter().take_while(|&&byte| byte == b'>').count();
    if quoted > 0 && line[quoted..].starts_with(b"From ") {
        &line[1..]
    } else {
        line
    }
}

impl<R: BufRead> MboxReader<R> {
    /// A reader over `reader`, whose first byte is at stream offset
    /// `offset`.
    pub(super) const fn new(reader: R, offset: u64) -> Self {
        Self {
            reader,
            offset,
            pending: None,
        }
    }

    /// The stream offset of the next message: where a later read goes on
    /// from.
    pub(super) fn resume_offset(&self) -> u64 {
        self.pending
            .as_ref()
            .map_or(self.offset, |(_, offset)| *offset)
    }

    /// The next message, or `None` at the end of the stream.
    pub(super) fn next_message(&mut self) -> io::Result<Option<MboxMessage>> {
        let mut line = Vec::new();
        let separator = match self.pending.take() {
            Some((separator, _)) => separator,
            None => loop {
                line.clear();
                let read = self.reader.read_until(b'\n', &mut line)?;
                if read == 0 {
                    return Ok(None);
                }
                self.offset += read as u64;
                if line.starts_with(b"From ") {
                    break separator_text(&line);
                }
            },
        };
        let mut raw = Vec::new();
        let mut oversized = false;
        let mut previous_blank = false;
        loop {
            let start = self.offset;
            line.clear();
            let read = self.reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            self.offset += read as u64;
            if line.starts_with(b"From ") && (previous_blank || looks_like_separator(&line)) {
                self.pending = Some((separator_text(&line), start));
                break;
            }
            previous_blank = is_blank(&line);
            if oversized {
                continue;
            }
            let text = unescape(&line);
            if raw.len() + text.len() > MAX_MESSAGE_BYTES {
                oversized = true;
                raw = Vec::new();
            } else {
                raw.extend_from_slice(text);
            }
        }
        // The blank line before the next separator belongs to the separator.
        if raw.ends_with(b"\r\n\r\n") {
            raw.truncate(raw.len() - 2);
        } else if raw.ends_with(b"\n\n") {
            raw.truncate(raw.len() - 1);
        }
        Ok(Some(MboxMessage {
            separator,
            raw,
            oversized,
        }))
    }
}
