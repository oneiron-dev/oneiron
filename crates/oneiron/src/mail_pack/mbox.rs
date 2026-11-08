//! An mbox file's messages, one at a time (FIX 12559: mbox and Google
//! Takeout intake). A message starts at a separator line shaped `From <who>
//! <weekday> <month> <day> <time> [<zone>] <year>`, the first line or one
//! after a blank line. A body line escaped as `>From ` reads as `From `
//! again (mboxrd); length-delimited mbox variants are not read. The reader
//! keeps its byte offset, so an import goes on from where the last call
//! stopped, and holds at most one bounded line at a time.

use std::io::{self, BufRead};

/// The largest message read; a larger one is skipped whole.
pub(super) const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// The longest line held; a longer one makes its message too large.
const MAX_LINE_BYTES: usize = 1024 * 1024;
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

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

/// Whether a line is an mbox separator: `From `, a sender word, then a
/// weekday, a month, a day, a clock time and a four-digit year.
fn is_separator(line: &[u8]) -> bool {
    if !line.starts_with(b"From ") {
        return false;
    }
    let text = String::from_utf8_lossy(line);
    let words: Vec<&str> = text.split_whitespace().skip(1).collect();
    let [sender, weekday, month, day, time, ..] = words.as_slice() else {
        return false;
    };
    let clock = |word: &str| {
        word.split(':').count() >= 2
            && word
                .split(':')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    };
    !sender.is_empty()
        && WEEKDAYS.contains(weekday)
        && MONTHS.contains(month)
        && day.len() <= 2
        && day.bytes().all(|byte| byte.is_ascii_digit())
        && clock(time)
        && words
            .last()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()))
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

    /// Reads one line into `line`, at most [`MAX_LINE_BYTES`] of it (the
    /// rest is passed over). Answers whether a line was read, and whether
    /// it was cut.
    fn read_line(&mut self, line: &mut Vec<u8>) -> io::Result<(bool, bool)> {
        line.clear();
        let mut cut = false;
        let mut read_any = false;
        loop {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Ok((read_any, cut));
            }
            read_any = true;
            let (taken, ended) = match available.iter().position(|&byte| byte == b'\n') {
                Some(newline) => (newline + 1, true),
                None => (available.len(), false),
            };
            let room = MAX_LINE_BYTES.saturating_sub(line.len());
            if taken > room {
                cut = true;
            }
            line.extend_from_slice(&available[..taken.min(room)]);
            self.reader.consume(taken);
            self.offset += taken as u64;
            if ended {
                return Ok((true, cut));
            }
        }
    }

    /// The next message, or `None` at the end of the stream.
    pub(super) fn next_message(&mut self) -> io::Result<Option<MboxMessage>> {
        let mut line = Vec::new();
        let separator = match self.pending.take() {
            Some((separator, _)) => separator,
            None => loop {
                let (read, _) = self.read_line(&mut line)?;
                if !read {
                    return Ok(None);
                }
                if is_separator(&line) {
                    break separator_text(&line);
                }
            },
        };
        let mut raw = Vec::new();
        let mut oversized = false;
        let mut previous_blank = true;
        loop {
            let start = self.offset;
            let (read, cut) = self.read_line(&mut line)?;
            if !read {
                break;
            }
            if previous_blank && is_separator(&line) {
                self.pending = Some((separator_text(&line), start));
                break;
            }
            previous_blank = is_blank(&line);
            if cut {
                oversized = true;
            }
            if oversized {
                raw = Vec::new();
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
