//! PDF structural tokens. Never use a non-match as evidence of absence.
//!
//! Nesting of any depth is lexed whole (Rule 5): literal strings and stream
//! dictionaries are loops, and a skipped value keeps its open arrays and
//! dictionaries on an explicit stack, never the call stack. The deepest
//! nesting a lexer met and the tokens it took go to the running analysis's
//! counts for the `[limits]` rows.

use std::ops::Range;

use crate::api::{Counter, note_current};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Word,
    Name,
    DictStart,
    DictEnd,
    Delimiter,
}
#[derive(Debug, Clone)]
pub(super) struct Token<'a> {
    pub(super) kind: Kind,
    pub(super) value: &'a [u8],
    pub(super) span: Range<usize>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LexError {
    Malformed,
}

pub(super) fn space(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}
fn delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// A single grammar for comments, strings and dictionaries. The caller owns
/// stream provenance and skips exactly its validated length-delimited span.
/// It counts the tokens it reads and the deepest nesting it meets, never
/// stopping at either; dropping it notes that depth.
pub(super) struct PdfLexer<'a> {
    bytes: &'a [u8],
    pub(super) at: usize,
    work: usize,
    depth: usize,
}
impl<'a> PdfLexer<'a> {
    pub(super) fn new(bytes: &'a [u8], at: usize) -> Self {
        Self {
            bytes,
            at,
            work: 0,
            depth: 0,
        }
    }
    pub(super) fn work(&self) -> usize {
        self.work
    }
    /// Records nesting `depth` if it is the deepest yet.
    fn deepen(&mut self, depth: usize) {
        self.depth = self.depth.max(depth);
    }
    pub(super) fn skip_to(&mut self, end: usize) -> Result<(), LexError> {
        if end < self.at || end > self.bytes.len() {
            return Err(LexError::Malformed);
        }
        self.at = end;
        Ok(())
    }
    pub(super) fn next(&mut self) -> Result<Option<Token<'a>>, LexError> {
        let len = self.bytes.len();
        while self.at < len {
            match self.bytes[self.at] {
                b if space(b) => self.at += 1,
                b'%' => {
                    self.at += 1;
                    while self.at < len && !matches!(self.bytes[self.at], b'\r' | b'\n') {
                        self.at += 1;
                    }
                }
                _ => break,
            }
        }
        if self.at >= len {
            return Ok(None);
        }
        self.work = self.work.saturating_add(1);
        let start = self.at;
        let b = self.bytes[start];
        let kind = match b {
            b'(' => {
                self.at += 1;
                let mut depth = 1usize;
                while self.at < len && depth > 0 {
                    match self.bytes[self.at] {
                        b'\\' => {
                            self.at = self.at.checked_add(2).ok_or(LexError::Malformed)?;
                        }
                        b'(' => {
                            depth += 1;
                            self.deepen(depth);
                            self.at += 1;
                        }
                        b')' => {
                            depth -= 1;
                            self.at += 1;
                        }
                        _ => self.at += 1,
                    }
                }
                if depth != 0 || self.at > len {
                    return Err(LexError::Malformed);
                }
                Kind::Delimiter
            }
            b'<' if self.bytes.get(start + 1) == Some(&b'<') => {
                self.at += 2;
                Kind::DictStart
            }
            b'>' if self.bytes.get(start + 1) == Some(&b'>') => {
                self.at += 2;
                Kind::DictEnd
            }
            b'<' => {
                self.at += 1;
                while self.at < len && self.bytes[self.at] != b'>' {
                    self.at += 1;
                }
                if self.at >= len {
                    return Err(LexError::Malformed);
                }
                self.at += 1;
                Kind::Delimiter
            }
            b'/' => {
                self.at += 1;
                while self.at < len
                    && !space(self.bytes[self.at])
                    && !delimiter(self.bytes[self.at])
                {
                    if self.bytes[self.at] == b'#' {
                        let escaped = self
                            .bytes
                            .get(self.at + 1..self.at + 3)
                            .ok_or(LexError::Malformed)?;
                        if !escaped.iter().all(u8::is_ascii_hexdigit) {
                            return Err(LexError::Malformed);
                        }
                        self.at += 3;
                    } else {
                        self.at += 1;
                    }
                }
                Kind::Name
            }
            b if delimiter(b) => {
                self.at += 1;
                Kind::Delimiter
            }
            _ => {
                self.at += 1;
                while self.at < len
                    && !space(self.bytes[self.at])
                    && !delimiter(self.bytes[self.at])
                {
                    self.at += 1;
                }
                Kind::Word
            }
        };
        Ok(Some(Token {
            kind,
            value: &self.bytes[start..self.at],
            span: start..self.at,
        }))
    }
}
impl Drop for PdfLexer<'_> {
    fn drop(&mut self) {
        note_current(Counter::PdfDepth, self.depth);
    }
}

/// The first stream keyword following the dictionary, including LF/CRLF.
pub(super) fn stream_delimiter(header: &[u8]) -> Option<(usize, usize)> {
    let mut lexer = PdfLexer::new(header, 0);
    let mut depth = 0usize;
    let mut seen_dict = false;
    while let Ok(Some(token)) = lexer.next() {
        match token.kind {
            Kind::DictStart => {
                depth += 1;
                lexer.deepen(depth);
                seen_dict = true;
            }
            Kind::DictEnd => depth = depth.checked_sub(1)?,
            Kind::Word if seen_dict && depth == 0 && token.value == b"stream" => {
                let at = token.span.end;
                if header.get(at..at + 2) == Some(b"\r\n") {
                    return Some((token.span.start, at + 2));
                }
                if header.get(at) == Some(&b'\n') {
                    return Some((token.span.start, at + 1));
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

/// Compare a PDF name after decoding its `#HH` escapes. A malformed name
/// is an analysis error, never evidence that the key is absent.
fn name_is(token: &Token<'_>, expected: &[u8]) -> Result<bool, LexError> {
    if token.kind != Kind::Name || !token.value.starts_with(b"/") {
        return Err(LexError::Malformed);
    }
    let mut at = 1;
    let mut decoded = 0;
    let mut equal = true;
    while at < token.value.len() {
        let b = if token.value[at] == b'#' {
            let chars = token.value.get(at + 1..at + 3).ok_or(LexError::Malformed)?;
            let hi = (chars[0] as char).to_digit(16).ok_or(LexError::Malformed)?;
            let lo = (chars[1] as char).to_digit(16).ok_or(LexError::Malformed)?;
            at += 3;
            (hi * 16 + lo) as u8
        } else {
            let b = token.value[at];
            at += 1;
            b
        };
        if expected.get(decoded) != Some(&b) {
            equal = false;
        }
        decoded += 1;
    }
    Ok(equal && decoded == expected.len())
}

/// Skips the value `first` opens, however deeply its arrays and
/// dictionaries nest: each open container waits on an explicit stack
/// (`true` for a dictionary, which reads a key before each value). An
/// indirect reference's three tokens are one value.
fn skip_value<'a>(lexer: &mut PdfLexer<'a>, first: Token<'a>) -> Result<(), LexError> {
    let mut open: Vec<bool> = Vec::new();
    let mut value = first;
    loop {
        match value.kind {
            Kind::DictStart => open.push(true),
            Kind::Delimiter if value.value == b"[" => open.push(false),
            Kind::Word if value.value.iter().all(u8::is_ascii_digit) => {
                // An indirect reference is three tokens: object, generation, R.
                let checkpoint = lexer.at;
                let next = lexer.next()?;
                let end = lexer.next()?;
                if !matches!((&next, &end), (Some(generation), Some(r))
                    if generation.kind == Kind::Word && generation.value.iter().all(u8::is_ascii_digit)
                        && r.kind == Kind::Word && r.value == b"R")
                {
                    lexer.at = checkpoint;
                }
            }
            Kind::DictEnd => return Err(LexError::Malformed),
            Kind::Delimiter if value.value == b"]" => return Err(LexError::Malformed),
            _ => {}
        }
        lexer.deepen(open.len());
        // The next value to skip, past every container that closes first.
        value = loop {
            let Some(&dictionary) = open.last() else {
                return Ok(());
            };
            let next = lexer.next()?.ok_or(LexError::Malformed)?;
            if dictionary {
                if next.kind == Kind::DictEnd {
                    open.pop();
                    continue;
                }
                if next.kind != Kind::Name {
                    return Err(LexError::Malformed);
                }
                break lexer.next()?.ok_or(LexError::Malformed)?;
            }
            if next.kind == Kind::Delimiter && next.value == b"]" {
                open.pop();
                continue;
            }
            break next;
        };
    }
}

/// [`table_prev_work`] without its token count.
#[cfg(test)]
pub(super) fn table_prev(section: &[u8]) -> Result<Option<usize>, LexError> {
    table_prev_work(section).map(|(prev, _)| prev)
}

/// Parse the actual classic-xref trailer dictionary using the same token
/// grammar as object definitions. `None` is proven absence, not a failed
/// spelling match. Nested names/values cannot impersonate its key. The
/// whole section is lexed however long it is (Rule 5); the tokens it took
/// come back beside the offset for the `[limits]` structural-work row.
pub(super) fn table_prev_work(section: &[u8]) -> Result<(Option<usize>, usize), LexError> {
    let mut lexer = PdfLexer::new(section, 0);
    if lexer
        .next()?
        .is_none_or(|t| t.kind != Kind::Word || t.value != b"xref")
    {
        return Err(LexError::Malformed);
    }
    loop {
        let next = lexer.next()?.ok_or(LexError::Malformed)?;
        if next.kind == Kind::Word && next.value == b"trailer" {
            break;
        }
    }
    if lexer.next()?.is_none_or(|t| t.kind != Kind::DictStart) {
        return Err(LexError::Malformed);
    }
    let mut prev = None;
    loop {
        let key = lexer.next()?.ok_or(LexError::Malformed)?;
        if key.kind == Kind::DictEnd {
            break;
        }
        if key.kind != Kind::Name {
            return Err(LexError::Malformed);
        }
        let is_prev = name_is(&key, b"Prev")?;
        let value = lexer.next()?.ok_or(LexError::Malformed)?;
        if is_prev {
            if prev.is_some()
                || value.kind != Kind::Word
                || !value.value.iter().all(u8::is_ascii_digit)
            {
                return Err(LexError::Malformed);
            }
            let offset = std::str::from_utf8(value.value)
                .map_err(|_| LexError::Malformed)?
                .parse::<usize>()
                .map_err(|_| LexError::Malformed)?;
            prev = Some(offset);
        } else {
            skip_value(&mut lexer, value)?;
        }
    }
    Ok((prev, lexer.work()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoded_trailer_names_share_one_linkage_grammar() {
        assert_eq!(
            table_prev(b"xref\ntrailer\n<< /Pr#65v 42 >>").unwrap(),
            Some(42)
        );
        assert_eq!(
            table_prev(b"xref\ntrailer\n<< /ID [/Prev] /Pr#65v 42 >>").unwrap(),
            Some(42)
        );
        assert!(table_prev(b"xref\ntrailer\n<< /Prev 42 /Pr#65v 42 >>").is_err());
        assert!(table_prev(b"xref\ntrailer\n<< /Pr#ZZv 42 >>").is_err());
    }
}
