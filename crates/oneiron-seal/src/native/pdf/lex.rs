//! Bounded PDF structural tokens. Never use a non-match as evidence of absence.

use std::ops::Range;

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
    WorkLimit,
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
pub(super) struct PdfLexer<'a> {
    bytes: &'a [u8],
    pub(super) at: usize,
    work: usize,
    max_work: usize,
}
impl<'a> PdfLexer<'a> {
    pub(super) fn new(bytes: &'a [u8], at: usize, max_work: usize) -> Self {
        Self {
            bytes,
            at,
            work: 0,
            max_work,
        }
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
        self.work += 1;
        if self.work > self.max_work {
            return Err(LexError::WorkLimit);
        }
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
                            self.at += 1;
                        }
                        b')' => {
                            depth -= 1;
                            self.at += 1;
                        }
                        _ => self.at += 1,
                    }
                    if depth > 64 {
                        return Err(LexError::WorkLimit);
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
                    if self.bytes[self.at] == b'#' && self.at + 2 < len {
                        // PDF name escapes are part of a name, not a token boundary.
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

/// The first stream keyword following the dictionary, including LF/CRLF.
pub(super) fn stream_delimiter(header: &[u8]) -> Option<(usize, usize)> {
    let mut lexer = PdfLexer::new(header, 0, header.len());
    let mut depth = 0usize;
    let mut seen_dict = false;
    while let Ok(Some(token)) = lexer.next() {
        match token.kind {
            Kind::DictStart => {
                depth += 1;
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
        if depth > 64 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structural_tokens_exclude_strings_hex_and_comments() {
        let bytes = b"% 99 0 obj\r\n(1 0 obj \\(nested\\)) <312030206F626A> \n1 % legal\r2 % legal\nobj << /Label (3 0 obj) /Hex <342030206F626A> >> endobj";
        let mut lexer = PdfLexer::new(bytes, 0, 200);
        let mut words = Vec::new();
        while let Some(t) = lexer.next().unwrap() {
            if t.kind == Kind::Word {
                words.push(t.value.to_vec());
            }
        }
        assert_eq!(
            words,
            vec![
                b"1".to_vec(),
                b"2".to_vec(),
                b"obj".to_vec(),
                b"endobj".to_vec()
            ]
        );
    }
}
