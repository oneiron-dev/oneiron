//! The streaming JSON check behind a callable skill's answer (FIX 10149).
//!
//! The spooled answer is read in fixed chunks and judged against its return
//! contract as the bytes pass, so no string, key or number is ever held
//! whole: a string streams through a UTF-8 and escape check, and a key is
//! matched against the contract's own field names byte by byte. Nesting
//! keeps its own stack, so no depth refuses an answer. Every buffer the check
//! keeps (its read chunk, its stack and each object's field table) is held on
//! the caller's result-memory share until the check ends. A share that cannot
//! give a step asks its row's question and the check reads on: nothing
//! refuses an answer for its size.

use std::io::Read;

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::limit_ask::LimitWatch;
use crate::result_memory::{ResultHold, ResultShare};

/// How many answer bytes one read takes from the spool, and the step the
/// check's holds grow by. A processing chunk, never a maximum on the answer
/// (CALL).
const ANSWER_CHECK_CHUNK_BYTES: usize = 8 * 1024;

/// The caller's share of the result-memory pool and the rows it asks
/// through: what an answer check holds its buffers on.
#[derive(Clone, Copy)]
pub(crate) struct AnswerMemory<'m> {
    pub(crate) share: &'m ResultShare,
    pub(crate) watch: &'m LimitWatch,
}

/// Reads `reader` once to its end, judging it against `shape` as
/// `matches_shape` judges a parsed value: the SHA-256 of every byte when it
/// is JSON within the contract, `None` when it is JSON outside it. Bytes that
/// are no JSON are an error.
pub(super) fn check_answer(
    reader: impl Read,
    shape: &JsonValue,
    memory: Option<AnswerMemory<'_>>,
) -> crate::Result<Option<[u8; 32]>> {
    let mut holds = Holds {
        memory,
        covered: 0,
        holds: Vec::new(),
    };
    holds.cover(ANSWER_CHECK_CHUNK_BYTES);
    let mut checker = Checker {
        input: Input {
            inner: reader,
            chunk: vec![0; ANSWER_CHECK_CHUNK_BYTES],
            at: 0,
            end: 0,
            digest: Sha256::new(),
        },
        stack: Vec::new(),
        tables: 0,
        holds,
    };
    match checker.run(shape) {
        Ok(matched) => {
            let digest: [u8; 32] = checker.input.digest.finalize().into();
            Ok(matched.then_some(digest))
        }
        Err(Fault::Io(error)) => Err(error.into()),
        Err(Fault::Syntax) => Err(super::invalid("callable skill returned non-JSON output")),
    }
}

enum Fault {
    Io(std::io::Error),
    Syntax,
}

impl From<std::io::Error> for Fault {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

type Step<T> = std::result::Result<T, Fault>;

/// What the check holds on the caller's share, grown in chunk steps and
/// given back when the check ends.
struct Holds<'m> {
    memory: Option<AnswerMemory<'m>>,
    /// The bytes the check has asked its share for, held or not.
    covered: usize,
    holds: Vec<ResultHold>,
}

impl Holds<'_> {
    fn cover(&mut self, bytes: usize) {
        let Some(memory) = self.memory else {
            return;
        };
        if bytes <= self.covered {
            return;
        }
        let step = (bytes - self.covered).max(ANSWER_CHECK_CHUNK_BYTES);
        // Past the share the watch asks the row's question and nothing is
        // held; the check reads on either way.
        if let Some(hold) = memory.share.hold(step as u64, memory.watch) {
            self.holds.push(hold);
        }
        self.covered = self.covered.saturating_add(step);
    }
}

/// The spooled answer, read a chunk at a time and digested as it is read.
struct Input<R> {
    inner: R,
    chunk: Vec<u8>,
    at: usize,
    end: usize,
    digest: Sha256,
}

impl<R: Read> Input<R> {
    fn peek(&mut self) -> Step<Option<u8>> {
        if self.at == self.end {
            self.end = loop {
                match self.inner.read(&mut self.chunk) {
                    Ok(read) => break read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            };
            self.at = 0;
            self.digest.update(&self.chunk[..self.end]);
            if self.end == 0 {
                return Ok(None);
            }
        }
        Ok(Some(self.chunk[self.at]))
    }

    fn next(&mut self) -> Step<Option<u8>> {
        let byte = self.peek()?;
        if byte.is_some() {
            self.at += 1;
        }
        Ok(byte)
    }

    fn byte(&mut self) -> Step<u8> {
        self.next()?.ok_or(Fault::Syntax)
    }

    fn skip_space(&mut self) -> Step<()> {
        while matches!(self.peek()?, Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
        Ok(())
    }

    /// The first byte after any space.
    fn token(&mut self) -> Step<u8> {
        self.skip_space()?;
        self.byte()
    }

    fn literal(&mut self, rest: &[u8]) -> Step<()> {
        for expected in rest {
            if self.byte()? != *expected {
                return Err(Fault::Syntax);
            }
        }
        Ok(())
    }

    /// One number after its first byte; whether it reads as an integer, as
    /// the parser that judged answers before read one (`-0`, a fraction, an
    /// exponent or a value past 64 bits is not).
    fn number(&mut self, first: u8) -> Step<bool> {
        let negative = first == b'-';
        let lead = if negative { self.byte()? } else { first };
        let mut significand = match lead {
            b'0' => {
                if matches!(self.peek()?, Some(b'0'..=b'9')) {
                    return Err(Fault::Syntax);
                }
                Some(0_u64)
            }
            b'1'..=b'9' => Some(u64::from(lead - b'0')),
            _ => return Err(Fault::Syntax),
        };
        while let Some(digit @ b'0'..=b'9') = self.peek()? {
            self.at += 1;
            significand = significand
                .and_then(|value| value.checked_mul(10))
                .and_then(|value| value.checked_add(u64::from(digit - b'0')));
        }
        let mut integer = significand.is_some();
        if self.peek()? == Some(b'.') {
            self.at += 1;
            self.digits()?;
            integer = false;
        }
        if matches!(self.peek()?, Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek()?, Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.digits()?;
            integer = false;
        }
        if negative {
            integer &= significand.is_some_and(|value| (1..=(1 << 63)).contains(&value));
        }
        Ok(integer)
    }

    /// One or more digits.
    fn digits(&mut self) -> Step<()> {
        if !matches!(self.byte()?, b'0'..=b'9') {
            return Err(Fault::Syntax);
        }
        while matches!(self.peek()?, Some(b'0'..=b'9')) {
            self.at += 1;
        }
        Ok(())
    }

    /// One string after its opening quote, its decoded bytes handed to
    /// `text` as they pass. A `strict` string is checked as text (UTF-8 and
    /// paired surrogate escapes), as a judged value or key is; one read
    /// through is checked for its grammar only.
    fn string(&mut self, strict: bool, mut text: impl FnMut(&[u8])) -> Step<()> {
        let mut utf8 = Utf8::default();
        loop {
            let byte = self.byte()?;
            if utf8.pending > 0 {
                if !(utf8.low..=utf8.high).contains(&byte) {
                    return Err(Fault::Syntax);
                }
                utf8.pending -= 1;
                (utf8.low, utf8.high) = (0x80, 0xBF);
                text(&[byte]);
                continue;
            }
            match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    if let Some(decoded) = self.escape(strict)? {
                        text(decoded.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                }
                0x00..=0x1F => return Err(Fault::Syntax),
                0x80..=0xFF if strict => {
                    utf8.lead(byte)?;
                    text(&[byte]);
                }
                _ => text(&[byte]),
            }
        }
    }

    /// One escape after its backslash, decoded when `strict`.
    fn escape(&mut self, strict: bool) -> Step<Option<char>> {
        let decoded = match self.byte()? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex4()?;
                if !strict {
                    return Ok(None);
                }
                let point = match unit {
                    0xDC00..=0xDFFF => return Err(Fault::Syntax),
                    0xD800..=0xDBFF => {
                        self.literal(b"\\u")?;
                        let low = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return Err(Fault::Syntax);
                        }
                        0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                    }
                    _ => unit,
                };
                char::from_u32(point).ok_or(Fault::Syntax)?
            }
            _ => return Err(Fault::Syntax),
        };
        Ok(Some(decoded))
    }

    fn hex4(&mut self) -> Step<u32> {
        let mut unit = 0;
        for _ in 0..4 {
            let digit = char::from(self.byte()?).to_digit(16).ok_or(Fault::Syntax)?;
            unit = unit * 16 + digit;
        }
        Ok(unit)
    }

    /// One object key after any space, then its colon: the index of the
    /// contract field it names, when `names` is the object's field table.
    fn key(
        &mut self,
        first: Option<u8>,
        strict: bool,
        names: Option<&[(&str, &JsonValue)]>,
    ) -> Step<Option<usize>> {
        let quote = match first {
            Some(byte) => byte,
            None => self.token()?,
        };
        if quote != b'"' {
            return Err(Fault::Syntax);
        }
        let mut prefix = names.map(|names| Prefix {
            low: 0,
            high: names.len(),
            len: 0,
        });
        self.string(strict, |bytes| {
            if let (Some(prefix), Some(names)) = (prefix.as_mut(), names) {
                for byte in bytes {
                    prefix.feed(names, *byte);
                }
            }
        })?;
        if self.token()? != b':' {
            return Err(Fault::Syntax);
        }
        Ok(prefix
            .zip(names)
            .and_then(|(prefix, names)| prefix.found(names)))
    }
}

/// The continuation bytes a UTF-8 sequence still owes, and the range the
/// next one must fall in.
#[derive(Default)]
struct Utf8 {
    pending: u8,
    low: u8,
    high: u8,
}

impl Utf8 {
    fn lead(&mut self, byte: u8) -> Step<()> {
        (self.pending, self.low, self.high) = match byte {
            0xC2..=0xDF => (1, 0x80, 0xBF),
            0xE0 => (2, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
            0xED => (2, 0x80, 0x9F),
            0xF0 => (3, 0x90, 0xBF),
            0xF1..=0xF3 => (3, 0x80, 0xBF),
            0xF4 => (3, 0x80, 0x8F),
            _ => return Err(Fault::Syntax),
        };
        Ok(())
    }
}

/// The run of byte-sorted field names that still share a key's bytes so far.
#[derive(Clone, Copy)]
struct Prefix {
    low: usize,
    high: usize,
    len: usize,
}

impl Prefix {
    fn feed(&mut self, names: &[(&str, &JsonValue)], byte: u8) {
        let at = self.len;
        let run = &names[self.low..self.high];
        let start =
            run.partition_point(|(name, _)| name.as_bytes().get(at).is_none_or(|b| *b < byte));
        let end =
            run.partition_point(|(name, _)| name.as_bytes().get(at).is_none_or(|b| *b <= byte));
        self.high = self.low + end;
        self.low += start;
        self.len += 1;
    }

    fn found(self, names: &[(&str, &JsonValue)]) -> Option<usize> {
        (self.low < self.high && names[self.low].0.len() == self.len).then_some(self.low)
    }
}

/// An open array or object.
struct Frame<'s> {
    members: Members<'s>,
    /// Whether everything read in it so far is within its contract.
    matched: bool,
    /// Whether no member has been read yet.
    first: bool,
    /// Whether it is judged against a contract, its keys checked as text,
    /// rather than read through.
    judged: bool,
}

enum Members<'s> {
    /// Each item against one shape; `None` reads it through.
    Array(Option<&'s JsonValue>),
    /// The contract's fields sorted by bytes, which of them were seen, and
    /// how many are still unseen.
    Fields {
        names: Vec<(&'s str, &'s JsonValue)>,
        seen: Vec<bool>,
        unseen: usize,
    },
    /// Any keys, each value read through.
    AnyKeys,
}

impl<'s> Frame<'s> {
    fn object(shape: Option<&'s JsonValue>) -> Self {
        let members = match shape {
            Some(JsonValue::Object(fields)) => {
                let mut names: Vec<(&str, &JsonValue)> = fields
                    .iter()
                    .map(|(name, kind)| (name.as_str(), kind))
                    .collect();
                names.sort_unstable_by(|left, right| left.0.cmp(right.0));
                Members::Fields {
                    seen: vec![false; names.len()],
                    unseen: names.len(),
                    names,
                }
            }
            _ => Members::AnyKeys,
        };
        Self {
            members,
            matched: shape.is_none_or(|shape| shape.is_object() || is_kind(shape, "object")),
            first: true,
            judged: shape.is_some(),
        }
    }

    fn array(shape: Option<&'s JsonValue>) -> Self {
        let item = match shape {
            Some(JsonValue::Array(items)) if items.len() == 1 => Some(&items[0]),
            _ => None,
        };
        Self {
            members: Members::Array(item),
            matched: shape.is_none_or(|shape| item.is_some() || is_kind(shape, "array")),
            first: true,
            judged: shape.is_some(),
        }
    }

    /// The bytes its field table keeps.
    fn table_bytes(&self) -> usize {
        match &self.members {
            Members::Fields { names, seen, .. } => names
                .capacity()
                .saturating_mul(std::mem::size_of::<(&str, &JsonValue)>())
                .saturating_add(seen.capacity()),
            Members::Array(_) | Members::AnyKeys => 0,
        }
    }
}

fn is_kind(shape: &JsonValue, name: &str) -> bool {
    matches!(shape, JsonValue::String(kind) if kind == name)
}

/// Whether a scalar of kind `name` is within `shape`; anything is within a
/// value read through.
fn kind(shape: Option<&JsonValue>, name: &str) -> bool {
    shape.is_none_or(|shape| is_kind(shape, name))
}

struct Checker<'s, 'm, R> {
    input: Input<R>,
    stack: Vec<Frame<'s>>,
    /// The bytes the open frames' field tables keep.
    tables: usize,
    holds: Holds<'m>,
}

impl<'s, R: Read> Checker<'s, '_, R> {
    fn run(&mut self, shape: &'s JsonValue) -> Step<bool> {
        let mut done = self.value(None, Some(shape))?;
        loop {
            if let Some(matched) = done.take() {
                let Some(frame) = self.stack.last_mut() else {
                    // The answer is one value, then only space.
                    self.input.skip_space()?;
                    return match self.input.next()? {
                        None => Ok(matched),
                        Some(_) => Err(Fault::Syntax),
                    };
                };
                frame.matched &= matched;
            }
            done = self.step()?;
        }
    }

    /// The open container reads its next member, or closes.
    fn step(&mut self) -> Step<Option<bool>> {
        let byte = self.input.token()?;
        let frame = self.stack.last_mut().ok_or(Fault::Syntax)?;
        let close = match frame.members {
            Members::Array(_) => b']',
            Members::Fields { .. } | Members::AnyKeys => b'}',
        };
        if byte == close {
            return self.close().map(Some);
        }
        if frame.first {
            frame.first = false;
            self.member(Some(byte))
        } else if byte == b',' {
            self.member(None)
        } else {
            Err(Fault::Syntax)
        }
    }

    /// One member of the open container; `first` is its first byte when the
    /// container already read it.
    fn member(&mut self, first: Option<u8>) -> Step<Option<bool>> {
        let frame = self.stack.last_mut().ok_or(Fault::Syntax)?;
        let (child, value_first) = match &mut frame.members {
            Members::Array(item) => (*item, first),
            Members::Fields {
                names,
                seen,
                unseen,
            } => match self.input.key(first, true, Some(names.as_slice()))? {
                Some(at) => {
                    if !seen[at] {
                        seen[at] = true;
                        *unseen -= 1;
                    }
                    (Some(names[at].1), None)
                }
                None => {
                    // A field outside the contract: the object is outside
                    // it, and the value is still read to its end.
                    frame.matched = false;
                    (None, None)
                }
            },
            Members::AnyKeys => {
                self.input.key(first, frame.judged, None)?;
                (None, None)
            }
        };
        self.value(value_first, child)
    }

    /// One value; `first` is its first byte when already read. A scalar is
    /// judged at once; a container opens a frame and is judged at its close.
    fn value(&mut self, first: Option<u8>, shape: Option<&'s JsonValue>) -> Step<Option<bool>> {
        let byte = match first {
            Some(byte) => byte,
            None => self.input.token()?,
        };
        let matched = match byte {
            b'{' => {
                self.open(Frame::object(shape));
                return Ok(None);
            }
            b'[' => {
                self.open(Frame::array(shape));
                return Ok(None);
            }
            b'"' => {
                self.input.string(shape.is_some(), |_| {})?;
                kind(shape, "string")
            }
            b'-' | b'0'..=b'9' => {
                let integer = self.input.number(byte)?;
                kind(shape, "number") || (integer && kind(shape, "integer"))
            }
            b't' => {
                self.input.literal(b"rue")?;
                kind(shape, "boolean")
            }
            b'f' => {
                self.input.literal(b"alse")?;
                kind(shape, "boolean")
            }
            b'n' => {
                self.input.literal(b"ull")?;
                kind(shape, "null")
            }
            _ => return Err(Fault::Syntax),
        };
        Ok(Some(matched))
    }

    fn open(&mut self, frame: Frame<'s>) {
        self.tables = self.tables.saturating_add(frame.table_bytes());
        self.stack.push(frame);
        let working = ANSWER_CHECK_CHUNK_BYTES
            .saturating_add(
                self.stack
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Frame<'_>>()),
            )
            .saturating_add(self.tables);
        self.holds.cover(working);
    }

    fn close(&mut self) -> Step<bool> {
        let frame = self.stack.pop().ok_or(Fault::Syntax)?;
        self.tables = self.tables.saturating_sub(frame.table_bytes());
        Ok(match frame.members {
            Members::Fields { unseen, .. } => frame.matched && unseen == 0,
            Members::Array(_) | Members::AnyKeys => frame.matched,
        })
    }
}
