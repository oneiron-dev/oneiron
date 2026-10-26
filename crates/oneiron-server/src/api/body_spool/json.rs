//! One JSON object decoded as it is read, its bulk string members streamed
//! (FIX 7917, Rule 5). Every member but the named bulk ones is copied as it
//! stands and decoded as the route's DTO, with that DTO's own rules for
//! types, duplicates and unknown fields. A bulk member's string is unescaped
//! and checked as UTF-8 as it is read, and each run goes to its sink, so it
//! is never one string in memory. The whole document is checked before the
//! route acts on any of it: a sink that refuses its bytes stops being fed,
//! the rest is still read, and a malformed document is told as one first.

use std::fs::File;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

use base64::Engine as _;
use serde::de::DeserializeOwned;

/// Bytes of base64 text a [`Base64FileSink`] holds before it decodes them.
const BASE64_PIECE: usize = 64 * 1024;

/// The document is not one JSON object its route reads.
#[derive(Debug)]
pub(in crate::api) struct JsonInvalid;

type Decoded<T> = Result<T, JsonInvalid>;

/// Where a bulk member's string goes as it is read.
pub(in crate::api) trait StringSink {
    /// The next run of the string, as UTF-8. `false` once the sink refused
    /// it; it is fed nothing after.
    fn write(&mut self, run: &[u8]) -> bool;
    /// The string's end. `false` when the sink refuses what it was given.
    fn finish(&mut self) -> bool;
}

/// A string member of the object read into a sink, not into the DTO.
pub(in crate::api) struct BulkMember<'a> {
    name: &'static str,
    sink: &'a mut dyn StringSink,
    required: bool,
    seen: bool,
    refused: bool,
}

impl<'a> BulkMember<'a> {
    /// A member the object must carry, as a string.
    pub(in crate::api) fn required(name: &'static str, sink: &'a mut dyn StringSink) -> Self {
        Self {
            name,
            sink,
            required: true,
            seen: false,
            refused: false,
        }
    }

    fn take(&mut self, run: &[u8]) {
        if !self.refused && !self.sink.write(run) {
            self.refused = true;
        }
    }
}

/// Decodes the object `reader` holds to its end: each bulk member's string
/// to its sink, every other member as `T`. A bulk member given twice, given
/// as anything but a string, or missing while required, or anything after
/// the object, is malformed.
pub(super) fn decode_object<T: DeserializeOwned>(
    reader: impl BufRead,
    bulk: &mut [BulkMember<'_>],
) -> Decoded<T> {
    let mut scan = Scanner { reader };
    let mut head = vec![b'{'];
    scan.skip_whitespace()?;
    scan.expect(b'{')?;
    scan.skip_whitespace()?;
    if scan.peek()? == Some(b'}') {
        scan.bump();
    } else {
        loop {
            scan.skip_whitespace()?;
            scan.expect(b'"')?;
            let mut name = Vec::new();
            scan.string(&mut |run: &[u8]| name.extend_from_slice(run))?;
            let name = String::from_utf8(name).map_err(|_| JsonInvalid)?;
            scan.skip_whitespace()?;
            scan.expect(b':')?;
            scan.skip_whitespace()?;
            if let Some(member) = bulk.iter_mut().find(|member| member.name == name) {
                if member.seen {
                    return Err(JsonInvalid);
                }
                member.seen = true;
                scan.expect(b'"')?;
                scan.string(&mut |run: &[u8]| member.take(run))?;
                if !member.refused && !member.sink.finish() {
                    member.refused = true;
                }
            } else {
                if head.len() > 1 {
                    head.push(b',');
                }
                head.extend_from_slice(
                    serde_json::to_string(&name)
                        .map_err(|_| JsonInvalid)?
                        .as_bytes(),
                );
                head.push(b':');
                scan.copy_value(&mut head)?;
            }
            scan.skip_whitespace()?;
            match scan.next()? {
                Some(b',') => {}
                Some(b'}') => break,
                _ => return Err(JsonInvalid),
            }
        }
    }
    scan.skip_whitespace()?;
    if scan.peek()?.is_some() {
        return Err(JsonInvalid);
    }
    if bulk.iter().any(|member| member.required && !member.seen) {
        return Err(JsonInvalid);
    }
    head.push(b'}');
    serde_json::from_slice(&head).map_err(|_| JsonInvalid)
}

/// The document as bytes, read one at a time over its buffer.
struct Scanner<R> {
    reader: R,
}

impl<R: BufRead> Scanner<R> {
    fn peek(&mut self) -> Decoded<Option<u8>> {
        let buffer = self.reader.fill_buf().map_err(|_| JsonInvalid)?;
        Ok(buffer.first().copied())
    }

    fn bump(&mut self) {
        self.reader.consume(1);
    }

    fn next(&mut self) -> Decoded<Option<u8>> {
        let byte = self.peek()?;
        if byte.is_some() {
            self.bump();
        }
        Ok(byte)
    }

    fn expect(&mut self, byte: u8) -> Decoded<()> {
        if self.next()? == Some(byte) {
            Ok(())
        } else {
            Err(JsonInvalid)
        }
    }

    fn skip_whitespace(&mut self) -> Decoded<()> {
        while let Some(byte) = self.peek()? {
            if !matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                break;
            }
            self.bump();
        }
        Ok(())
    }

    /// A string's content, after its opening quote, to its closing quote:
    /// unescaped, checked as UTF-8, and handed to `emit` run by run.
    fn string(&mut self, emit: &mut dyn FnMut(&[u8])) -> Decoded<()> {
        let mut text = Utf8Runs::default();
        loop {
            let (run, stop) = {
                let buffer = self.reader.fill_buf().map_err(|_| JsonInvalid)?;
                if buffer.is_empty() {
                    return Err(JsonInvalid);
                }
                let run = buffer
                    .iter()
                    .position(|&byte| byte == b'"' || byte == b'\\' || byte < 0x20)
                    .unwrap_or(buffer.len());
                text.feed(&buffer[..run], emit)?;
                (run, buffer.get(run).copied())
            };
            self.reader.consume(run);
            let Some(stop) = stop else {
                continue;
            };
            // A quote or an escape inside a character is not UTF-8.
            text.at_boundary()?;
            self.bump();
            match stop {
                b'"' => return Ok(()),
                b'\\' => self.escape(emit)?,
                _ => return Err(JsonInvalid),
            }
        }
    }

    /// One escape, after its backslash.
    fn escape(&mut self, emit: &mut dyn FnMut(&[u8])) -> Decoded<()> {
        let byte = match self.next()?.ok_or(JsonInvalid)? {
            b'"' => b'"',
            b'\\' => b'\\',
            b'/' => b'/',
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => return self.unicode_escape(emit),
            _ => return Err(JsonInvalid),
        };
        emit(&[byte]);
        Ok(())
    }

    /// A `\u` escape, after its `u`: one code unit, or a surrogate pair.
    fn unicode_escape(&mut self, emit: &mut dyn FnMut(&[u8])) -> Decoded<()> {
        let unit = self.hex_unit()?;
        let code = match unit {
            0xD800..=0xDBFF => {
                self.expect(b'\\')?;
                self.expect(b'u')?;
                let low = self.hex_unit()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(JsonInvalid);
                }
                0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(JsonInvalid),
            unit => u32::from(unit),
        };
        let character = char::from_u32(code).ok_or(JsonInvalid)?;
        emit(character.encode_utf8(&mut [0; 4]).as_bytes());
        Ok(())
    }

    fn hex_unit(&mut self) -> Decoded<u16> {
        let mut unit = 0u16;
        for _ in 0..4 {
            let digit = char::from(self.next()?.ok_or(JsonInvalid)?)
                .to_digit(16)
                .ok_or(JsonInvalid)?;
            unit = (unit << 4) | digit as u16;
        }
        Ok(unit)
    }

    /// One value as it stands, appended to `out`. Only its extent is found
    /// here; the DTO's decode judges what it holds.
    fn copy_value(&mut self, out: &mut Vec<u8>) -> Decoded<()> {
        match self.peek()?.ok_or(JsonInvalid)? {
            b'"' => {
                self.bump();
                out.push(b'"');
                self.copy_string(out)
            }
            b'{' | b'[' => {
                let mut depth = 0usize;
                loop {
                    let byte = self.next()?.ok_or(JsonInvalid)?;
                    out.push(byte);
                    match byte {
                        b'"' => self.copy_string(out)?,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                return Ok(());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                while let Some(byte) = self.peek()? {
                    if matches!(byte, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t') {
                        break;
                    }
                    out.push(byte);
                    self.bump();
                }
                Ok(())
            }
        }
    }

    /// A string as it stands, after its opening quote, through its closing
    /// quote.
    fn copy_string(&mut self, out: &mut Vec<u8>) -> Decoded<()> {
        loop {
            let byte = self.next()?.ok_or(JsonInvalid)?;
            out.push(byte);
            match byte {
                b'"' => return Ok(()),
                b'\\' => out.push(self.next()?.ok_or(JsonInvalid)?),
                _ => {}
            }
        }
    }
}

/// A string's raw bytes checked as UTF-8 run by run: a character split
/// across two runs is held until its end arrives.
#[derive(Default)]
struct Utf8Runs {
    held: [u8; 4],
    len: usize,
}

impl Utf8Runs {
    fn feed(&mut self, mut run: &[u8], emit: &mut dyn FnMut(&[u8])) -> Decoded<()> {
        if self.len > 0 {
            let width = utf8_width(self.held[0]).ok_or(JsonInvalid)?;
            let take = (width - self.len).min(run.len());
            self.held[self.len..self.len + take].copy_from_slice(&run[..take]);
            self.len += take;
            run = &run[take..];
            if self.len < width {
                return Ok(());
            }
            std::str::from_utf8(&self.held[..width]).map_err(|_| JsonInvalid)?;
            emit(&self.held[..width]);
            self.len = 0;
        }
        match std::str::from_utf8(run) {
            Ok(_) => {
                if !run.is_empty() {
                    emit(run);
                }
            }
            Err(error) if error.error_len().is_none() => {
                let (whole, rest) = run.split_at(error.valid_up_to());
                if !whole.is_empty() {
                    emit(whole);
                }
                self.held[..rest.len()].copy_from_slice(rest);
                self.len = rest.len();
            }
            Err(_) => return Err(JsonInvalid),
        }
        Ok(())
    }

    fn at_boundary(&self) -> Decoded<()> {
        if self.len == 0 {
            Ok(())
        } else {
            Err(JsonInvalid)
        }
    }
}

fn utf8_width(lead: u8) -> Option<usize> {
    match lead {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// How a bulk member's bytes failed to land.
#[derive(Debug)]
pub(in crate::api) enum SinkRefusal {
    /// The string is not standard base64.
    NotBase64,
    /// The vault's disk refused a write for want of room.
    NoRoom,
    /// Its file could not be written or read.
    Failed,
}

/// A bulk member's decoded bytes whole in an anonymous file, read from its
/// start.
pub(in crate::api) struct SpooledField {
    file: File,
    len: u64,
}

impl SpooledField {
    /// The field's bytes in one buffer, for a door that takes a slice.
    pub(in crate::api) fn read_all(mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(usize::try_from(self.len).unwrap_or(0));
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

/// A standard base64 string, decoded into an anonymous file as it is read,
/// with the same rules a whole decode keeps: padding only at the end, and
/// canonical.
pub(in crate::api) struct Base64FileSink {
    file: File,
    text: Vec<u8>,
    len: u64,
    refusal: Option<SinkRefusal>,
}

impl Base64FileSink {
    pub(in crate::api) fn new(file: File) -> Self {
        Self {
            file,
            text: Vec::new(),
            len: 0,
            refusal: None,
        }
    }

    /// The decoded field, or why it did not land.
    pub(in crate::api) fn into_field(mut self) -> Result<SpooledField, SinkRefusal> {
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| SinkRefusal::Failed)?;
        Ok(SpooledField {
            file: self.file,
            len: self.len,
        })
    }

    /// Decodes `text` and writes it; `false` with the refusal kept.
    fn land(&mut self, text_len: usize, last: bool) -> bool {
        let text = &self.text[..text_len];
        if !last && text.contains(&b'=') {
            self.refusal = Some(SinkRefusal::NotBase64);
            return false;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text) else {
            self.refusal = Some(SinkRefusal::NotBase64);
            return false;
        };
        if let Err(error) = self.file.write_all(&bytes) {
            self.refusal = Some(if error.kind() == io::ErrorKind::StorageFull {
                SinkRefusal::NoRoom
            } else {
                SinkRefusal::Failed
            });
            return false;
        }
        self.len = self.len.saturating_add(bytes.len() as u64);
        self.text.drain(..text_len);
        true
    }
}

impl StringSink for Base64FileSink {
    fn write(&mut self, run: &[u8]) -> bool {
        self.text.extend_from_slice(run);
        if self.text.len() < BASE64_PIECE {
            return true;
        }
        // Whole quads only, and never the last one: padding may close it.
        let quads = (self.text.len() / 4).saturating_sub(1);
        self.land(quads * 4, false)
    }

    fn finish(&mut self) -> bool {
        let len = self.text.len();
        self.land(len, true)
    }
}
