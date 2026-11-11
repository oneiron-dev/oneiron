//! The JSON of removal archive copies, read where it lies (FIX 21529): a
//! delivery session's answer spooled to a file, and a copy the receiver
//! kept. A walk copies the JSON into memory with each copy's archive left
//! out, `""` in its place, and notes where in the file the archive's base64
//! lies; serde reads the rest as it always did, so every rule the copy's
//! types keep still holds. The archive is decoded from the file into a spool
//! file of the vault's own, hashed as it is written, and never held whole.
//! An archive's base64 is read as it is: one that carries a JSON escape
//! does not decode.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use oneiron::federation::{RemovalExportCopy, RemovalExportFile};
use serde::Deserialize;

/// Where a value lies in its file: its first byte and its length.
#[derive(Debug, Clone, Copy)]
pub(super) struct Span {
    start: u64,
    len: u64,
}

/// The longest member name, in raw bytes, a walk decodes to compare: a
/// longer one is none it looks for.
const NAME_MAX: u64 = 64;

/// The buffer the archive's base64 is read through.
const READ_BUFFER: usize = 64 * 1024;

/// A delivery session's answer as serde reads it, each copy's archive
/// empty.
#[derive(Deserialize)]
struct Answer {
    deliveries: Vec<Sent>,
}

#[derive(Deserialize)]
struct Sent {
    version: u64,
    copy: RemovalExportCopy,
}

/// One archive a session sent: its delivery version, its copy with the
/// archive left empty, and where in the answer's file the copy's JSON and
/// the archive's base64 lie.
pub(super) struct Delivery {
    pub(super) version: u64,
    pub(super) copy: RemovalExportCopy,
    pub(super) json: Span,
    pub(super) archive: Span,
}

fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "a removal archive answer is not the JSON it should be",
    )
}

/// A forward walk over JSON read from a file, copying what it passes into
/// `out`.
struct Walk<R> {
    reader: R,
    /// The file offset of the next byte.
    at: u64,
    out: Vec<u8>,
}

impl<R: BufRead> Walk<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            at: 0,
            out: Vec::new(),
        }
    }

    fn peek(&mut self) -> io::Result<u8> {
        self.reader
            .fill_buf()?
            .first()
            .copied()
            .ok_or_else(malformed)
    }

    fn advance(&mut self, len: usize) {
        self.reader.consume(len);
        self.at = self.at.saturating_add(len as u64);
    }

    /// Passes the next byte, copying it.
    fn copy_byte(&mut self) -> io::Result<u8> {
        let byte = self.peek()?;
        self.out.push(byte);
        self.advance(1);
        Ok(byte)
    }

    fn expect(&mut self, byte: u8) -> io::Result<()> {
        if self.copy_byte()? == byte {
            Ok(())
        } else {
            Err(malformed())
        }
    }

    /// Passes the bytes `take` admits, copying them; answers how many.
    fn copy_while(&mut self, take: impl Fn(u8) -> bool) -> io::Result<u64> {
        let mut passed = 0_u64;
        loop {
            let buffered = self.reader.fill_buf()?;
            let len = buffered.iter().take_while(|&&byte| take(byte)).count();
            if len == 0 {
                return Ok(passed);
            }
            self.out
                .extend_from_slice(buffered.get(..len).unwrap_or_default());
            self.advance(len);
            passed = passed.saturating_add(len as u64);
        }
    }

    fn copy_space(&mut self) -> io::Result<()> {
        self.copy_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))?;
        Ok(())
    }

    /// Passes a string's contents, its opening quote passed, up to its
    /// closing quote, copying them when `copy`; answers their length.
    fn pass_contents(&mut self, copy: bool) -> io::Result<u64> {
        let mut passed = 0_u64;
        let mut escaped = false;
        loop {
            let buffered = self.reader.fill_buf()?;
            if buffered.is_empty() {
                return Err(malformed());
            }
            let mut end = None;
            for (at, &byte) in buffered.iter().enumerate() {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    end = Some(at);
                    break;
                }
            }
            let len = end.unwrap_or(buffered.len());
            if copy {
                self.out
                    .extend_from_slice(buffered.get(..len).unwrap_or_default());
            }
            self.advance(len);
            passed = passed.saturating_add(len as u64);
            if end.is_some() {
                return Ok(passed);
            }
        }
    }

    fn copy_string(&mut self) -> io::Result<u64> {
        self.expect(b'"')?;
        let len = self.pass_contents(true)?;
        self.expect(b'"')?;
        Ok(len)
    }

    /// Passes a member name, copying it; answers it decoded when it is
    /// short enough to be one a walk looks for.
    fn copy_name(&mut self) -> io::Result<Option<String>> {
        let quoted = self.out.len();
        if self.copy_string()? > NAME_MAX {
            return Ok(None);
        }
        serde_json::from_slice(self.out.get(quoted..).unwrap_or_default())
            .map(Some)
            .map_err(|_| malformed())
    }

    /// Passes the string next, copying all but its contents, so `""` stands
    /// in its place; answers where its contents lie.
    fn strip_string(&mut self) -> io::Result<Span> {
        self.expect(b'"')?;
        let start = self.at;
        let len = self.pass_contents(false)?;
        self.expect(b'"')?;
        Ok(Span { start, len })
    }

    /// Passes a number or a literal, copying it.
    fn copy_scalar(&mut self) -> io::Result<()> {
        let len = self.copy_while(|byte| {
            !matches!(
                byte,
                b' ' | b'\t' | b'\n' | b'\r' | b',' | b':' | b'"' | b'{' | b'}' | b'[' | b']'
            )
        })?;
        if len == 0 { Err(malformed()) } else { Ok(()) }
    }

    /// Passes one value of any shape, copying it; serde judges its form.
    fn copy_value(&mut self) -> io::Result<()> {
        let mut depth = 0_usize;
        loop {
            self.copy_space()?;
            match self.peek()? {
                b'"' => {
                    self.copy_string()?;
                }
                b'{' | b'[' => {
                    self.copy_byte()?;
                    depth = depth.saturating_add(1);
                    continue;
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or_else(malformed)?;
                    self.copy_byte()?;
                }
                b',' | b':' if depth > 0 => {
                    self.copy_byte()?;
                    continue;
                }
                _ => self.copy_scalar()?,
            }
            if depth == 0 {
                return Ok(());
            }
        }
    }

    /// Passes an object, copying it; `member` passes each member's value,
    /// given its name ([`Self::copy_name`]).
    fn object(
        &mut self,
        mut member: impl FnMut(&mut Self, Option<&str>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.copy_space()?;
        self.expect(b'{')?;
        self.copy_space()?;
        if self.peek()? == b'}' {
            self.copy_byte()?;
            return Ok(());
        }
        loop {
            self.copy_space()?;
            let name = self.copy_name()?;
            self.copy_space()?;
            self.expect(b':')?;
            self.copy_space()?;
            member(self, name.as_deref())?;
            self.copy_space()?;
            match self.copy_byte()? {
                b',' => {}
                b'}' => return Ok(()),
                _ => return Err(malformed()),
            }
        }
    }

    /// Passes an array, copying it; `element` passes each element.
    fn array(&mut self, mut element: impl FnMut(&mut Self) -> io::Result<()>) -> io::Result<()> {
        self.copy_space()?;
        self.expect(b'[')?;
        self.copy_space()?;
        if self.peek()? == b']' {
            self.copy_byte()?;
            return Ok(());
        }
        loop {
            self.copy_space()?;
            element(self)?;
            self.copy_space()?;
            match self.copy_byte()? {
                b',' => {}
                b']' => return Ok(()),
                _ => return Err(malformed()),
            }
        }
    }

    /// Passes one copy, its archive's contents left out; answers where they
    /// lie. A copy with no archive does not read.
    fn copy(&mut self) -> io::Result<Span> {
        let mut archive = None;
        self.object(|walk, name| match name {
            Some("export") => walk.object(|walk, name| match name {
                Some("archive") => {
                    archive = Some(walk.strip_string()?);
                    Ok(())
                }
                _ => walk.copy_value(),
            }),
            _ => walk.copy_value(),
        })?;
        archive.ok_or_else(malformed)
    }

    /// Passes a delivery session's answer, each copy's archive left out;
    /// answers where each copy and its archive lie, in order.
    fn deliveries(&mut self) -> io::Result<Vec<(Span, Span)>> {
        let mut found = Vec::new();
        self.object(|walk, name| match name {
            Some("deliveries") => walk.array(|walk| {
                walk.object(|walk, name| match name {
                    Some("copy") => {
                        let start = walk.at;
                        let archive = walk.copy()?;
                        let json = Span {
                            start,
                            len: walk.at.saturating_sub(start),
                        };
                        found.push((json, archive));
                        Ok(())
                    }
                    _ => walk.copy_value(),
                })
            }),
            _ => walk.copy_value(),
        })?;
        Ok(found)
    }

    /// Passes what follows the document: whitespace alone.
    fn end(&mut self) -> io::Result<()> {
        self.copy_space()?;
        if self.reader.fill_buf()?.is_empty() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}

fn invalid(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// The deliveries of the session answer spooled in `answer`, read from its
/// start: each with its copy, its archive left in the file.
pub(super) fn read_deliveries(answer: &mut File) -> io::Result<Vec<Delivery>> {
    answer.seek(SeekFrom::Start(0))?;
    let mut walk = Walk::new(BufReader::new(&mut *answer));
    let spans = walk.deliveries()?;
    walk.end()?;
    let read: Answer = serde_json::from_slice(&walk.out).map_err(invalid)?;
    if read.deliveries.len() != spans.len() {
        return Err(malformed());
    }
    Ok(read
        .deliveries
        .into_iter()
        .zip(spans)
        .map(|(sent, (json, archive))| Delivery {
            version: sent.version,
            copy: sent.copy,
            json,
            archive,
        })
        .collect())
}

/// Copies the bytes `span` names in `file` to `out`.
pub(super) fn copy_span(file: &mut File, span: Span, out: &mut impl Write) -> io::Result<()> {
    file.seek(SeekFrom::Start(span.start))?;
    let copied = io::copy(&mut Read::take(&mut *file, span.len), out)?;
    if copied == span.len {
        Ok(())
    } else {
        Err(malformed())
    }
}

/// A writer that hashes what it passes on.
struct Hashing<W> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hasher.update(bytes.get(..written).unwrap_or_default());
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The archive whose standard base64 `span` names in `file`, decoded into
/// `spool` and rewound, and its BLAKE3, lowercase hex.
pub(super) fn decode_archive(
    file: &mut File,
    span: Span,
    spool: File,
) -> io::Result<(File, String)> {
    file.seek(SeekFrom::Start(span.start))?;
    let base64 = BufReader::with_capacity(READ_BUFFER, Read::take(&mut *file, span.len));
    let mut decoder =
        base64::read::DecoderReader::new(base64, &base64::engine::general_purpose::STANDARD);
    let mut out = Hashing {
        inner: BufWriter::new(spool),
        hasher: blake3::Hasher::new(),
    };
    io::copy(&mut decoder, &mut out)?;
    let Hashing { inner, hasher } = out;
    let mut spool = inner.into_inner().map_err(io::IntoInnerError::into_error)?;
    spool.seek(SeekFrom::Start(0))?;
    Ok((spool, hasher.finalize().to_hex().to_string()))
}

/// The copy kept at `path`, as the receiver wrote it, its archive decoded
/// into `spool`; the import checks it against its digest.
pub(super) fn read_kept(path: &Path, spool: File) -> io::Result<RemovalExportFile> {
    let mut file = File::open(path)?;
    let (copy, archive) = {
        let mut walk = Walk::new(BufReader::new(&mut file));
        let archive = walk.copy()?;
        walk.end()?;
        let copy: RemovalExportCopy = serde_json::from_slice(&walk.out).map_err(invalid)?;
        (copy, archive)
    };
    let (spool, _) = decode_archive(&mut file, archive, spool)?;
    Ok(RemovalExportFile::received(copy, spool))
}
