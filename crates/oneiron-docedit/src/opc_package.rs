//! Minimal Open Packaging Conventions (OPC) reader/writer for the ARTL-3
//! edit round-trip pipeline.
//!
//! Office Open XML files (xlsx/docx/pptx) are ZIP containers of XML parts. The
//! pipeline needs to decompose the bytes a code-session produced into their
//! parts so it can enforce the OF-368 D5 fidelity law **independently of the
//! session** — the corruption/passthrough gate must not trust the very tool
//! that wrote the bytes. That is why this lives in the engine (pure Rust,
//! runnable in CI) rather than behind the external-binary seam.
//!
//! Scope is deliberately narrow: read STORED and DEFLATE ZIP entries via the
//! central directory, and write STORED entries. The pipeline retains session
//! bytes unless it restores missing worksheet XML. That repair repackages the
//! decompressed parts without changing their order or other part bytes.
//! Writing also builds copies handed to sessions and test fixtures.
//!
//! Every entry is bounded and verified before it is trusted: the reader
//! rejects a declared uncompressed size over a per-entry or per-package cap
//! before inflating (a zip bomb), inflates against that bound, and checks the
//! resulting length and CRC-32 against the central directory. Duplicate part
//! names, multi-disk archives, ZIP64 sentinels, encrypted entries, and
//! compression methods other than STORED/DEFLATE are rejected as corruption
//! rather than silently mishandled.
//!
//! Before any payload is copied or inflated, its local header must repeat its
//! central entry (name bytes, method, flags other than the DEFLATE option
//! hints, and, without a data descriptor, checksum and sizes), and its local
//! record must not overlap another entry's or reach the central directory, so
//! one compressed payload is never inflated twice under two names.
//!
//! This is original code written against the published ZIP appnote and the
//! ECMA-376 OPC part-naming conventions (facts, not expression); it copies no
//! source from any packaging library.

use std::borrow::Cow;
use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};

use oneiron_contracts::error::{ArtifactError, Error, Result};

pub use read::{read, read_from, read_with_limits};

mod read;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_DIR_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_FILE_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_MIN_LEN: usize = 22;
const CENTRAL_DIR_MIN_LEN: usize = 46;
const LOCAL_FILE_MIN_LEN: usize = 30;
const ZIP_STORED: u16 = 0;
const ZIP_DEFLATE: u16 = 8;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
/// General-purpose bits 1-2: DEFLATE option hints, which Excel writes
/// differently in some local headers than in the central record.
const DEFLATE_OPTION_FLAGS: u16 = 0x0006;
/// General-purpose bit 3: CRC and sizes follow the payload in a descriptor.
const DATA_DESCRIPTOR_FLAG: u16 = 0x0008;

/// What an OPC package is read from: its bytes in memory, or a seekable
/// reader read at the offsets its ZIP records name (FIX 22074), so a package
/// on disk is checked without its whole body in memory.
trait Source {
    /// The package's length in bytes.
    fn total_len(&self) -> usize;
    /// The `len` bytes at `offset`; `None` when they run past the end.
    fn range(&self, offset: usize, len: usize) -> Result<Option<Cow<'_, [u8]>>>;
    /// `read` over the `len` bytes at `offset` as they stream, never held
    /// whole by the source; `None` when they run past the end.
    fn with_range<T>(
        &self,
        offset: usize,
        len: usize,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<Option<T>>;
}

impl Source for [u8] {
    fn total_len(&self) -> usize {
        self.len()
    }

    fn range(&self, offset: usize, len: usize) -> Result<Option<Cow<'_, [u8]>>> {
        Ok(offset
            .checked_add(len)
            .and_then(|end| self.get(offset..end))
            .map(Cow::Borrowed))
    }

    fn with_range<T>(
        &self,
        offset: usize,
        len: usize,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<Option<T>> {
        match offset
            .checked_add(len)
            .and_then(|end| self.get(offset..end))
        {
            Some(mut bytes) => read(&mut bytes).map(Some),
            None => Ok(None),
        }
    }
}

/// A package a seekable reader holds, `len` bytes long.
struct ReaderSource<'r, R> {
    reader: RefCell<&'r mut R>,
    len: usize,
}

impl<R: Read + Seek> Source for ReaderSource<'_, R> {
    fn total_len(&self) -> usize {
        self.len
    }

    fn range(&self, offset: usize, len: usize) -> Result<Option<Cow<'_, [u8]>>> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Ok(None);
        }
        let mut reader = self.reader.borrow_mut();
        reader
            .seek(SeekFrom::Start(offset as u64))
            .map_err(Error::Io)?;
        let mut out = vec![0; len];
        reader.read_exact(&mut out).map_err(Error::Io)?;
        Ok(Some(Cow::Owned(out)))
    }

    fn with_range<T>(
        &self,
        offset: usize,
        len: usize,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<Option<T>> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Ok(None);
        }
        let mut reader = self.reader.borrow_mut();
        reader
            .seek(SeekFrom::Start(offset as u64))
            .map_err(Error::Io)?;
        let mut range = RangeRead {
            inner: (&mut **reader).take(len as u64),
            failed: None,
        };
        let verdict = read(&mut range);
        // The whole range is read, as the slice source holds it whole: a
        // source that fails or ends early anywhere in it fails the package
        // with its own error, before the payload's verdict.
        range.drain();
        if let Some(error) = range.failed {
            return Err(Error::Io(error));
        }
        verdict.map(Some)
    }
}

/// A payload range as it streams from a reader source, keeping the
/// source's own read error apart from what a decoder makes of it.
struct RangeRead<R> {
    inner: std::io::Take<R>,
    failed: Option<std::io::Error>,
}

impl<R: Read> Read for RangeRead<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.inner.read(out) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let reported =
                        std::io::Error::new(error.kind(), "opc package source read failed");
                    self.failed.get_or_insert(error);
                    return Err(reported);
                }
                Ok(read) => return Ok(read),
            }
        }
    }
}

impl<R: Read> RangeRead<R> {
    /// Reads what the payload's reader left of the range, holding none of
    /// it, and notes a source that fails or ends before the range does.
    fn drain(&mut self) {
        if self.failed.is_some() {
            return;
        }
        let mut scratch = [0u8; 8192];
        loop {
            match self.inner.read(&mut scratch) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.failed = Some(error);
                    return;
                }
            }
        }
        if self.inner.limit() > 0 {
            self.failed = Some(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "opc package source ended inside an entry",
            ));
        }
    }
}

/// The OPC content-type manifest present in every well-formed package.
pub const CONTENT_TYPES_PART: &str = "[Content_Types].xml";

/// Coarse classification of an OPC part for the fidelity law.
///
/// `Supported` parts are the core editable spreadsheet surface the edit tool
/// is allowed to rewrite. `Unknown` parts — macros, pivots, charts, custom
/// XML, anything unrecognized — must survive an edit byte-for-byte
/// ([passthrough law](super)); a change to one of them is corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartClass {
    Supported,
    Unknown,
}

/// One part of an OPC package: its archive path and decompressed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcPart {
    pub name: String,
    pub data: Vec<u8>,
}

/// A decomposed OPC package. Part order mirrors the source central directory
/// so a read/write round-trip is stable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpcPackage {
    parts: Vec<OpcPart>,
}

impl OpcPackage {
    pub fn from_parts(parts: Vec<OpcPart>) -> Self {
        Self { parts }
    }

    pub fn parts(&self) -> &[OpcPart] {
        &self.parts
    }

    /// Returns the decompressed bytes for `name`, if present.
    pub fn part(&self, name: &str) -> Option<&[u8]> {
        self.parts
            .iter()
            .find(|part| part.name == name)
            .map(|part| part.data.as_slice())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.parts.iter().any(|part| part.name == name)
    }

    /// Iterates part names in package order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().map(|part| part.name.as_str())
    }

    /// Inserts or replaces a part, preserving position for replacements.
    pub fn upsert(&mut self, name: impl Into<String>, data: Vec<u8>) {
        let name = name.into();
        if let Some(existing) = self.parts.iter_mut().find(|part| part.name == name) {
            existing.data = data;
        } else {
            self.parts.push(OpcPart { name, data });
        }
    }
}

/// Serializes a package to ZIP bytes using STORED (method 0) entries.
///
/// Production repairs use [`write_checked`] to check the ZIP32 field widths.
/// Part order and decompressed bytes are retained; ZIP metadata is rebuilt.
pub fn write(package: &OpcPackage) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;

    for part in package.parts() {
        let name = part.name.as_bytes();
        let crc = crc32(&part.data);
        let size = part.data.len() as u32;
        let local_offset = out.len() as u32;

        out.extend_from_slice(&LOCAL_FILE_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&ZIP_STORED.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(&part.data);

        central.extend_from_slice(&CENTRAL_DIR_SIGNATURE.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&ZIP_STORED.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name);

        count = count.saturating_add(1);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes()); // entries this disk
    out.extend_from_slice(&count.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// Serializes a repaired package after checking the existing ZIP32 widths.
pub fn write_checked(package: &OpcPackage) -> Result<Vec<u8>> {
    let invalid = || {
        Error::Artifact(ArtifactError::EditRoundtripFailed(
            "repaired opc package does not fit ZIP32 fields",
        ))
    };
    if package.parts().len() >= usize::from(u16::MAX) {
        return Err(invalid());
    }
    let mut local_bytes = 0u64;
    let mut central_bytes = 0u64;
    for part in package.parts() {
        let name_bytes = u64::from(u16::try_from(part.name.len()).map_err(|_| invalid())?);
        let data_bytes = u32::try_from(part.data.len()).map_err(|_| invalid())?;
        if data_bytes == u32::MAX {
            return Err(invalid());
        }
        local_bytes = local_bytes
            .checked_add(LOCAL_FILE_MIN_LEN as u64 + name_bytes + u64::from(data_bytes))
            .ok_or_else(invalid)?;
        central_bytes = central_bytes
            .checked_add(CENTRAL_DIR_MIN_LEN as u64 + name_bytes)
            .ok_or_else(invalid)?;
    }
    if local_bytes >= u64::from(u32::MAX) || central_bytes >= u64::from(u32::MAX) {
        return Err(invalid());
    }
    let mut out = write(package);
    let utf8_flags = 0x0800u16.to_le_bytes();
    let mut local = 0usize;
    let mut central = local_bytes as usize;
    for part in package.parts() {
        out[local + 6..local + 8].copy_from_slice(&utf8_flags);
        out[central + 8..central + 10].copy_from_slice(&utf8_flags);
        local += LOCAL_FILE_MIN_LEN + part.name.len() + part.data.len();
        central += CENTRAL_DIR_MIN_LEN + part.name.len();
    }
    Ok(out)
}

/// Classifies a part for the fidelity law. Unknown-forcing families (macros,
/// pivots, charts, custom XML) are checked before the generic `xl/` editable
/// surface so a pivot part never counts as supported.
pub fn classify(name: &str) -> PartClass {
    if is_unknown_forced(name) {
        return PartClass::Unknown;
    }
    if name == CONTENT_TYPES_PART
        || name.starts_with("_rels/")
        || name.contains("/_rels/")
        || name.starts_with("docProps/")
        || is_supported_xl(name)
        || name.starts_with("word/")
        || name.starts_with("ppt/")
    {
        return PartClass::Supported;
    }
    PartClass::Unknown
}

/// True for part families the edit tool never rewrites and must pass through
/// byte-for-byte: VBA macros, pivot caches/tables, charts, and custom XML.
fn is_unknown_forced(name: &str) -> bool {
    name == "xl/vbaProject.bin"
        || name.starts_with("xl/externalLinks/")
        || name.starts_with("customXml/")
        || name.starts_with("xl/pivotCache/")
        || name.starts_with("xl/pivotTables/")
        || name.starts_with("xl/charts/")
}

fn is_supported_xl(name: &str) -> bool {
    const SUPPORTED_XL_PREFIXES: [&str; 7] = [
        "xl/worksheets/",
        "xl/theme/",
        "xl/tables/",
        "xl/drawings/",
        "xl/metadata",
        "xl/sharedStrings.xml",
        "xl/styles.xml",
    ];
    name == "xl/workbook.xml"
        || name == "xl/calcChain.xml"
        || SUPPORTED_XL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}
