//! Retained ZIP admission, metadata inspection and expansion.
//! Entry: `Package::open`.
//! Package and its private state remain in the parent module.

use super::*;
use crate::resource::{Dimension, Hold, bytes_of};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The most entries classic ZIP records: 65,535 is its ZIP64 sentinel.
const ZIP32_ENTRIES: usize = u16::MAX as usize - 1;
/// The most bytes classic ZIP records in a size or offset: 0xFFFFFFFF is its
/// ZIP64 sentinel.
const ZIP32_BYTES: usize = u32::MAX as usize - 1;

impl Package {
    /// Open a single-disk, non-ZIP64 OPC package under explicit limits.
    /// Supported payload methods are STORED and DEFLATE. Every entry is CRC
    /// checked; duplicate, unsafe or ambiguous names are rejected. An empty
    /// entry whose name ends in `/` is a ZIP directory entry: its folder path
    /// passes the same checks, and the archive keeps it, but it is no part.
    ///
    /// The entry count is an observation (FIX 8574): the source copy, the
    /// entry index, the names and each part's inflate buffer are reserved
    /// through `resources` before they are allocated, and the package keeps
    /// `resources` for its later reads, edits and copies. Only the ZIP32
    /// codec bounds the count: 65,535 is its ZIP64 sentinel.
    pub fn open(source: &[u8], limits: Limits, resources: &Resources) -> Result<Self> {
        check_limits(limits)?;
        if source.len() > limits.archive_bytes {
            return Err(Error::capacity_hit(
                Dimension::ArchiveBytes,
                source.len(),
                limits.archive_bytes,
            ));
        }
        let floor = source.len().saturating_sub(22 + u16::MAX as usize);
        let eocd = (floor..source.len().saturating_sub(21))
            .rev()
            .find(|&at| {
                get32(source, at).ok() == Some(EOCD)
                    && get16(source, at + 20)
                        .ok()
                        .and_then(|n| at.checked_add(22 + n as usize))
                        == Some(source.len())
            })
            .ok_or(Error::Invalid("missing end-of-central-directory"))?;
        if get16(source, eocd + 4)? != 0
            || get16(source, eocd + 6)? != 0
            || get16(source, eocd + 8)? != get16(source, eocd + 10)?
        {
            return Err(Error::Invalid("multi-disk ZIP"));
        }
        let count = usize::from(get16(source, eocd + 10)?);
        // Past classic ZIP's widths (a ZIP64 sentinel) is that format's
        // limit, not a malformed package (FIX 5354).
        if count > ZIP32_ENTRIES {
            return Err(Error::capacity_hit(
                Dimension::ZipEntries,
                count,
                ZIP32_ENTRIES,
            ));
        }
        let cd_offset = get32(source, eocd + 16)? as usize;
        let cd_size = get32(source, eocd + 12)? as usize;
        if cd_offset > ZIP32_BYTES || cd_size > ZIP32_BYTES {
            return Err(Error::capacity_hit(
                Dimension::ZipBytes,
                cd_offset.max(cd_size),
                ZIP32_BYTES,
            ));
        }
        if cd_offset.checked_add(cd_size) != Some(eocd) {
            return Err(Error::Invalid("central directory bounds"));
        }
        // The retained source and the entry index, reserved before either is
        // allocated; the hold lasts until the package exists.
        let mut hold = resources.hold();
        hold.take(wide(source.len()))?;
        // The central directory's count, before its records are walked: an
        // estimate, never a measured need (Engine 10-22 20:0x).
        hold.take_estimate(bytes_of::<Entry>(count), 0)?;
        // One part's inflate buffer at a time, covered at its largest.
        let mut scratch = Inflate::new(resources);
        let mut seen = HashSet::new();
        let mut entries = Vec::with_capacity(count);
        let mut cursor = cd_offset;
        let mut total = 0usize;
        for _ in 0..count {
            resources.checkpoint()?;
            if get32(source, cursor)? != CENTRAL || cursor + 46 > eocd {
                return Err(Error::Invalid("central header"));
            }
            let flags = get16(source, cursor + 8)?;
            let method = get16(source, cursor + 10)?;
            let crc = get32(source, cursor + 16)?;
            let compressed = get32(source, cursor + 20)? as usize;
            let uncompressed = get32(source, cursor + 24)? as usize;
            let n = get16(source, cursor + 28)? as usize;
            let x = get16(source, cursor + 30)? as usize;
            let c = get16(source, cursor + 32)? as usize;
            let end = cursor
                .checked_add(46)
                .and_then(|v| v.checked_add(n))
                .and_then(|v| v.checked_add(x))
                .and_then(|v| v.checked_add(c))
                .ok_or(Error::Invalid("central entry overflow"))?;
            let local_offset = get32(source, cursor + 42)? as usize;
            if compressed > ZIP32_BYTES || uncompressed > ZIP32_BYTES || local_offset > ZIP32_BYTES
            {
                return Err(Error::capacity_hit(
                    Dimension::ZipBytes,
                    compressed.max(uncompressed).max(local_offset),
                    ZIP32_BYTES,
                ));
            }
            if end > eocd || get16(source, cursor + 34)? != 0 {
                return Err(Error::Invalid("central entry bounds"));
            }
            // Bits 1-2 encode the compressor's DEFLATE level in real Office
            // archives (including PPTArena), not encryption. Bit 0 encrypts.
            if flags & !0x080e != 0
                || (method == 0 && flags & 6 != 0)
                || !matches!(method, 0 | 8)
                || has_zip64_extra(&source[cursor + 46 + n..cursor + 46 + n + x])?
            {
                return Err(Error::Invalid("encrypted or unsupported entry"));
            }
            let name_bytes = source
                .get(cursor + 46..cursor + 46 + n)
                .ok_or(Error::Invalid("name bounds"))?;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| Error::Invalid("non-UTF8 entry name"))?;
            // The entry's name and its lowercase key in the duplicate set; the
            // retained name's bytes are the measured part.
            hold.take_estimate(wide(2 * n).saturating_add(bytes_of::<String>(2)), wide(n))?;
            // A directory entry (`xl/`) is empty, and its folder path takes the
            // part-name checks, so it also collides with a part of that name.
            let path = match name.strip_suffix('/') {
                Some(_) if uncompressed != 0 => {
                    return Err(Error::Invalid("directory entry with content"));
                }
                Some(folder) => folder,
                None => name,
            };
            if path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path.contains('\0')
                || path
                    .split('/')
                    .any(|part| part == ".." || part == "." || part.is_empty())
                || !seen.insert(path.to_ascii_lowercase())
            {
                return Err(Error::Invalid("unsafe or duplicate entry name"));
            }
            total = total
                .checked_add(uncompressed)
                .ok_or(Error::Invalid("expanded size overflow"))?;
            if uncompressed > limits.part_bytes {
                return Err(Error::capacity_hit(
                    Dimension::PartBytes,
                    uncompressed,
                    limits.part_bytes,
                ));
            }
            if total > limits.expanded_bytes {
                return Err(Error::capacity_hit(
                    Dimension::ExpandedBytes,
                    total,
                    limits.expanded_bytes,
                ));
            }
            let local_start = get32(source, cursor + 42)? as usize;
            // Excel writes some local headers whose DEFLATE option hints (bits
            // 1-2) differ from the central record; every other bit must agree.
            let local_flags = get16(source, local_start + 6)?;
            if get32(source, local_start)? != LOCAL
                || (local_flags ^ flags) & !0x0006 != 0
                || (method == 0 && local_flags & 6 != 0)
                || get16(source, local_start + 8)? != method
            {
                return Err(Error::Invalid("local header mismatch"));
            }
            let ln = get16(source, local_start + 26)? as usize;
            let lx = get16(source, local_start + 28)? as usize;
            let data_start = local_start
                .checked_add(30)
                .and_then(|v| v.checked_add(ln))
                .and_then(|v| v.checked_add(lx))
                .ok_or(Error::Invalid("local bounds"))?;
            let data_end = data_start
                .checked_add(compressed)
                .ok_or(Error::Invalid("data bounds"))?;
            if data_end > cd_offset
                || source.get(local_start + 30..local_start + 30 + ln) != Some(name_bytes)
            {
                return Err(Error::Invalid("local name or payload bounds"));
            }
            if flags & 8 == 0
                && (get32(source, local_start + 14)? != crc
                    || get32(source, local_start + 18)? as usize != compressed
                    || get32(source, local_start + 22)? as usize != uncompressed)
            {
                return Err(Error::Invalid("local size or checksum mismatch"));
            }
            let trailer = if flags & 8 != 0 {
                // The CRC of an unsigned descriptor can equal the optional
                // signature word. Compare both complete layouts, never infer
                // the layout from that first word alone.
                let unsigned = get32(source, data_end).ok() == Some(crc)
                    && get32(source, data_end + 4).ok() == Some(compressed as u32)
                    && get32(source, data_end + 8).ok() == Some(uncompressed as u32);
                let signed = get32(source, data_end).ok() == Some(0x0807_4b50)
                    && get32(source, data_end + 4).ok() == Some(crc)
                    && get32(source, data_end + 8).ok() == Some(compressed as u32)
                    && get32(source, data_end + 12).ok() == Some(uncompressed as u32);
                match (unsigned, signed) {
                    (true, false) => data_end + 12,
                    (false, true) => data_end + 16,
                    _ => return Err(Error::Invalid("ambiguous or invalid data descriptor")),
                }
            } else {
                data_end
            };
            if trailer > cd_offset || has_zip64_extra(&source[local_start + 30 + ln..data_start])? {
                return Err(Error::Invalid("local descriptor or ZIP64 extra"));
            }
            let raw = &source[data_start..data_end];
            let mut data = Vec::new();
            if method == 0 {
                // A stored part's copy is its own bytes in the source, every
                // one measured (FIX 10656).
                scratch.cover(raw.len(), raw.len())?;
                data.extend_from_slice(raw);
            } else {
                scratch.cover(uncompressed, 0)?;
                DeflateDecoder::new(raw)
                    .take(uncompressed as u64 + 1)
                    .read_to_end(&mut data)
                    .map_err(|_| Error::Invalid("deflate corruption"))?;
            }
            if data.len() != uncompressed || crc32fast::hash(&data) != crc {
                return Err(Error::Invalid("entry size or CRC mismatch"));
            }
            entries.push(Entry {
                name: name.to_owned(),
                central: cursor..end,
                local: local_start..data_end,
                data: data_start..data_end,
                trailer,
                method,
                flags,
                uncompressed,
                crc,
                replacement: None,
                removed: false,
            });
            cursor = end;
        }
        if cursor != eocd
            || !entries
                .iter()
                .any(|entry| entry.name == "[Content_Types].xml")
        {
            return Err(Error::Invalid(
                "central directory or OPC content types missing",
            ));
        }
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_unstable_by_key(|&i| entries[i].local.start);
        for (at, &index) in order.iter().enumerate() {
            let next = order
                .get(at + 1)
                .map_or(cd_offset, |&i| entries[i].local.start);
            if entries[index].trailer > next {
                return Err(Error::Invalid("overlapping local records"));
            }
            entries[index].local.end = next; // Includes descriptor and non-entry padding.
        }
        let mut package = Self {
            source: source.into(),
            entries,
            cd_offset,
            eocd,
            limits,
            editability: Editability::Unsigned,
            added: Vec::new(),
            resources: resources.clone(),
            inflated: Arc::default(),
        };
        drop(scratch);
        package.editability = package.signature_or_unsafe_metadata()?;
        drop(hold);
        Ok(package)
    }

    /// Detect OPC digital signatures by type declarations and relationships,
    /// not only their conventional path. Invalid metadata leaves the package
    /// open for byte-exact no-op export but makes every edit read-only. Only
    /// parts count on that path: an empty `_xmlsignatures/` folder entry
    /// holds no signature. A part whose memory was refused is not
    /// uninspectable markup: the refusal is the open's own error.
    pub(super) fn signature_or_unsafe_metadata(&self) -> Result<Editability> {
        if self
            .names()
            .any(|name| name.to_ascii_lowercase().starts_with("_xmlsignatures/"))
        {
            return Ok(Editability::Signed);
        }
        let mut editability = Editability::Unsigned;
        for entry in self.entries.iter().filter(|entry| {
            entry.name == "[Content_Types].xml" || {
                let lower = entry.name.to_ascii_lowercase();
                lower.ends_with(".rels")
                    && (lower.starts_with("_rels/") || lower.contains("/_rels/"))
            }
        }) {
            match self.expanded(entry).and_then(|data| {
                xml::ValidatedXmlPart::parse(&data, &self.resources).map(|part| part.signature())
            }) {
                Ok(true) => return Ok(Editability::Signed),
                Ok(false) => {}
                Err(Error::Resource(refusal)) => return Err(Error::Resource(refusal)),
                Err(_) => editability = Editability::MetadataUnsupported,
            }
        }
        Ok(editability)
    }

    /// One part's expanded bytes, reserved through the package's port
    /// before they are allocated.
    pub(super) fn expanded(&self, entry: &Entry) -> Result<Vec<u8>> {
        if let Some(ref replacement) = entry.replacement {
            let _hold = self.resources.reserve(wide(replacement.len()))?;
            return Ok(replacement.clone());
        }
        let raw = &self.source[entry.data.clone()];
        let _hold = self.resources.reserve(wide(entry.uncompressed))?;
        if entry.method == 0 {
            return Ok(raw.to_vec());
        }
        if let Some(part) = self.inflated.read(entry.data.start) {
            return Ok(part);
        }
        let mut out = Vec::with_capacity(entry.uncompressed);
        DeflateDecoder::new(raw)
            .take(entry.uncompressed as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| Error::Invalid("deflate corruption"))?;
        if out.len() != entry.uncompressed || crc32fast::hash(&out) != entry.crc {
            return Err(Error::Invalid("entry size or CRC mismatch"));
        }
        // The kept copy is reserved before it is allocated, and the hold
        // lives as long as the copy; one the port does not admit is left
        // out, and its part inflates on each read.
        if let Ok(hold) = self.resources.reserve(wide(out.len())) {
            self.inflated.keep(entry.data.start, &out, hold);
        }
        Ok(out)
    }
}

/// The source's DEFLATE parts inflated and CRC-checked so far, by their
/// payload's offset in the source (FIX 5144). The source never changes, so a
/// part stays exact for the package's life and every copy of it shares the
/// parts; an edited or removed part is answered before these are read.
#[derive(Default)]
pub(super) struct Inflated(Mutex<HashMap<usize, (Hold, Vec<u8>)>>);

impl Inflated {
    /// A copy of the part whose payload starts at `offset`, once inflated.
    fn read(&self, offset: usize) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&offset)
            .map(|(_, part)| part.clone())
    }

    /// Keeps a copy of `part`, inflated from the payload at `offset`, with
    /// the memory `hold` that counts it.
    fn keep(&self, offset: usize, part: &[u8], hold: Hold) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(offset)
            .or_insert_with(|| (hold, part.to_vec()));
    }
}

impl std::fmt::Debug for Inflated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("Inflated")
            .field("parts", &parts.len())
            .finish()
    }
}

/// The inflate scratch of an open: one part's buffer lives at a time, so one
/// hold covers the largest part read so far.
struct Inflate {
    hold: Hold,
    covered: usize,
}

impl Inflate {
    fn new(resources: &Resources) -> Self {
        Self {
            hold: resources.hold(),
            covered: 0,
        }
    }

    /// Covers a buffer of `bytes`, reserving only what the largest so far
    /// did not, of which `measured` the source holds already: a stored
    /// part's own bytes. A deflated part's size is the entry header's word
    /// before the part is inflated: an estimate, of which nothing is
    /// measured yet.
    fn cover(&mut self, bytes: usize, measured: usize) -> Result<()> {
        if bytes > self.covered {
            let more = bytes - self.covered;
            let measured = measured.saturating_sub(self.covered).min(more);
            self.hold.take_estimate(wide(more), wide(measured))?;
            self.covered = bytes;
        }
        Ok(())
    }
}

pub(super) fn check_limits(limits: Limits) -> Result<()> {
    if [
        limits.archive_bytes,
        limits.part_bytes,
        limits.expanded_bytes,
    ]
    .contains(&0)
    {
        return Err(Error::Invalid("resource limits must be positive"));
    }
    Ok(())
}

pub(super) fn has_zip64_extra(mut extra: &[u8]) -> Result<bool> {
    while !extra.is_empty() {
        if extra.len() < 4 {
            return Err(Error::Invalid("malformed ZIP extra"));
        }
        let id = u16::from_le_bytes([extra[0], extra[1]]);
        let size = usize::from(u16::from_le_bytes([extra[2], extra[3]]));
        extra = extra
            .get(4..)
            .and_then(|bytes| bytes.get(size..))
            .ok_or(Error::Invalid("malformed ZIP extra"))?;
        if id == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}
