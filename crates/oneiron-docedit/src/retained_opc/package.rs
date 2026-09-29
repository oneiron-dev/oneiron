//! ZIP central-directory reader and copy-through writer. All source records
//! remain owned by the package; only declared XML leaf edits can produce output.
use super::{Error, Result, XmlLimits, xml};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use std::{
    collections::HashSet,
    io::{Read, Write},
};

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const EOCD: u32 = 0x0605_4b50;

/// Caller-selected limits, checked before decompression and again after it.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum source ZIP bytes.
    pub archive_bytes: usize,
    /// Maximum number of entries.
    pub entries: usize,
    /// Maximum expanded bytes per entry.
    pub part_bytes: usize,
    /// Maximum total expanded bytes.
    pub expanded_bytes: usize,
    /// Maximum XML depth and parser nodes at both the signature and edit doors.
    pub xml: XmlLimits,
}

/// A package may still be exported exactly when XML metadata cannot be
/// inspected. Only the Unsigned state admits a checked edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Editability {
    Unsigned,
    Signed,
    MetadataUnsupported,
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    central: std::ops::Range<usize>,
    local: std::ops::Range<usize>,
    data: std::ops::Range<usize>,
    trailer: usize,
    method: u16,
    flags: u16,
    uncompressed: usize,
    crc: u32,
    replacement: Option<Vec<u8>>,
}

/// A retained OPC package. It owns the original ZIP, including unreachable
/// entries, central-directory metadata, comments and untouched local records.
#[derive(Debug, Clone)]
pub struct Package {
    source: Vec<u8>,
    entries: Vec<Entry>,
    cd_offset: usize,
    eocd: usize,
    limits: Limits,
    editability: Editability,
}

impl Package {
    /// Open a single-disk, non-ZIP64 OPC package under explicit limits.
    /// Supported payload methods are STORED and DEFLATE. Every entry is CRC
    /// checked; duplicate, unsafe or ambiguous names are rejected.
    pub fn open(source: &[u8], limits: Limits) -> Result<Self> {
        if [
            limits.archive_bytes,
            limits.entries,
            limits.part_bytes,
            limits.expanded_bytes,
            limits.xml.max_depth,
            limits.xml.max_nodes,
        ]
        .contains(&0)
        {
            return Err(Error::Invalid("resource limits must be positive"));
        }
        if source.len() > limits.archive_bytes {
            return Err(Error::Invalid("archive size limit"));
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
        if count == usize::from(u16::MAX) || count > limits.entries {
            return Err(Error::Invalid("entry limit or ZIP64"));
        }
        let cd_offset = get32(source, eocd + 16)? as usize;
        let cd_size = get32(source, eocd + 12)? as usize;
        if cd_offset == u32::MAX as usize
            || cd_size == u32::MAX as usize
            || cd_offset.checked_add(cd_size) != Some(eocd)
        {
            return Err(Error::Invalid("central directory bounds or ZIP64"));
        }
        let mut seen = HashSet::new();
        let mut entries = Vec::with_capacity(count);
        let mut cursor = cd_offset;
        let mut total = 0usize;
        for _ in 0..count {
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
            if end > eocd
                || get16(source, cursor + 34)? != 0
                || compressed == u32::MAX as usize
                || uncompressed == u32::MAX as usize
                || get32(source, cursor + 42)? == u32::MAX
            {
                return Err(Error::Invalid("central entry bounds or ZIP64"));
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
            if name.is_empty()
                || name.starts_with('/')
                || name.contains('\\')
                || name.contains('\0')
                || name
                    .split('/')
                    .any(|part| part == ".." || part == "." || part.is_empty())
                || !seen.insert(name.to_ascii_lowercase())
            {
                return Err(Error::Invalid("unsafe or duplicate entry name"));
            }
            total = total
                .checked_add(uncompressed)
                .ok_or(Error::Invalid("expanded size overflow"))?;
            if uncompressed > limits.part_bytes || total > limits.expanded_bytes {
                return Err(Error::Invalid("expanded size limit"));
            }
            let local_start = get32(source, cursor + 42)? as usize;
            if get32(source, local_start)? != LOCAL
                || get16(source, local_start + 6)? != flags
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
                data.extend_from_slice(raw);
            } else {
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
            source: source.to_vec(),
            entries,
            cd_offset,
            eocd,
            limits,
            editability: Editability::Unsigned,
        };
        package.editability = package.signature_or_unsafe_metadata();
        Ok(package)
    }

    /// Detect OPC digital signatures by type declarations and relationships,
    /// not only their conventional path. Invalid metadata leaves the package
    /// open for byte-exact no-op export but makes every edit read-only.
    fn signature_or_unsafe_metadata(&self) -> Editability {
        if self.entries.iter().any(|entry| {
            entry
                .name
                .to_ascii_lowercase()
                .starts_with("_xmlsignatures/")
        }) {
            return Editability::Signed;
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
                xml::ValidatedXmlPart::parse(&data, self.limits.xml).map(|part| part.signature())
            }) {
                Ok(true) => return Editability::Signed,
                Ok(false) => {}
                Err(_) => editability = Editability::MetadataUnsupported,
            }
        }
        editability
    }

    /// The observable edit refusal reason; no-op export remains exact in every state.
    pub fn editability(&self) -> Editability {
        self.editability
    }

    /// The limits this package was opened under; derived readers of its
    /// parts use the same XML ceilings.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Names in central-directory order, including unreachable entries.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.name.as_str())
    }

    /// Returns verified expanded bytes for one part.
    pub fn part(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| self.expanded(entry))
            .transpose()
    }

    /// Replace the text of exactly one leaf XML node by its absolute QName
    /// path. The old text is an optimistic concurrency check. A caller cannot
    /// submit arbitrary part bytes or modify an unaddressed XML subtree.
    pub fn replace_text(
        &mut self,
        name: &str,
        path: &[&str],
        expected: &str,
        value: &str,
    ) -> Result<()> {
        let index = self.editable_xml_part(name)?;
        let old = self.expanded(&self.entries[index])?;
        let other_size =
            self.entries
                .iter()
                .enumerate()
                .try_fold(0usize, |total, (at, entry)| {
                    total
                        .checked_add(if at == index {
                            0
                        } else {
                            entry
                                .replacement
                                .as_ref()
                                .map_or(entry.uncompressed, Vec::len)
                        })
                        .ok_or(Error::Edit("edited package size overflow"))
                })?;
        let budget = self.limits.part_bytes.min(
            self.limits
                .expanded_bytes
                .checked_sub(other_size)
                .ok_or(Error::Edit("edited package size limit"))?,
        );
        let part = xml::ValidatedXmlPart::parse(&old, self.limits.xml)?;
        let new = part.replace_text(path, expected, value, budget)?.0;
        self.commit_replacement(index, old, new)
    }

    /// Replace one whole XML part with bytes the caller derived from it, for a
    /// writer that patches byte spans of the part it read (recalculated formula
    /// caches, for one). The bytes must pass the same XML validation and
    /// limits as a leaf edit; signed or uninspectable packages stay read-only,
    /// and every part, expansion and archive budget still holds.
    pub fn replace_xml_part(&mut self, name: &str, value: Vec<u8>) -> Result<()> {
        if name == "[Content_Types].xml" {
            return Err(Error::Edit("package metadata is not a document part"));
        }
        let index = self.editable_xml_part(name)?;
        let old = self.expanded(&self.entries[index])?;
        if value.len() > self.limits.part_bytes {
            return Err(Error::Edit("edited part size limit"));
        }
        xml::ValidatedXmlPart::parse(&value, self.limits.xml)?;
        self.commit_replacement(index, old, value)
    }

    fn editable_xml_part(&self, name: &str) -> Result<usize> {
        if self.editability != Editability::Unsigned {
            return Err(Error::Edit("signed or unsupported metadata is read-only"));
        }
        if !name.ends_with(".xml") {
            return Err(Error::Edit("not an XML part"));
        }
        self.entries
            .iter()
            .position(|entry| entry.name == name)
            .ok_or(Error::Edit("part missing"))
    }

    /// Record `new` as the part's payload after the expansion and archive
    /// budgets pass. `old` is the part's current expanded bytes.
    fn commit_replacement(&mut self, index: usize, old: Vec<u8>, new: Vec<u8>) -> Result<()> {
        if new.len() > self.limits.part_bytes {
            return Err(Error::Edit("edited part size limit"));
        }
        let total = self
            .entries
            .iter()
            .enumerate()
            .try_fold(0usize, |sum, (at, entry)| {
                sum.checked_add(if at == index {
                    new.len()
                } else {
                    entry
                        .replacement
                        .as_ref()
                        .map_or(entry.uncompressed, Vec::len)
                })
                .ok_or(Error::Edit("edited package size overflow"))
            })?;
        if total > self.limits.expanded_bytes {
            return Err(Error::Edit("edited package size limit"));
        }
        if new != old {
            let original = if self.entries[index].replacement.is_some() {
                let mut raw = self.entries[index].clone();
                raw.replacement = None;
                self.expanded(&raw)?
            } else {
                old
            };
            let replacement = (new != original).then_some(new);
            self.check_export_size(index, replacement.as_deref())?;
            self.entries[index].replacement = replacement;
        }
        Ok(())
    }

    /// Compute the exact compressed output length with a counting sink before
    /// committing a replacement; no over-budget ZIP allocation is attempted.
    fn check_export_size(&self, edited: usize, candidate: Option<&[u8]>) -> Result<()> {
        let mut total = self.source.len();
        for (index, entry) in self.entries.iter().enumerate() {
            let replacement = if index == edited {
                candidate
            } else {
                entry.replacement.as_deref()
            };
            let Some(data) = replacement else {
                continue;
            };
            let header = entry
                .data
                .start
                .checked_sub(entry.local.start)
                .ok_or(Error::Edit("ZIP header size overflow"))?;
            let padding = entry
                .local
                .end
                .checked_sub(entry.trailer)
                .ok_or(Error::Edit("ZIP padding size overflow"))?;
            let emitted = header
                .checked_add(compressed_length(entry.method, data)?)
                .and_then(|size| size.checked_add(padding))
                .ok_or(Error::Edit("edited ZIP size overflow"))?;
            total = total
                .checked_sub(entry.local.len())
                .and_then(|size| size.checked_add(emitted))
                .ok_or(Error::Edit("edited ZIP size overflow"))?;
        }
        if total > self.limits.archive_bytes || u32::try_from(total).is_err() {
            return Err(Error::Edit("edited archive size limit"));
        }
        Ok(())
    }

    /// Export an exact original archive on no-op. After an edit, retain all
    /// untouched local records and compressed payloads, patch central offsets,
    /// and replace only edited entry payload/header/checksum fields.
    pub fn export(&self) -> Result<Vec<u8>> {
        if self.entries.iter().all(|entry| entry.replacement.is_none()) {
            return Ok(self.source.clone());
        }
        let mut out = Vec::with_capacity(self.source.len());
        let mut offsets = vec![0u32; self.entries.len()];
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        order.sort_unstable_by_key(|&i| self.entries[i].local.start);
        let first = order
            .first()
            .map_or(self.cd_offset, |&i| self.entries[i].local.start);
        out.extend_from_slice(&self.source[..first]);
        for index in order {
            let entry = &self.entries[index];
            offsets[index] = as_u32(out.len())?;
            if let Some(ref replacement) = entry.replacement {
                let compressed = if entry.method == 0 {
                    replacement.clone()
                } else {
                    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                    encoder
                        .write_all(replacement)
                        .map_err(|_| Error::Invalid("compression failed"))?;
                    encoder
                        .finish()
                        .map_err(|_| Error::Invalid("compression failed"))?
                };
                let mut header = self.source[entry.local.start..entry.data.start].to_vec();
                patch16(&mut header, 6, entry.flags & !0x000e);
                patch32(&mut header, 14, crc32fast::hash(replacement));
                patch32(&mut header, 18, as_u32(compressed.len())?);
                patch32(&mut header, 22, as_u32(replacement.len())?);
                out.extend_from_slice(&header);
                out.extend_from_slice(&compressed);
                out.extend_from_slice(&self.source[entry.trailer..entry.local.end]);
            } else {
                out.extend_from_slice(&self.source[entry.local.clone()]);
            }
        }
        let cd_offset = as_u32(out.len())?;
        for (index, entry) in self.entries.iter().enumerate() {
            let mut record = self.source[entry.central.clone()].to_vec();
            patch32(&mut record, 42, offsets[index]);
            if let Some(ref replacement) = entry.replacement {
                let compressed = if entry.method == 0 {
                    replacement.clone()
                } else {
                    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                    encoder
                        .write_all(replacement)
                        .map_err(|_| Error::Invalid("compression failed"))?;
                    encoder
                        .finish()
                        .map_err(|_| Error::Invalid("compression failed"))?
                };
                patch16(&mut record, 8, entry.flags & !0x000e);
                patch32(&mut record, 16, crc32fast::hash(replacement));
                patch32(&mut record, 20, as_u32(compressed.len())?);
                patch32(&mut record, 24, as_u32(replacement.len())?);
            }
            out.extend_from_slice(&record);
        }
        let cd_size = as_u32(out.len() - cd_offset as usize)?;
        let mut footer = self.source[self.eocd..].to_vec();
        patch32(&mut footer, 12, cd_size);
        patch32(&mut footer, 16, cd_offset);
        out.extend_from_slice(&footer);
        if out.len() > self.limits.archive_bytes {
            return Err(Error::Invalid("export archive size limit"));
        }
        Ok(out)
    }

    fn expanded(&self, entry: &Entry) -> Result<Vec<u8>> {
        if let Some(ref replacement) = entry.replacement {
            return Ok(replacement.clone());
        }
        let raw = &self.source[entry.data.clone()];
        if entry.method == 0 {
            return Ok(raw.to_vec());
        }
        let mut out = Vec::with_capacity(entry.uncompressed);
        DeflateDecoder::new(raw)
            .take(entry.uncompressed as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| Error::Invalid("deflate corruption"))?;
        if out.len() != entry.uncompressed || crc32fast::hash(&out) != entry.crc {
            return Err(Error::Invalid("entry size or CRC mismatch"));
        }
        Ok(out)
    }
}

fn get16(bytes: &[u8], at: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(at..at.checked_add(2).ok_or(Error::Invalid("offset overflow"))?)
        .ok_or(Error::Invalid("truncated ZIP"))?
        .try_into()
        .map_err(|_| Error::Invalid("truncated ZIP"))?;
    Ok(u16::from_le_bytes(raw))
}
fn get32(bytes: &[u8], at: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(at..at.checked_add(4).ok_or(Error::Invalid("offset overflow"))?)
        .ok_or(Error::Invalid("truncated ZIP"))?
        .try_into()
        .map_err(|_| Error::Invalid("truncated ZIP"))?;
    Ok(u32::from_le_bytes(raw))
}
fn patch16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn patch32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn as_u32(size: usize) -> Result<u32> {
    u32::try_from(size).map_err(|_| Error::Invalid("ZIP32 output limit"))
}

fn has_zip64_extra(mut extra: &[u8]) -> Result<bool> {
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

struct CountedBytes(usize);
impl Write for CountedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn compressed_length(method: u16, data: &[u8]) -> Result<usize> {
    if method == 0 {
        return Ok(data.len());
    }
    let mut encoder = DeflateEncoder::new(CountedBytes(0), Compression::default());
    encoder
        .write_all(data)
        .map_err(|_| Error::Edit("compression failed"))?;
    let sink = encoder
        .finish()
        .map_err(|_| Error::Edit("compression failed"))?;
    Ok(sink.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edited_export_copies_other_zip_records_and_payloads_verbatim() {
        let original = include_bytes!("../../tests/fixtures/retained.pptx");
        let mut package = Package::open(
            original,
            Limits {
                archive_bytes: 32 * 1024 * 1024,
                entries: 1000,
                part_bytes: 16 * 1024 * 1024,
                expanded_bytes: 32 * 1024 * 1024,
                xml: XmlLimits {
                    max_depth: 256,
                    max_nodes: 100_000,
                },
            },
        )
        .expect("fixture operation");
        package
            .replace_text("ppt/slides/slide1.xml", &["root", "item"], "old", "changed")
            .expect("fixture operation");
        let edited = package.export().expect("fixture operation");
        let reopened = Package::open(
            &edited,
            Limits {
                archive_bytes: 32 * 1024 * 1024,
                entries: 1000,
                part_bytes: 16 * 1024 * 1024,
                expanded_bytes: 32 * 1024 * 1024,
                xml: XmlLimits {
                    max_depth: 256,
                    max_nodes: 100_000,
                },
            },
        )
        .expect("fixture operation");
        for (before, after) in package.entries.iter().zip(&reopened.entries) {
            if before.name == "ppt/slides/slide1.xml" {
                continue;
            }
            assert_eq!(
                &original[before.local.clone()],
                &edited[after.local.clone()],
                "local metadata and compressed payload: {}",
                before.name
            );
            let mut original_cd = original[before.central.clone()].to_vec();
            let mut edited_cd = edited[after.central.clone()].to_vec();
            original_cd[42..46].fill(0);
            edited_cd[42..46].fill(0);
            assert_eq!(original_cd, edited_cd, "central metadata: {}", before.name);
        }
        assert!(edited.ends_with(b"archive-comment"));
    }

    #[test]
    fn whole_xml_part_replacement_is_validated_and_retains_other_records() {
        let original = include_bytes!("../../tests/fixtures/retained.xlsx");
        let limits = Limits {
            archive_bytes: 1024 * 1024,
            entries: 100,
            part_bytes: 64 * 1024,
            expanded_bytes: 1024 * 1024,
            xml: XmlLimits {
                max_depth: 64,
                max_nodes: 10_000,
            },
        };
        let sheet = "xl/worksheets/sheet1.xml";
        let mut package = Package::open(original, limits).expect("fixture opens");
        for (name, bytes, reason) in [
            (sheet, &b"<root><unclosed></root>"[..], "malformed XML"),
            ("[Content_Types].xml", b"<Types/>", "package metadata"),
            ("_rels/.rels", b"<Relationships/>", "not XML"),
            ("customXml/unreachable.bin", b"<a/>", "binary part"),
            ("xl/missing.xml", b"<a/>", "missing part"),
        ] {
            assert!(
                package.replace_xml_part(name, bytes.to_vec()).is_err(),
                "{reason}"
            );
        }
        assert_eq!(package.export().expect("no-op export"), original);
        let edited = br#"<root xmlns:x="urn:ext"><item note="keep">new</item></root>"#;
        package
            .replace_xml_part(sheet, edited.to_vec())
            .expect("valid replacement");
        let output = package.export().expect("edited export");
        let reopened = Package::open(&output, limits).expect("output opens");
        assert_eq!(reopened.part(sheet).expect("sheet"), Some(edited.to_vec()));
        for name in [
            "[Content_Types].xml",
            "_rels/.rels",
            "customXml/unreachable.bin",
        ] {
            assert_eq!(
                reopened.part(name).expect("part"),
                package.part(name).expect("part"),
                "{name}"
            );
        }
    }

    #[test]
    fn one_zip_reader_serves_parts_and_retained_ranges() {
        let original = include_bytes!("../../tests/fixtures/retained.xlsx");
        let limits = Limits {
            archive_bytes: 1024 * 1024,
            entries: 100,
            part_bytes: 64 * 1024,
            expanded_bytes: 1024 * 1024,
            xml: XmlLimits {
                max_depth: 64,
                max_nodes: 10_000,
            },
        };
        let package = Package::open(original, limits).expect("fixture opens");
        assert_eq!(package.names().count(), package.entries.len());
        let mut locals: Vec<_> = package.entries.iter().map(|e| e.local.clone()).collect();
        locals.sort_by_key(|range| range.start);
        assert!(locals.windows(2).all(|pair| pair[0].end <= pair[1].start));
        for entry in &package.entries {
            // The central record, its local record and the payload the part
            // is read from all come from the same walk of the directory.
            assert!(package.cd_offset <= entry.central.start && entry.central.end <= package.eocd);
            assert!(entry.local.start <= entry.data.start && entry.data.end <= entry.local.end);
            let raw = &original[entry.data.clone()];
            let expanded = match entry.method {
                0 => raw.to_vec(),
                8 => {
                    let mut out = Vec::new();
                    DeflateDecoder::new(raw)
                        .read_to_end(&mut out)
                        .expect("fixture payload inflates");
                    out
                }
                method => panic!("unexpected fixture method {method}"),
            };
            assert_eq!(package.part(&entry.name).expect("part"), Some(expanded));
        }
    }
}
