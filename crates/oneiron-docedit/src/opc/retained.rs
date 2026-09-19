//! Retained ZIP records: untouched local records and central metadata are copied verbatim.
use super::archive;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ops::Range;

/// Allocation ceilings, checked against directory declarations before decompression.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub archive_bytes: usize,
    pub part_bytes: usize,
    pub total_part_bytes: usize,
    pub parts: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            archive_bytes: 128 * 1024 * 1024,
            part_bytes: 64 * 1024 * 1024,
            total_part_bytes: 256 * 1024 * 1024,
            parts: 4096,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    central: Range<usize>,
    local: Range<usize>,
    data_start: usize,
}
#[derive(Debug, Clone)]
struct Layout {
    entries: Vec<Entry>,
    eocd: usize,
    cd_start: usize,
}

/// An opened OPC package retaining the original archive and all unknown part bytes.
#[derive(Debug, Clone)]
pub struct Package {
    original: Vec<u8>,
    parsed: archive::OpcPackage,
    layout: Layout,
    edits: BTreeMap<String, Vec<u8>>,
    added: Vec<archive::OpcPart>,
    limits: Limits,
}
impl Package {
    pub fn open(bytes: &[u8], limits: Limits) -> Result<Self> {
        if bytes.len() > limits.archive_bytes {
            return invalid("archive byte limit");
        }
        let layout = layout(bytes, limits)?;
        let parsed = archive::read(bytes)?;
        Ok(Self {
            original: bytes.to_vec(),
            parsed,
            layout,
            edits: BTreeMap::new(),
            added: Vec::new(),
            limits,
        })
    }
    #[must_use]
    pub fn part(&self, name: &str) -> Option<&[u8]> {
        self.edits
            .get(name)
            .map(Vec::as_slice)
            .or_else(|| self.parsed.part(name))
            .or_else(|| {
                self.added
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| p.data.as_slice())
            })
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.parsed
            .names()
            .chain(self.added.iter().map(|p| p.name.as_str()))
    }

    /// Append a new part without re-emitting any existing archive record.
    pub fn insert(&mut self, name: &str, bytes: Vec<u8>) -> Result<()> {
        validate_name(name)?;
        if self.part(name).is_some() {
            return invalid("part already exists");
        }
        let count = self.layout.entries.len() + self.added.len();
        if count >= self.limits.parts || count + 1 >= u16::MAX as usize {
            return invalid("part count limit");
        }
        if bytes.len() > self.limits.part_bytes {
            return invalid("part byte limit");
        }
        let total = self.names().try_fold(bytes.len(), |sum, other| {
            sum.checked_add(self.part(other).map_or(0, <[u8]>::len))
                .ok_or(Error::InvalidPackage("part size overflow"))
        })?;
        if total > self.limits.total_part_bytes {
            return invalid("total part byte limit");
        }
        self.added.push(archive::OpcPart {
            name: name.into(),
            data: bytes,
        });
        Ok(())
    }

    /// Replace an existing part. Unchanged parts retain their original compressed bytes,
    /// extra fields, ordering, and metadata. A byte-identical replacement is a no-op.
    pub fn replace(&mut self, name: &str, bytes: Vec<u8>) -> Result<()> {
        let original = self
            .parsed
            .part(name)
            .or_else(|| {
                self.added
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| p.data.as_slice())
            })
            .ok_or(Error::InvalidPackage("missing part"))?;
        if bytes.len() > self.limits.part_bytes {
            return invalid("part byte limit");
        }
        let mut total = bytes.len();
        for other in self.names().filter(|other| *other != name) {
            total = total
                .checked_add(self.part(other).map_or(0, <[u8]>::len))
                .ok_or(Error::InvalidPackage("part size overflow"))?;
        }
        if total > self.limits.total_part_bytes {
            return invalid("total part byte limit");
        }
        if original == bytes {
            self.edits.remove(name);
        } else {
            self.edits.insert(name.into(), bytes);
        }
        Ok(())
    }

    /// Checked byte-range editing for native XML writers. Unknown XML outside the
    /// selected range stays in place, including whitespace, prefixes and extensions.
    pub fn splice(
        &mut self,
        name: &str,
        range: Range<usize>,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<()> {
        let source = self
            .part(name)
            .ok_or(Error::InvalidPackage("missing part"))?;
        if source.get(range.clone()) != Some(expected) {
            return invalid("XML edit base mismatch");
        }
        let size = source
            .len()
            .checked_sub(range.len())
            .and_then(|n| n.checked_add(replacement.len()))
            .ok_or(Error::InvalidPackage("XML edit length overflow"))?;
        if size > self.limits.part_bytes {
            return invalid("part byte limit");
        }
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&source[..range.start]);
        bytes.extend_from_slice(replacement);
        bytes.extend_from_slice(&source[range.end..]);
        self.replace(name, bytes)
    }

    /// No edits returns the original archive, not a recompressed approximation.
    pub fn write(&self) -> Result<Vec<u8>> {
        if self.edits.is_empty() && self.added.is_empty() {
            return Ok(self.original.clone());
        }
        let mut physical: Vec<_> = self.layout.entries.iter().collect();
        physical.sort_by_key(|entry| entry.local.start);
        let prefix_end = physical
            .first()
            .map_or(self.layout.cd_start, |entry| entry.local.start);
        let mut out = self.original[..prefix_end].to_vec();
        let mut offsets = BTreeMap::new();
        for entry in physical {
            offsets.insert(&entry.name, narrow(out.len())?);
            if let Some(bytes) = self.edits.get(&entry.name) {
                let mut header = self.original[entry.local.start..entry.data_start].to_vec();
                update_local(&mut header, bytes)?;
                out.extend_from_slice(&header);
                out.extend_from_slice(bytes);
            } else {
                out.extend_from_slice(&self.original[entry.local.clone()]);
            }
            if out.len() > self.limits.archive_bytes {
                return invalid("archive byte limit");
            }
        }
        let added_size = self.added.iter().try_fold(22usize, |sum, part| {
            sum.checked_add(self.part(&part.name).map_or(0, <[u8]>::len))
                .and_then(|n| n.checked_add(76 + 2 * part.name.len()))
                .ok_or(Error::InvalidPackage("added archive size overflow"))
        })?;
        if added_size > self.limits.archive_bytes {
            return invalid("archive byte limit");
        }
        let new_parts = self
            .added
            .iter()
            .map(|part| archive::OpcPart {
                name: part.name.clone(),
                data: self.part(&part.name).unwrap_or_default().to_vec(),
            })
            .collect();
        let appended = archive::write(&archive::OpcPackage::from_parts(new_parts));
        let appended_layout = layout(&appended, self.limits)?;
        let appended_offset = narrow(out.len())?;
        if out
            .len()
            .checked_add(appended_layout.cd_start)
            .is_none_or(|n| n > self.limits.archive_bytes)
        {
            return invalid("archive byte limit");
        }
        out.extend_from_slice(&appended[..appended_layout.cd_start]);
        let cd_start = narrow(out.len())?;
        for entry in &self.layout.entries {
            let mut central = self.original[entry.central.clone()].to_vec();
            put32(&mut central, 42, offsets[&entry.name]);
            if let Some(bytes) = self.edits.get(&entry.name) {
                let flags = read16(&central, 8)? & !14;
                put16(&mut central, 8, flags);
                put16(&mut central, 10, 0);
                put32(&mut central, 16, crc(bytes));
                put32(&mut central, 20, narrow(bytes.len())?);
                put32(&mut central, 24, narrow(bytes.len())?);
            }
            out.extend_from_slice(&central);
        }
        for entry in &appended_layout.entries {
            let mut central = appended[entry.central.clone()].to_vec();
            let offset = appended_offset
                .checked_add(narrow(entry.local.start)?)
                .ok_or(Error::InvalidPackage("ZIP32 offset overflow"))?;
            put32(&mut central, 42, offset);
            out.extend_from_slice(&central);
        }
        let cd_size = narrow(out.len())? - cd_start;
        let mut eocd = self.original[self.layout.eocd..].to_vec();
        let count = u16::try_from(self.layout.entries.len() + self.added.len())
            .map_err(|_| Error::InvalidPackage("part count overflow"))?;
        put16(&mut eocd, 8, count);
        put16(&mut eocd, 10, count);
        put32(&mut eocd, 12, cd_size);
        put32(&mut eocd, 16, cd_start);
        out.extend_from_slice(&eocd);
        if out.len() > self.limits.archive_bytes {
            return invalid("archive byte limit");
        }
        Ok(out)
    }
}

fn layout(bytes: &[u8], limits: Limits) -> Result<Layout> {
    let last = bytes
        .len()
        .checked_sub(22)
        .ok_or(Error::InvalidPackage("missing EOCD"))?;
    let eocd = (last.saturating_sub(u16::MAX as usize)..=last)
        .rev()
        .find(|&offset| {
            read32(bytes, offset).ok() == Some(0x0605_4b50)
                && read16(bytes, offset + 20)
                    .is_ok_and(|len| offset + 22 + usize::from(len) == bytes.len())
        })
        .ok_or(Error::InvalidPackage("missing EOCD"))?;
    let count = usize::from(read16(bytes, eocd + 10)?);
    if count > limits.parts || count == u16::MAX as usize {
        return invalid("part count limit");
    }
    if read16(bytes, eocd + 4)? != 0
        || read16(bytes, eocd + 6)? != 0
        || usize::from(read16(bytes, eocd + 8)?) != count
    {
        return invalid("spanned ZIP archive");
    }
    let cd_start = read32(bytes, eocd + 16)? as usize;
    let cd_size = read32(bytes, eocd + 12)? as usize;
    if cd_start.checked_add(cd_size) != Some(eocd) {
        return invalid("central directory bounds");
    }
    let mut cursor = cd_start;
    let mut total = 0usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if read32(bytes, cursor)? != 0x0201_4b50 {
            return invalid("central directory signature");
        }
        let size = read32(bytes, cursor + 24)? as usize;
        total = total
            .checked_add(size)
            .ok_or(Error::InvalidPackage("part size overflow"))?;
        if size > limits.part_bytes || total > limits.total_part_bytes {
            return invalid("declared part byte limit");
        }
        let name_len = usize::from(read16(bytes, cursor + 28)?);
        let row_len = 46
            + name_len
            + usize::from(read16(bytes, cursor + 30)?)
            + usize::from(read16(bytes, cursor + 32)?);
        let end = cursor
            .checked_add(row_len)
            .ok_or(Error::InvalidPackage("central row overflow"))?;
        if end > eocd {
            return invalid("central row bounds");
        }
        let name_bytes = slice(bytes, cursor + 46, name_len)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| Error::InvalidPackage("non UTF-8 part name"))?
            .to_owned();
        validate_name(&name)?;
        let flags = read16(bytes, cursor + 8)?;
        let method = read16(bytes, cursor + 10)?;
        // OPC supports stored/deflate entries, never encryption, patched data,
        // masked headers, split disks, or unrecognized flag semantics.
        if flags & !0x080e != 0
            || !matches!(method, 0 | 8)
            || (method == 0 && flags & 6 != 0)
            || read16(bytes, cursor + 34)? != 0
        {
            return invalid("unsupported ZIP flags, compression, or disk");
        }
        let local = read32(bytes, cursor + 42)? as usize;
        if read32(bytes, local)? != 0x0403_4b50
            || read16(bytes, local + 6)? != read16(bytes, cursor + 8)?
            || read16(bytes, local + 8)? != read16(bytes, cursor + 10)?
            || usize::from(read16(bytes, local + 26)?) != name_len
            || slice(bytes, local + 30, name_len)? != name_bytes
        {
            return invalid("local/central header mismatch");
        }
        for (local_field, central_field) in [(14, 16), (18, 20), (22, 24)] {
            let declared = read32(bytes, local + local_field)?;
            let actual = read32(bytes, cursor + central_field)?;
            if declared != actual && !(flags & 8 != 0 && declared == 0) {
                return invalid("local/central CRC or size mismatch");
            }
        }
        let data_start = local
            .checked_add(30 + name_len + usize::from(read16(bytes, local + 28)?))
            .ok_or(Error::InvalidPackage("local header overflow"))?;
        let data_end = data_start
            .checked_add(read32(bytes, cursor + 20)? as usize)
            .ok_or(Error::InvalidPackage("entry payload overflow"))?;
        if data_end > cd_start {
            return invalid("entry payload overlaps directory");
        }
        let mut record_end = data_end;
        if flags & 8 != 0 {
            let descriptor = if read32(bytes, data_end)? == 0x0807_4b50 {
                data_end + 4
            } else {
                data_end
            };
            for (offset, central_field) in [(0, 16), (4, 20), (8, 24)] {
                if read32(bytes, descriptor + offset)? != read32(bytes, cursor + central_field)? {
                    return invalid("data descriptor mismatch");
                }
            }
            record_end = descriptor + 12;
            if record_end > cd_start {
                return invalid("data descriptor overlaps directory");
            }
        }
        entries.push(Entry {
            name,
            central: cursor..end,
            local: local..record_end,
            data_start,
        });
        cursor = end;
    }
    if cursor != eocd {
        return invalid("central directory count mismatch");
    }
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| entries[i].local.start);
    for (position, &index) in order.iter().enumerate() {
        let end = order
            .get(position + 1)
            .map_or(cd_start, |&next| entries[next].local.start);
        if entries[index].local.end > end {
            return invalid("overlapping local entries");
        }
        entries[index].local.end = end;
    }
    Ok(Layout {
        entries,
        eocd,
        cd_start,
    })
}
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > u16::MAX as usize
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.split('/').any(|part| part == "." || part == "..")
    {
        return invalid("unsafe OPC part name");
    }
    Ok(())
}

fn update_local(header: &mut [u8], bytes: &[u8]) -> Result<()> {
    let flags = read16(header, 6)? & !14;
    put16(header, 6, flags);
    put16(header, 8, 0);
    put32(header, 14, crc(bytes));
    put32(header, 18, narrow(bytes.len())?);
    put32(header, 22, narrow(bytes.len())?);
    Ok(())
}
fn narrow(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::InvalidPackage("ZIP32 size overflow"))
}
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}
fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(Error::InvalidPackage(reason))
}
fn slice(bytes: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or(Error::InvalidPackage("ZIP offset overflow"))?;
    bytes
        .get(start..end)
        .ok_or(Error::InvalidPackage("truncated ZIP record"))
}
fn read16(bytes: &[u8], offset: usize) -> Result<u16> {
    let b = slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn read32(bytes: &[u8], offset: usize) -> Result<u32> {
    let b = slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests;
