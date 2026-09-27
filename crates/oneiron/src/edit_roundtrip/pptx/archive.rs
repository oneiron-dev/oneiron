//! Retained ZIP records: unchanged entries keep compression, metadata and local bytes.

use super::super::opc;
use super::package::{PatchResult, PptxError};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Archive<'a> {
    bytes: &'a [u8],
    pub parts: BTreeMap<String, Vec<u8>>,
    entries: Vec<(String, Vec<u8>, std::ops::Range<usize>)>,
    comment: Vec<u8>,
}
impl<'a> Archive<'a> {
    pub(super) fn read(bytes: &'a [u8]) -> PatchResult<Self> {
        let package = opc::read(bytes).map_err(|_| PptxError::InvalidPackage)?;
        let minimum = bytes
            .len()
            .checked_sub(22)
            .ok_or(PptxError::InvalidPackage)?;
        let eocd = (minimum.saturating_sub(65535)..=minimum)
            .rev()
            .find(|&p| {
                bytes.get(p..p + 4) == Some(&[0x50, 0x4b, 0x05, 0x06])
                    && u16_at(bytes, p + 20).is_ok_and(|n| p + 22 + usize::from(n) == bytes.len())
            })
            .ok_or(PptxError::InvalidPackage)?;
        let directory = u32_at(bytes, eocd + 16)? as usize;
        if directory.checked_add(u32_at(bytes, eocd + 12)? as usize) != Some(eocd)
            || u16_at(bytes, eocd + 8)? != u16_at(bytes, eocd + 10)?
        {
            return Err(PptxError::InvalidPackage);
        }
        let mut entries = Vec::new();
        let mut cursor = directory;
        let mut ranges = Vec::new();
        for part in package.parts() {
            validate_name(&part.name)?;
            let name_len = usize::from(u16_at(bytes, cursor + 28)?);
            let length = 46
                + name_len
                + usize::from(u16_at(bytes, cursor + 30)?)
                + usize::from(u16_at(bytes, cursor + 32)?);
            let central = bytes
                .get(cursor..cursor + length)
                .ok_or(PptxError::InvalidPackage)?
                .to_vec();
            let local = u32_at(&central, 42)? as usize;
            let ln = usize::from(u16_at(bytes, local + 26)?);
            let le = usize::from(u16_at(bytes, local + 28)?);
            let end = local
                .checked_add(30 + ln + le)
                .and_then(|n| n.checked_add(u32_at(&central, 20).ok()? as usize))
                .ok_or(PptxError::InvalidPackage)?;
            if end > directory
                || bytes.get(local + 30..local + 30 + ln) != Some(part.name.as_bytes())
                || u16_at(bytes, local + 6)? != u16_at(&central, 8)?
                || u16_at(bytes, local + 8)? != u16_at(&central, 10)?
            {
                return Err(PptxError::InvalidPackage);
            }
            // With a data descriptor, the CRC/sizes live after compressed data.
            let end = if u16_at(&central, 8)? & 0x0008 != 0 {
                let descriptor = if u32_at(bytes, end)? == 0x0807_4b50 {
                    end + 4
                } else {
                    end
                };
                if bytes.get(descriptor..descriptor + 12) != Some(&central[16..28]) {
                    return Err(PptxError::InvalidPackage);
                }
                descriptor + 12
            } else {
                end
            };
            if end > directory {
                return Err(PptxError::InvalidPackage);
            }
            ranges.push((local, end));
            entries.push((part.name.clone(), central, local..end));
            cursor += length;
        }
        ranges.sort_unstable();
        // Unknown local records are not legitimate pass-through parts. Refuse
        // them rather than preserving an archive PowerPoint may offer to repair.
        if cursor != eocd
            || ranges.first().map_or(directory != 0, |range| range.0 != 0)
            || ranges.windows(2).any(|w| w[0].1 != w[1].0)
            || ranges.last().is_some_and(|range| range.1 != directory)
        {
            return Err(PptxError::InvalidPackage);
        }
        Ok(Self {
            bytes,
            parts: package
                .parts()
                .iter()
                .map(|p| (p.name.clone(), p.data.clone()))
                .collect(),
            entries,
            comment: bytes[eocd + 22..].to_vec(),
        })
    }
    pub(super) fn text(&self, name: &str) -> PatchResult<&str> {
        std::str::from_utf8(self.parts.get(name).ok_or(PptxError::InvalidReference)?)
            .map_err(|_| PptxError::InvalidXml)
    }
    /// No-op returns the original ZIP. Mutations copy only live unchanged
    /// local records byte-for-byte; obsolete records must not survive behind
    /// a new central directory (PowerPoint offers to repair such archives).
    pub(super) fn write(&self, parts: &BTreeMap<String, Vec<u8>>) -> PatchResult<Vec<u8>> {
        if parts == &self.parts {
            return Ok(self.bytes.to_vec());
        }
        if parts.len() >= usize::from(u16::MAX)
            || self.parts.keys().any(|name| !parts.contains_key(name))
        {
            return Err(PptxError::InvalidPackage);
        }
        let mut out = Vec::new();
        let mut central = Vec::new();
        let mut seen = BTreeSet::new();
        for (name, record, local) in &self.entries {
            seen.insert(name.as_str());
            if parts.get(name) == self.parts.get(name) {
                let offset = u32::try_from(out.len()).map_err(|_| PptxError::InvalidPackage)?;
                out.extend_from_slice(&self.bytes[local.clone()]);
                let mut relocated = record.clone();
                relocated[42..46].copy_from_slice(&offset.to_le_bytes());
                central.extend_from_slice(&relocated);
            } else {
                append_entry(&mut out, &mut central, name, &parts[name])?;
            }
        }
        for (name, data) in parts {
            if !seen.contains(name.as_str()) {
                append_entry(&mut out, &mut central, name, data)?;
            }
        }
        let offset = u32::try_from(out.len()).map_err(|_| PptxError::InvalidPackage)?;
        let size = u32::try_from(central.len()).map_err(|_| PptxError::InvalidPackage)?;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x06054b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        let count = parts.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.comment);
        Ok(out)
    }
}
pub(super) fn changed(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
) -> BTreeSet<String> {
    before
        .keys()
        .chain(after.keys())
        .filter(|name| before.get(*name) != after.get(*name))
        .cloned()
        .collect()
}
pub(super) fn enforce_allowlist(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
    allowed: &BTreeSet<String>,
) -> PatchResult<BTreeSet<String>> {
    let actual = changed(before, after);
    if !actual.is_subset(allowed) {
        return Err(PptxError::PartDiffOutsideTransaction);
    }
    Ok(actual)
}
fn append_entry(
    out: &mut Vec<u8>,
    central: &mut Vec<u8>,
    name: &str,
    data: &[u8],
) -> PatchResult<()> {
    validate_name(name)?;
    let name_len = u16::try_from(name.len()).map_err(|_| PptxError::InvalidPackage)?;
    let size = u32::try_from(data.len()).map_err(|_| PptxError::InvalidPackage)?;
    let offset = u32::try_from(out.len()).map_err(|_| PptxError::InvalidPackage)?;
    let mut crc = flate2::Crc::new();
    crc.update(data);
    let mut local = Vec::new();
    local.extend_from_slice(&0x04034b50u32.to_le_bytes());
    local.extend_from_slice(&20u16.to_le_bytes());
    local.extend_from_slice(&0x800u16.to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes()); // STORED
    local.extend_from_slice(&0u16.to_le_bytes()); // midnight
    local.extend_from_slice(&0x0021u16.to_le_bytes()); // 1980-01-01 DOS date
    local.extend_from_slice(&crc.sum().to_le_bytes());
    local.extend_from_slice(&size.to_le_bytes());
    local.extend_from_slice(&size.to_le_bytes());
    local.extend_from_slice(&name_len.to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&local);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    central.extend_from_slice(&0x02014b50u32.to_le_bytes());
    central.extend_from_slice(&20u16.to_le_bytes());
    central.extend_from_slice(&local[4..28]);
    central.extend_from_slice(&[0; 12]);
    central.extend_from_slice(&offset.to_le_bytes());
    central.extend_from_slice(name.as_bytes());
    Ok(())
}
fn validate_name(name: &str) -> PatchResult<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains(['\\', ':', '%', '\0', '?', '#'])
        || name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(PptxError::InvalidPackage);
    }
    Ok(())
}
fn u16_at(bytes: &[u8], at: usize) -> PatchResult<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(PptxError::InvalidPackage)?
            .try_into()
            .map_err(|_| PptxError::InvalidPackage)?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> PatchResult<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(PptxError::InvalidPackage)?
            .try_into()
            .map_err(|_| PptxError::InvalidPackage)?,
    ))
}
