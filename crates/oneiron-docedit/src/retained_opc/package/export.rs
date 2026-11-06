//! Copy-through ZIP export under the package's original resource operation.

use super::{CENTRAL, Error, LOCAL, Package, Result, as_u32, patch16, patch32};
use crate::resource::{Dimension, wide};
use flate2::{Compression, write::DeflateEncoder};
use std::io::Write;

impl Package {
    /// Export an exact original archive on no-op. After an edit, retain all
    /// untouched local records and compressed payloads, patch central offsets,
    /// replace only edited entry payload/header/checksum fields, and leave out
    /// removed entries' local and central records.
    pub fn export(&self) -> Result<Vec<u8>> {
        if self.added.is_empty()
            && self
                .entries
                .iter()
                .all(|entry| entry.replacement.is_none() && !entry.removed)
        {
            let backing = self.resources.reserve(wide(self.source.len()))?;
            let mut out = Output::new(backing, wide(self.source.len()), self.source.len())?;
            out.extend_from_slice(&self.source)?;
            return Ok(out.finish());
        }
        // The output, each replacement's compressed copy and every added
        // record, reserved before any is allocated.
        let replaced = self
            .entries
            .iter()
            .filter_map(|entry| entry.replacement.as_ref())
            .fold(0usize, |sum, data| sum.saturating_add(data.len()));
        let added = self.added_archive_bytes()?;
        // Every byte the output carries over is measured (FIX 10656): the
        // source, less each removed entry's records and each replaced
        // entry's old payload and data descriptor, and the added records.
        // The replacements' compressed copies are the estimate.
        let carried = self.entries.iter().fold(
            wide(self.source.len()).saturating_add(wide(added)),
            |sum, entry| {
                if entry.removed {
                    sum.saturating_sub(wide(entry.local.len() + entry.central.len()))
                } else if entry.replacement.is_some() {
                    sum.saturating_sub(wide(entry.trailer.saturating_sub(entry.data.start)))
                } else {
                    sum
                }
            },
        );
        let backing = self.resources.reserve_estimate(
            wide(self.source.len())
                .saturating_add(wide(replaced).saturating_mul(2))
                .saturating_add(wide(added)),
            carried,
        )?;
        let output_capacity = wide(self.source.len())
            .saturating_add(wide(replaced))
            .saturating_add(wide(added));
        let mut out = Output::new(backing, output_capacity, self.source.len())?;
        let mut offsets = vec![0u32; self.entries.len()];
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        order.sort_unstable_by_key(|&i| self.entries[i].local.start);
        let first = order
            .first()
            .map_or(self.cd_offset, |&i| self.entries[i].local.start);
        out.extend_from_slice(&self.source[..first])?;
        for index in order {
            let entry = &self.entries[index];
            if entry.removed {
                continue;
            }
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
                out.extend_from_slice(&header)?;
                out.extend_from_slice(&compressed)?;
                out.extend_from_slice(&self.source[entry.trailer..entry.local.end])?;
            } else {
                out.extend_from_slice(&self.source[entry.local.clone()])?;
            }
        }
        let mut added_offsets = Vec::with_capacity(self.added.len());
        for part in &self.added {
            added_offsets.push(as_u32(out.len())?);
            out.extend_from_slice(&part.header(LOCAL, None)?)?;
            out.extend_from_slice(&part.deflated)?;
        }
        let cd_offset = as_u32(out.len())?;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.removed {
                continue;
            }
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
            out.extend_from_slice(&record)?;
        }
        for (part, offset) in self.added.iter().zip(added_offsets) {
            out.extend_from_slice(&part.header(CENTRAL, Some(offset))?)?;
        }
        let cd_size = as_u32(out.len() - cd_offset as usize)?;
        let mut footer = self.source[self.eocd..].to_vec();
        let kept = self.entries.iter().filter(|entry| !entry.removed).count();
        let count = u16::try_from(kept + self.added.len()).map_err(|_| {
            Error::capacity_hit(
                Dimension::ZipEntries,
                kept + self.added.len(),
                usize::from(u16::MAX),
            )
        })?;
        patch16(&mut footer, 8, count);
        patch16(&mut footer, 10, count);
        patch32(&mut footer, 12, cd_size);
        patch32(&mut footer, 16, cd_offset);
        out.extend_from_slice(&footer)?;
        if out.len() > self.limits.archive_bytes {
            return Err(Error::capacity_hit(
                Dimension::ArchiveBytes,
                out.len(),
                self.limits.archive_bytes,
            ));
        }
        Ok(out.finish())
    }
}

/// The original export reservation also covers compression scratch. Only
/// capacity past its output share needs another take from the same hold.
struct Output {
    bytes: Vec<u8>,
    backing: crate::resource::Hold,
    admitted: u64,
}

impl Output {
    fn new(backing: crate::resource::Hold, admitted: u64, capacity: usize) -> Result<Self> {
        let mut output = Self {
            bytes: Vec::with_capacity(capacity),
            backing,
            admitted,
        };
        output.admit(output.bytes.capacity())?;
        Ok(output)
    }

    fn admit(&mut self, capacity: usize) -> Result<()> {
        let capacity = wide(capacity);
        if capacity > self.admitted {
            self.backing.take(capacity - self.admitted)?;
            self.admitted = capacity;
        }
        Ok(())
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        let length = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            Error::capacity_hit(Dimension::ZipBytes, usize::MAX, u32::MAX as usize)
        })?;
        if length > self.bytes.capacity() {
            self.admit(length)?;
            self.bytes.reserve_exact(length - self.bytes.len());
            self.admit(self.bytes.capacity())?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn finish(self) -> Vec<u8> {
        // The server hands allocated bytes to live memory when this hold drops.
        self.bytes
    }
}
