//! Reading a package: the central directory, each entry's local record
//! checked against its central entry, and its payload copied or inflated
//! under the size ceilings.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

use oneiron_contracts::error::{ArtifactError, Error, Result};

use super::{
    CENTRAL_DIR_MIN_LEN, CENTRAL_DIR_SIGNATURE, DATA_DESCRIPTOR_FLAG, DATA_DESCRIPTOR_SIGNATURE,
    DEFLATE_OPTION_FLAGS, EOCD_MIN_LEN, EOCD_SIGNATURE, LOCAL_FILE_MIN_LEN, LOCAL_FILE_SIGNATURE,
    OpcPackage, OpcPart, ReaderSource, Source, ZIP_DEFLATE, ZIP_STORED, crc32,
};

/// Per-entry ceiling on a central-directory *declared* uncompressed size. An
/// OPC part advertising more than this is rejected before inflation, bounding a
/// single zip-bomb entry (this pipeline reasons over spreadsheet XML, not
/// arbitrary archives).
const MAX_ENTRY_UNCOMPRESSED: u64 = 256 * 1024 * 1024;
/// Whole-package ceiling on the sum of every entry's declared uncompressed
/// size, bounding an archive of many individually-modest entries.
const MAX_PACKAGE_UNCOMPRESSED: u64 = 1024 * 1024 * 1024;

/// Reads an OPC package from ZIP bytes via the central directory.
///
/// Returns [`ArtifactError::EditRoundtripFailed`](oneiron_contracts::error::ArtifactError::EditRoundtripFailed) for anything that is not a package
/// this pipeline can safely reason about — a missing/blank EOCD, a truncated
/// entry, or an unsupported compression method. Corruption checks upstream
/// rely on this failing loudly rather than guessing.
pub fn read(bytes: &[u8]) -> Result<OpcPackage> {
    read_bounded(
        bytes,
        MAX_ENTRY_UNCOMPRESSED,
        MAX_PACKAGE_UNCOMPRESSED,
        usize::from(u16::MAX),
    )
}

/// [`read`] over a package `reader` holds from its start to its end, read at
/// the offsets its ZIP records name, so a package on disk is checked without
/// its whole body in memory (FIX 22074): the same checks and caps as
/// [`read`].
///
/// # Errors
///
/// [`read`]'s errors, and the reader's.
pub fn read_from<R: Read + Seek>(reader: &mut R) -> Result<OpcPackage> {
    let len = reader.seek(SeekFrom::End(0)).map_err(Error::Io)?;
    let len = usize::try_from(len).map_err(|_| {
        Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc package past this machine's address space",
        ))
    })?;
    read_bounded(
        &ReaderSource {
            reader: RefCell::new(reader),
            len,
        },
        MAX_ENTRY_UNCOMPRESSED,
        MAX_PACKAGE_UNCOMPRESSED,
        usize::from(u16::MAX),
    )
}

/// The DOCX door resolves these limits from trusted policy rather than using
/// the spreadsheet reader's independent, fixed legacy ceiling.
pub fn read_with_limits(bytes: &[u8], limits: crate::ArchiveLimits) -> Result<OpcPackage> {
    if !limits.is_valid() {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "invalid docx archive limits",
        )));
    }
    // The DOCX entry count is an observation, never a refusal (FIX 8570):
    // the byte ceilings and the ZIP64 sentinels still bound this reader.
    read_bounded(
        bytes,
        limits.max_part_bytes,
        limits.max_total_bytes,
        usize::MAX,
    )
}

fn read_bounded<S: Source + ?Sized>(
    bytes: &S,
    max_entry: u64,
    max_package: u64,
    max_entries: usize,
) -> Result<OpcPackage> {
    let eocd = locate_eocd(bytes)?;

    // Multi-disk / spanned archives are out of scope: OPC packages are single
    // files. A non-zero disk number means the central directory this reader
    // walks is only part of the archive, so reject rather than reason over a
    // partial view.
    if read_u16(bytes, eocd + 4)? != 0 || read_u16(bytes, eocd + 6)? != 0 {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc archive spans multiple disks (unsupported)",
        )));
    }

    let entry_count = read_u16(bytes, eocd + 10)?;
    let cd_offset = read_u32(bytes, eocd + 16)?;
    // ZIP64 marks an overflowed 16/32-bit EOCD field with all-ones and moves
    // the real value into a ZIP64 record this reader does not parse. Reject the
    // sentinels loudly instead of truncating a 64-bit archive to 32 bits.
    if entry_count == u16::MAX || cd_offset == u32::MAX {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc archive uses zip64 sentinels (unsupported)",
        )));
    }
    let entry_count = entry_count as usize;
    if entry_count > max_entries {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc archive exceeds the entry-count cap",
        )));
    }

    let mut parts = Vec::with_capacity(entry_count);
    let mut seen_names = BTreeSet::new();
    // Every local record's `[start, end)` bytes, by start, for this decode.
    let mut local_ranges = BTreeMap::new();
    let mut total_declared: u64 = 0;
    let mut cursor = cd_offset as usize;
    for _ in 0..entry_count {
        if read_u32(bytes, cursor)? != CENTRAL_DIR_SIGNATURE {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc central directory header signature mismatch",
            )));
        }
        let flags = read_u16(bytes, cursor + 8)?;
        // General-purpose bit 0 marks an encrypted entry; we can neither verify
        // nor pass ciphertext through under the fidelity law.
        if flags & 0x0001 != 0 {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc entry is encrypted (unsupported)",
            )));
        }
        let method = read_u16(bytes, cursor + 10)?;
        let expected_crc = read_u32(bytes, cursor + 16)?;
        let comp_size = read_u32(bytes, cursor + 20)?;
        let declared_size = read_u32(bytes, cursor + 24)?;
        let name_len = read_u16(bytes, cursor + 28)? as usize;
        let extra_len = read_u16(bytes, cursor + 30)? as usize;
        let comment_len = read_u16(bytes, cursor + 32)? as usize;
        let disk_start = read_u16(bytes, cursor + 34)?;
        let local_offset = read_u32(bytes, cursor + 42)?;

        if disk_start != 0 {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc entry lives on another disk (unsupported)",
            )));
        }
        if comp_size == u32::MAX || declared_size == u32::MAX || local_offset == u32::MAX {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc entry uses zip64 sentinels (unsupported)",
            )));
        }

        // Zip-bomb bound: reject before inflating any entry whose declared
        // uncompressed size exceeds the per-entry cap, and any package whose
        // declared sizes sum past the whole-package cap.
        let declared_size = u64::from(declared_size);
        if declared_size > max_entry {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc entry declares an uncompressed size over the per-entry cap",
            )));
        }
        total_declared = total_declared.saturating_add(declared_size);
        if total_declared > max_package {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc package declares an uncompressed size over the package cap",
            )));
        }

        let name = read_name(bytes, cursor + CENTRAL_DIR_MIN_LEN, name_len)?;
        // OPC part names must be unique; with a duplicate, which of the two
        // same-named parts is authoritative is undefined, so the passthrough
        // law cannot be enforced. Treat it as corruption.
        if !seen_names.insert(name.clone()) {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc package has duplicate part names",
            )));
        }

        let data = read_local_entry(
            bytes,
            &CentralEntry {
                name: name.as_bytes(),
                flags,
                method,
                crc: expected_crc,
                comp_size,
                declared_size,
                local_offset: local_offset as usize,
            },
            cd_offset as usize,
            &mut local_ranges,
        )?;
        parts.push(OpcPart { name, data });

        cursor = cursor
            .checked_add(CENTRAL_DIR_MIN_LEN + name_len + extra_len + comment_len)
            .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc central directory overflow",
            )))?;
    }

    Ok(OpcPackage::from_parts(parts))
}

fn locate_eocd<S: Source + ?Sized>(bytes: &S) -> Result<usize> {
    if bytes.total_len() < EOCD_MIN_LEN {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc bytes too short for an EOCD record",
        )));
    }
    let max_back = bytes.total_len() - EOCD_MIN_LEN;
    // The EOCD comment can be up to 0xFFFF bytes; scan that far back at most,
    // over the tail read once.
    let scan_floor = max_back.saturating_sub(u16::MAX as usize);
    let tail = bytes
        .range(scan_floor, bytes.total_len() - scan_floor)?
        .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc read past end of buffer",
        )))?;
    for candidate in (scan_floor..=max_back).rev() {
        if read_u32(&tail[..], candidate - scan_floor)? == EOCD_SIGNATURE {
            return Ok(candidate);
        }
    }
    Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
        "opc end-of-central-directory record not found",
    )))
}

/// What one central-directory entry says about its local record, which the
/// local header must repeat before its payload is read.
struct CentralEntry<'a> {
    name: &'a [u8],
    flags: u16,
    method: u16,
    crc: u32,
    comp_size: u32,
    declared_size: u64,
    local_offset: usize,
}

fn read_local_entry<S: Source + ?Sized>(
    bytes: &S,
    entry: &CentralEntry<'_>,
    cd_offset: usize,
    local_ranges: &mut BTreeMap<usize, usize>,
) -> Result<Vec<u8>> {
    let local_offset = entry.local_offset;
    if read_u32(bytes, local_offset)? != LOCAL_FILE_SIGNATURE {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local file header signature mismatch",
        )));
    }
    // The local header is bound to its central entry before a byte of the
    // payload is copied or inflated. Extra fields and timestamps may differ.
    let local_flags = read_u16(bytes, local_offset + 6)?;
    if (local_flags ^ entry.flags) & !DEFLATE_OPTION_FLAGS != 0
        || read_u16(bytes, local_offset + 8)? != entry.method
    {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local header flags or method do not match its central entry",
        )));
    }
    let descriptor = entry.flags & DATA_DESCRIPTOR_FLAG != 0;
    if !descriptor
        && (read_u32(bytes, local_offset + 14)? != entry.crc
            || read_u32(bytes, local_offset + 18)? != entry.comp_size
            || u64::from(read_u32(bytes, local_offset + 22)?) != entry.declared_size)
    {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local header checksum or sizes do not match its central entry",
        )));
    }
    let local_name_len = read_u16(bytes, local_offset + 26)? as usize;
    let local_extra_len = read_u16(bytes, local_offset + 28)? as usize;
    let name_start = local_offset + LOCAL_FILE_MIN_LEN;
    if bytes.range(name_start, local_name_len)?.as_deref() != Some(entry.name) {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local header name does not match its central entry",
        )));
    }
    let data_start = local_offset
        .checked_add(LOCAL_FILE_MIN_LEN + local_name_len + local_extra_len)
        .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local data offset overflow",
        )))?;
    let data_end = data_start
        .checked_add(entry.comp_size as usize)
        .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local data length overflow",
        )))?;
    let record_end = if descriptor {
        descriptor_end(bytes, data_end, entry)?
    } else {
        data_end
    };
    if record_end > cd_offset {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local record reaches the central directory",
        )));
    }
    claim_local_range(local_ranges, local_offset, record_end)?;
    let declared_size = entry.declared_size;
    let expected_crc = entry.crc;
    // The payload streams from the source into its part, bounded by the
    // declared size: a file source never holds the compressed bytes whole.
    let data = bytes
        .with_range(data_start, data_end - data_start, |raw| {
            match entry.method {
                ZIP_STORED => read_stored(raw, declared_size),
                ZIP_DEFLATE => inflate(raw, declared_size),
                _ => Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                    "opc entry uses an unsupported compression method",
                ))),
            }
        })?
        .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc entry data truncated",
        )))?;

    // Verify the produced bytes against the central-directory declaration. The
    // gate never trusts a length or checksum it did not recompute from the
    // actual bytes: a mismatch is corruption (or a bomb capped by `inflate`).
    if data.len() as u64 != declared_size {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc entry size does not match its declared uncompressed size",
        )));
    }
    if crc32(&data) != expected_crc {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc entry crc-32 does not match its central-directory checksum",
        )));
    }
    Ok(data)
}

/// Where a bit-3 entry's record ends: past its data descriptor when one
/// follows the payload in the unsigned (12-byte) or signed (16-byte) ZIP32
/// layout, repeating the central checksum and sizes. A CRC equal to the
/// signature word can match both layouts; the shorter is taken. Anything else
/// claims no descriptor bytes: the payload is still checked against the
/// central CRC and size after it is read.
///
/// # Errors
///
/// The source's read errors: a word past the end is no descriptor, a read
/// that fails is no answer.
fn descriptor_end<S: Source + ?Sized>(
    bytes: &S,
    data_end: usize,
    entry: &CentralEntry<'_>,
) -> Result<usize> {
    let word = |at: usize| -> Result<Option<u32>> {
        let Some(offset) = data_end.checked_add(at) else {
            return Ok(None);
        };
        Ok(bytes
            .range(offset, 4)?
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]])))
    };
    let declared = u32::try_from(entry.declared_size).ok();
    Ok(
        if word(0)? == Some(entry.crc) && word(4)? == Some(entry.comp_size) && word(8)? == declared
        {
            data_end + 12
        } else if word(0)? == Some(DATA_DESCRIPTOR_SIGNATURE)
            && word(4)? == Some(entry.crc)
            && word(8)? == Some(entry.comp_size)
            && word(12)? == declared
        {
            data_end + 16
        } else {
            data_end
        },
    )
}

/// Claims one local record's `[start, end)` bytes for this decode. A record
/// starting where another starts, or overlapping either neighbour, aliases
/// another entry's bytes and is refused before its payload is read.
fn claim_local_range(ranges: &mut BTreeMap<usize, usize>, start: usize, end: usize) -> Result<()> {
    let overlaps_before = ranges
        .range(..=start)
        .next_back()
        .is_some_and(|(_, &prev_end)| prev_end > start);
    let overlaps_after = ranges
        .range(start..)
        .next()
        .is_some_and(|(&next_start, _)| next_start < end);
    if overlaps_before || overlaps_after {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc local records overlap",
        )));
    }
    ranges.insert(start, end);
    Ok(())
}

/// A STORED entry's bytes as they stream, at most one past its declared
/// size, so a longer one is refused by its size check, never held whole.
fn read_stored(raw: &mut dyn Read, declared_size: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    raw.take(declared_size.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(Error::Io)?;
    Ok(out)
}

fn inflate(raw: &mut dyn Read, declared_size: u64) -> Result<Vec<u8>> {
    // Bound the decompressor at declared+1 bytes: a well-formed entry inflates
    // to exactly `declared_size`, so reading one extra byte is enough for the
    // caller's length check to catch a stream that expands past its declaration
    // (a zip bomb) without ever buffering the full expansion.
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(raw)
        .take(declared_size.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| {
            Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc deflate entry failed to inflate",
            ))
        })?;
    Ok(out)
}

fn read_u16<S: Source + ?Sized>(bytes: &S, offset: usize) -> Result<u16> {
    let slice =
        bytes
            .range(offset, 2)?
            .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc read past end of buffer",
            )))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32<S: Source + ?Sized>(bytes: &S, offset: usize) -> Result<u32> {
    let slice =
        bytes
            .range(offset, 4)?
            .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc read past end of buffer",
            )))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_name<S: Source + ?Sized>(bytes: &S, offset: usize, len: usize) -> Result<String> {
    let raw =
        bytes
            .range(offset, len)?
            .ok_or(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "opc part name truncated",
            )))?;
    String::from_utf8(raw.to_vec()).map_err(|_| {
        Error::Artifact(ArtifactError::EditRoundtripFailed(
            "opc part name is not valid UTF-8",
        ))
    })
}
