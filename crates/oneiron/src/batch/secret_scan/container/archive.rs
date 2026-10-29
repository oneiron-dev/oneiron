//! A ZIP archive's members: each entry in central-directory order, Stored
//! or Deflated, read whole against its declared length and its CRC-32 (the
//! bounded read `batch::export::archive_read` uses). The rebuilt copy is a
//! new archive of the same entries in the same order, each with its own
//! method, time and mode; comments, extra fields and any bytes outside the
//! entries are left out.
//!
//! A scan reads those outside bytes too (FIX 2470): each run of bytes the
//! central directory's entries do not cover is handed whole when it is a
//! container the walk reads, and each local entry in it the central
//! directory does not name is decoded and handed as a member. A run or an
//! entry no reader here decodes is left to the scan of the file's own bytes.

use std::io::{Cursor, Read, Write};

use flate2::read::DeflateDecoder;
use zip::write::FileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use super::{Budget, Walked, encode_failed, hidden_member, over_budget, unreadable};
use crate::secret_custody::MemberStep;

/// The end-of-central-directory record, and the ZIP64 locator and record.
const END: &[u8] = b"PK\x05\x06";
const END_LEN: usize = 22;
const ZIP64_LOCATOR: &[u8] = b"PK\x06\x07";
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_END: &[u8] = b"PK\x06\x06";
/// The ZIP64 record and locator's least length: no record starts later
/// than this before the end record.
const ZIP64_SEARCH_GAP: usize = 60;
/// A central directory entry's least length: no archive declares more
/// entries than its bytes hold at this length (FIX 7943).
const CENTRAL_ENTRY_LEN: usize = 46;
/// A local entry's header and its least length.
const LOCAL: &[u8] = b"PK\x03\x04";
const LOCAL_LEN: usize = 30;
/// The step a member read outside the central directory takes: the scan
/// that reads it places no mark there.
const OUTSIDE: MemberStep = MemberStep::Zip { entry: u32::MAX };

/// One entry as the central directory declares it.
struct Entry {
    name: String,
    method: CompressionMethod,
    modified: DateTime,
    mode: Option<u32>,
    directory: bool,
}

/// The entry count the archive's end records declare, found as the reader
/// finds them and read before it is: the reader sizes its tables by it.
/// `None` when no record reads.
fn declared_entries(bytes: &[u8]) -> Option<u64> {
    let field = |at: usize| {
        bytes
            .get(at..at + 2)
            .map(|field| u16::from_le_bytes([field[0], field[1]]))
    };
    let last = bytes.len().checked_sub(END_LEN)?;
    let floor = last.saturating_sub(usize::from(u16::MAX));
    let at = (floor..=last)
        .rev()
        .find(|&at| bytes[at..].starts_with(END))?;
    let on_disk = field(at + 8)?;
    // The reader looks for a ZIP64 locator before an end record whose
    // comment runs to the end of the bytes.
    let comment = usize::from(field(at + 20)?);
    let Some(locator) = bytes
        .len()
        .checked_sub(ZIP64_LOCATOR_LEN + END_LEN + comment)
        .filter(|&locator| bytes[locator..].starts_with(ZIP64_LOCATOR))
    else {
        return Some(u64::from(on_disk));
    };
    let nominal = bytes.get(locator + 8..locator + 16)?.try_into().ok()?;
    let nominal = usize::try_from(u64::from_le_bytes(nominal)).ok()?;
    // The first ZIP64 record from where the locator says, as the reader
    // searches for it past any bytes prepended to the archive.
    let upper = at.checked_sub(ZIP64_SEARCH_GAP)?;
    let record = (nominal..=upper).find(|&at| bytes[at..].starts_with(ZIP64_END))?;
    let count = bytes.get(record + 32..record + 40)?.try_into().ok()?;
    Some(u64::from_le_bytes(count))
}

fn open(bytes: &[u8]) -> Walked<ZipArchive<Cursor<&[u8]>>> {
    // The reader sizes its tables by the declared count: a count the bytes
    // cannot hold is a malformed archive, never a bound.
    let declared = declared_entries(bytes).ok_or_else(unreadable)?;
    if usize::try_from(declared).map_or(true, |declared| declared > bytes.len() / CENTRAL_ENTRY_LEN)
    {
        return Err(unreadable());
    }
    let archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| unreadable())?;
    // The reader keeps one entry per name: a name held twice is ambiguous.
    if archive.file_names().count() != archive.len() {
        return Err(unreadable());
    }
    Ok(archive)
}

/// Whether `bytes`' frame parses as an archive: an end record and a
/// central directory the reader opens (FIX 2474).
pub(super) fn opens(bytes: &[u8]) -> bool {
    open(bytes).is_ok()
}

/// Entry `index`, read whole, with the bytes its local header and data
/// cover in the archive.
fn read(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
    budget: &mut Budget,
) -> Walked<(Entry, Vec<u8>, (u64, u64))> {
    let mut file = archive.by_index(index).map_err(|_| unreadable())?;
    // Only these two decode here. Checked before the first read: the
    // reader picks its decoder then, and has no arm for some methods.
    let method = file.compression();
    if method != CompressionMethod::Stored && method != CompressionMethod::Deflated {
        return Err(unreadable());
    }
    let declared = file.size();
    if usize::try_from(declared).map_or(true, |declared| declared > budget.limit()) {
        return Err(over_budget());
    }
    let entry = Entry {
        name: file.name().to_owned(),
        method,
        modified: file.last_modified(),
        mode: file.unix_mode(),
        directory: file.is_dir(),
    };
    let covered = (
        file.header_start(),
        file.data_start().saturating_add(file.compressed_size()),
    );
    // One byte past the declared length catches a longer stream, and
    // reading to the end checks the CRC-32.
    let mut data = Vec::new();
    file.by_ref()
        .take(declared.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|_| unreadable())?;
    if data.len() as u64 != declared {
        return Err(unreadable());
    }
    budget.spend(data.len())?;
    Ok((entry, data, covered))
}

fn step(index: usize) -> Walked<MemberStep> {
    let entry = u32::try_from(index).map_err(|_| over_budget())?;
    Ok(MemberStep::Zip { entry })
}

pub(super) fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let mut archive = open(bytes)?;
    let mut covered = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let (_, data, span) = read(&mut archive, index, budget)?;
        covered.push(span);
        each(step(index)?, &data, budget)?;
    }
    if budget.hidden {
        outside(bytes, covered, budget, each)?;
    }
    Ok(())
}

/// The bytes outside the central directory's entries (FIX 2470): each run
/// `covered` leaves, handed whole when it is a container the walk reads,
/// and each local entry in it decoded.
fn outside(
    bytes: &[u8],
    mut covered: Vec<(u64, u64)>,
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let at = |offset: u64| usize::try_from(offset).map_or(bytes.len(), |at| at.min(bytes.len()));
    covered.sort_unstable();
    let mut runs = Vec::new();
    let mut end = 0;
    for (from, to) in covered {
        if at(from) > end {
            runs.push(end..at(from));
        }
        end = end.max(at(to));
    }
    runs.push(end..bytes.len());
    for run in runs {
        let run = &bytes[run];
        if run.is_empty() {
            continue;
        }
        if super::classify(run).is_some() && hidden_member(run) {
            each(OUTSIDE, run, budget)?;
        }
        for (local, head) in run.windows(LOCAL.len()).enumerate() {
            if head == LOCAL
                && let Some(data) = local_entry(&run[local..], budget)?
                && hidden_member(&data)
            {
                each(OUTSIDE, &data, budget)?;
            }
        }
    }
    Ok(())
}

/// The data of the local entry `bytes` start with, decoded: Stored at the
/// length its header declares, or Deflated to its stream's own end, charged
/// to the walk. `None` when it does not decode.
fn local_entry(bytes: &[u8], budget: &mut Budget) -> Walked<Option<Vec<u8>>> {
    let field = |at: usize, len: usize| {
        bytes.get(at..at + len).map(|field| {
            field
                .iter()
                .rev()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
        })
    };
    let (Some(method), Some(compressed), Some(name), Some(extra)) =
        (field(8, 2), field(18, 4), field(26, 2), field(28, 2))
    else {
        return Ok(None);
    };
    let Some(data) = usize::try_from(name + extra)
        .ok()
        .and_then(|header| bytes.get(LOCAL_LEN + header..))
    else {
        return Ok(None);
    };
    let limit = budget.limit();
    let decoded = match method {
        0 => usize::try_from(compressed)
            .ok()
            .filter(|&len| len > 0)
            .and_then(|len| data.get(..len))
            .map(<[u8]>::to_vec),
        8 => {
            let mut decoded = Vec::new();
            DeflateDecoder::new(data)
                .take((limit as u64).saturating_add(1))
                .read_to_end(&mut decoded)
                .ok()
                .map(|_| decoded)
        }
        _ => None,
    };
    let Some(decoded) = decoded.filter(|decoded| !decoded.is_empty()) else {
        return Ok(None);
    };
    if decoded.len() > limit {
        return Err(over_budget());
    }
    budget.spend(decoded.len())?;
    Ok(Some(decoded))
}

pub(super) fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let mut archive = open(bytes)?;
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let (entry, data, _) = read(&mut archive, index, budget)?;
        let data = each(step(index)?, &data, budget)?.unwrap_or(data);
        let mut options = FileOptions::default()
            .compression_method(entry.method)
            .last_modified_time(entry.modified);
        if let Some(mode) = entry.mode {
            options = options.unix_permissions(mode);
        }
        if entry.directory && data.is_empty() {
            out.add_directory(entry.name, options)
                .map_err(|_| encode_failed())?;
        } else {
            out.start_file(entry.name, options)
                .map_err(|_| encode_failed())?;
            out.write_all(&data).map_err(|_| encode_failed())?;
        }
    }
    let out = out.finish().map_err(|_| encode_failed())?;
    Ok(out.into_inner())
}
