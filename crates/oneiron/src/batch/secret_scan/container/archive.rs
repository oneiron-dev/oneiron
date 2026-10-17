//! A ZIP archive's members: each entry in central-directory order, Stored
//! or Deflated, read whole against its declared length and its CRC-32 (the
//! bounded read `batch::export::archive_read` uses). The rebuilt copy is a
//! new archive of the same entries in the same order, each with its own
//! method, time and mode; comments, extra fields and any bytes outside the
//! entries are left out.

use std::io::{Cursor, Read, Write};

use zip::write::FileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use super::{Budget, Walked, encode_failed, over_budget, unreadable};
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

fn open<'b>(bytes: &'b [u8], budget: &Budget) -> Walked<ZipArchive<Cursor<&'b [u8]>>> {
    let declared = declared_entries(bytes).ok_or_else(unreadable)?;
    if usize::try_from(declared).map_or(true, |declared| declared > budget.members) {
        return Err(over_budget());
    }
    let archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| unreadable())?;
    // The reader keeps one entry per name: a name held twice is ambiguous.
    if archive.file_names().count() != archive.len() {
        return Err(unreadable());
    }
    Ok(archive)
}

/// Entry `index`, read whole.
fn read(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
    budget: &mut Budget,
) -> Walked<(Entry, Vec<u8>)> {
    budget.member()?;
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
    Ok((entry, data))
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
    let mut archive = open(bytes, budget)?;
    for index in 0..archive.len() {
        let (_, data) = read(&mut archive, index, budget)?;
        each(step(index)?, &data, budget)?;
    }
    Ok(())
}

pub(super) fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let mut archive = open(bytes, budget)?;
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let (entry, data) = read(&mut archive, index, budget)?;
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
