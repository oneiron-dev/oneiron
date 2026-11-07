//! A 7z archive's members (FIX 11575): each entry with data, by its place
//! in the archive's file list, decoded whole against its declared size and
//! CRC under the walk's budget. Directories, entries with no data and anti
//! items are not members. The archive is read with no password, so an
//! encrypted archive or header, like a coder no reader here decodes, leaves
//! it unreadable: sealed, as an encrypted ZIP is. The rebuilt copy is a new
//! archive with every entry in its place, its name, times and attributes
//! kept, each entry with data holding its masked bytes in a block of its own
//! (LZMA2, the 7z default).

use std::io::{Cursor, Read};

use sevenz_rust2::{Archive, ArchiveEntry, ArchiveWriter, BlockDecoder, Password};
use zeroize::Zeroizing;

use crate::batch::secret_scan::container::Budget;
use crate::batch::secret_scan::container::Stop;
use crate::batch::secret_scan::container::Walked;
use crate::batch::secret_scan::container::encode_failed;
use crate::batch::secret_scan::container::over_budget;
use crate::batch::secret_scan::container::unreadable;
use crate::file_secret_marks::MemberStep;

/// A 7z file's first six bytes: its signature header's (FIX 11575).
pub const SIGNATURE: [u8; 6] = [b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c];

/// The archive's header: its start header's CRC verified, and the header it
/// names read whole. No password is given.
fn open(bytes: &[u8]) -> Walked<Archive> {
    Archive::read(&mut Cursor::new(bytes), &Password::empty()).map_err(|_| unreadable())
}

/// Whether `bytes`' frame parses as a 7z archive: its signature, its start
/// header's CRC and the header it names (FIX 11575).
pub fn opens(bytes: &[u8]) -> bool {
    bytes.starts_with(&SIGNATURE) && open(bytes).is_ok()
}

fn step(index: usize) -> Walked<MemberStep> {
    let entry = u32::try_from(index).map_err(|_| over_budget())?;
    Ok(MemberStep::SevenZip { entry })
}

/// Whether `entry` is a member: a file or stream entry with data.
fn is_member(entry: &ArchiveEntry) -> bool {
    entry.has_stream && !entry.is_directory && !entry.is_anti_item
}

/// One member's bytes, read whole against its declared size; the block's
/// decoder checks its CRC at its end.
fn read_member(
    entry: &ArchiveEntry,
    reader: &mut dyn Read,
    budget: &mut Budget,
) -> Walked<Zeroizing<Vec<u8>>> {
    let declared = entry.size;
    if usize::try_from(declared).map_or(true, |declared| declared > budget.limit()) {
        return Err(over_budget());
    }
    let mut data = Zeroizing::new(Vec::new());
    Read::take(&mut *reader, declared.saturating_add(1))
        .read_to_end(&mut *data)
        .map_err(|_| unreadable())?;
    if data.len() as u64 != declared {
        return Err(unreadable());
    }
    budget.spend(data.len())?;
    Ok(data)
}

/// The archive's header and each member's bytes, by its place in the file
/// list (`None` for an entry that is no member). Each block is decoded in
/// its order on one thread, the sizes its entries declare held to the
/// budget before it starts.
fn read_all(
    bytes: &[u8],
    budget: &mut Budget,
) -> Walked<(Archive, Vec<Option<Zeroizing<Vec<u8>>>>)> {
    let archive = open(bytes)?;
    let mut data: Vec<Option<Zeroizing<Vec<u8>>>> = Vec::new();
    data.try_reserve_exact(archive.files.len())
        .map_err(|_| over_budget())?;
    data.resize_with(archive.files.len(), || None);
    let password = Password::empty();
    let mut source = Cursor::new(bytes);
    for block in 0..archive.blocks.len() {
        let first = *archive
            .stream_map
            .block_first_file_index
            .get(block)
            .ok_or_else(unreadable)?;
        let decoder = BlockDecoder::new(1, block, &archive, &password, &mut source);
        let declared = decoder
            .entries()
            .iter()
            .map(|entry| entry.size)
            .fold(0u64, u64::saturating_add);
        if usize::try_from(declared).map_or(true, |declared| declared > budget.limit()) {
            return Err(over_budget());
        }
        decode_block(decoder, first, &mut data, budget)?;
    }
    Ok((archive, data))
}

/// One block's members into `data`, at their places from `first`: the
/// decoder hands each entry of the block in file-list order, those with no
/// data too.
fn decode_block(
    decoder: BlockDecoder<'_, Cursor<&[u8]>>,
    first: usize,
    data: &mut [Option<Zeroizing<Vec<u8>>>],
    budget: &mut Budget,
) -> Walked<()> {
    let mut at = first;
    let mut stop: Option<Stop> = None;
    let mut visit =
        |entry: &ArchiveEntry, reader: &mut dyn Read| -> Result<bool, sevenz_rust2::Error> {
            let index = at;
            at += 1;
            if !is_member(entry) {
                return Ok(true);
            }
            let Some(slot) = data.get_mut(index) else {
                stop = Some(unreadable());
                return Ok(false);
            };
            match read_member(entry, reader, budget) {
                Ok(member) => {
                    *slot = Some(member);
                    Ok(true)
                }
                Err(walk_stop) => {
                    stop = Some(walk_stop);
                    Ok(false)
                }
            }
        };
    let decoded = decoder.for_each_entries(&mut visit);
    if let Some(stop) = stop {
        return Err(stop);
    }
    decoded.map(drop).map_err(|_| unreadable())
}

pub fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let (_, data) = read_all(bytes, budget)?;
    for (index, member) in data.iter().enumerate() {
        if let Some(member) = member {
            each(step(index)?, member, budget)?;
        }
    }
    Ok(())
}

pub fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let (archive, data) = read_all(bytes, budget)?;
    let mut out = ArchiveWriter::new(Cursor::new(Vec::new())).map_err(|_| encode_failed())?;
    for (index, (entry, member)) in archive.files.into_iter().zip(data).enumerate() {
        match member {
            Some(member) => {
                let masked = each(step(index)?, &member, budget)?;
                let body: &[u8] = masked.as_deref().unwrap_or(&member);
                out.push_archive_entry(entry, Some(body))
                    .map_err(|_| encode_failed())?;
            }
            None => {
                out.push_archive_entry(entry, None::<&[u8]>)
                    .map_err(|_| encode_failed())?;
            }
        }
    }
    let copy = out.finish().map_err(|_| encode_failed())?;
    Ok(copy.into_inner())
}
