//! A tar archive's members: each regular file in archive order, read whole
//! against its declared length under the walk's budget (FIX 2471). Links,
//! directories and special entries are not read. The rebuilt copy is a new
//! archive with each masked member's header size updated; other entries are
//! copied as they are.

use std::io::Read;

use zeroize::Zeroizing;

use super::{Budget, Walked, encode_failed, over_budget, unreadable};
use crate::secret_custody::MemberStep;

/// Whether `bytes`' frame parses as a tar archive: its first header's
/// checksum verifies (FIX 2471).
pub(super) fn opens(bytes: &[u8]) -> bool {
    let Some(head) = bytes.get(..512) else {
        return false;
    };
    if !head
        .get(257..)
        .is_some_and(|magic| magic.starts_with(b"ustar"))
    {
        return false;
    }
    let sum = head[..148]
        .iter()
        .chain(head[156..].iter())
        .fold(0u32, |sum, byte| sum + u32::from(*byte))
        + 8 * 32;
    let field = &head[148..156];
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let Ok(text) = std::str::from_utf8(&field[..end]) else {
        return false;
    };
    let Ok(cksum) = u64::from_str_radix(text.trim(), 8) else {
        return false;
    };
    cksum == u64::from(sum)
}

fn step(index: usize) -> Walked<MemberStep> {
    let entry = u32::try_from(index).map_err(|_| over_budget())?;
    Ok(MemberStep::Tar { entry })
}

/// Whether `kind` is a regular file's: those are the members (FIX 2471).
fn is_file(kind: tar::EntryType) -> bool {
    kind.is_file() || kind.is_contiguous() || kind.is_gnu_sparse()
}

fn read(entry: &mut tar::Entry<&[u8]>, budget: &mut Budget) -> Walked<Zeroizing<Vec<u8>>> {
    let declared = entry.size();
    if usize::try_from(declared).map_or(true, |declared| declared > budget.limit()) {
        return Err(over_budget());
    }
    let mut data = Zeroizing::new(Vec::new());
    entry
        .by_ref()
        .take(declared.saturating_add(1))
        .read_to_end(&mut *data)
        .map_err(|_| unreadable())?;
    if data.len() as u64 != declared {
        return Err(unreadable());
    }
    budget.spend(data.len())?;
    Ok(data)
}

pub(super) fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let mut archive = tar::Archive::new(bytes);
    let entries = archive.entries().map_err(|_| unreadable())?;
    for (index, entry) in entries.enumerate() {
        let mut entry = entry.map_err(|_| unreadable())?;
        if !is_file(entry.header().entry_type()) {
            continue;
        }
        let data = read(&mut entry, budget)?;
        each(step(index)?, &data, budget)?;
    }
    Ok(())
}

pub(super) fn rebuilt(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<Vec<u8>> {
    let mut archive = tar::Archive::new(bytes);
    let mut out = tar::Builder::new(Vec::new());
    let entries = archive.entries().map_err(|_| unreadable())?;
    for (index, entry) in entries.enumerate() {
        let mut entry = entry.map_err(|_| unreadable())?;
        let kind = entry.header().entry_type();
        if is_file(kind) {
            rebuild_file(&mut entry, kind, step(index)?, budget, &mut out, each)?;
        } else if kind.is_hard_link() || kind.is_symlink() {
            rebuild_link(&mut entry, &mut out)?;
        } else if kind.is_dir()
            || kind.is_character_special()
            || kind.is_block_special()
            || kind.is_fifo()
        {
            rebuild_void(&mut entry, &mut out)?;
        } else {
            rebuild_other(&mut entry, budget, &mut out)?;
        }
    }
    out.into_inner().map_err(|_| encode_failed())
}

/// A regular file with its masked bytes and its header size updated (FIX 2471).
fn rebuild_file(
    entry: &mut tar::Entry<&[u8]>,
    kind: tar::EntryType,
    at: MemberStep,
    budget: &mut Budget,
    out: &mut tar::Builder<Vec<u8>>,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<Option<Vec<u8>>>,
) -> Walked<()> {
    let data = read(entry, budget)?;
    let masked = each(at, &data, budget)?.unwrap_or_else(|| data.to_vec());
    let mut header = entry.header().clone();
    if kind.is_gnu_sparse() {
        header.set_entry_type(tar::EntryType::Regular);
    }
    header.set_size(masked.len() as u64);
    let raw = entry.path_bytes();
    let path = String::from_utf8_lossy(&raw).into_owned();
    out.append_data(&mut header, path.as_str(), &masked[..])
        .map_err(|_| encode_failed())
}

/// A link with its target, copied as it is (FIX 2471).
fn rebuild_link(
    entry: &mut tar::Entry<&[u8]>,
    out: &mut tar::Builder<Vec<u8>>,
) -> Walked<()> {
    let mut header = entry.header().clone();
    header.set_size(0);
    let raw = entry.path_bytes();
    let path = String::from_utf8_lossy(&raw).into_owned();
    let Some(raw) = entry.link_name_bytes() else {
        return out
            .append_data(&mut header, path.as_str(), std::io::empty())
            .map_err(|_| encode_failed());
    };
    let target = String::from_utf8_lossy(&raw).into_owned();
    out.append_link(&mut header, path.as_str(), target.as_str())
        .map_err(|_| encode_failed())
}

/// A directory or special entry, copied as it is (FIX 2471).
fn rebuild_void(
    entry: &mut tar::Entry<&[u8]>,
    out: &mut tar::Builder<Vec<u8>>,
) -> Walked<()> {
    let mut header = entry.header().clone();
    header.set_size(0);
    let raw = entry.path_bytes();
    let path = String::from_utf8_lossy(&raw).into_owned();
    out.append_data(&mut header, path.as_str(), std::io::empty())
        .map_err(|_| encode_failed())
}

/// Any other entry with its bytes, copied as it is (FIX 2471).
fn rebuild_other(
    entry: &mut tar::Entry<&[u8]>,
    budget: &mut Budget,
    out: &mut tar::Builder<Vec<u8>>,
) -> Walked<()> {
    let data = read(entry, budget)?;
    let mut header = entry.header().clone();
    header.set_size(data.len() as u64);
    let raw = entry.path_bytes();
    let path = String::from_utf8_lossy(&raw).into_owned();
    out.append_data(&mut header, path.as_str(), &data[..])
        .map_err(|_| encode_failed())
}
