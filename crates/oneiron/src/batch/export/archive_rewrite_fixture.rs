//! Test fixture: copies a whole-vault archive member by member with its
//! manifest or one JSONL record file rewritten. A rewritten record file is
//! resealed in the manifest, so the archive still passes the integrity door
//! and the reader judges the rewritten rows themselves.
use std::io::{Read as _, Write as _};

use super::{VAULT_ARCHIVE_MANIFEST_PATH, WholeVaultDocumentManifest};
use crate::error::{Error, Result};

fn invalid(what: &str) -> Error {
    Error::InvalidConfig(format!("rewritten fixture archive: {what}"))
}

/// The archive's file members in archive order (directories skipped).
fn read_members(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|_| invalid("unreadable"))?;
    let mut members = Vec::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|_| invalid("unreadable"))?;
        let name = member.name().to_owned();
        if name.ends_with('/') {
            continue;
        }
        let mut content = Vec::new();
        member
            .read_to_end(&mut content)
            .map_err(|_| invalid("unreadable"))?;
        members.push((name, content));
    }
    Ok(members)
}

fn write_members(members: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::default();
    for (name, content) in members {
        out.start_file(name.as_str(), options)
            .map_err(|_| invalid("unwritable"))?;
        out.write_all(content).map_err(|_| invalid("unwritable"))?;
    }
    Ok(out
        .finish()
        .map_err(|_| invalid("unwritable"))?
        .into_inner())
}

fn member_index(members: &[(String, Vec<u8>)], path: &str) -> Result<usize> {
    members
        .iter()
        .position(|(name, _)| name == path)
        .ok_or_else(|| invalid("member absent"))
}

/// The archive with its manifest JSON rewritten by `rewrite`. Nothing is
/// resealed: the reader judges the rewritten manifest.
pub(crate) fn rewrite_archive_manifest(
    bytes: &[u8],
    rewrite: impl FnOnce(&mut serde_json::Value),
) -> Result<Vec<u8>> {
    let mut members = read_members(bytes)?;
    let index = member_index(&members, VAULT_ARCHIVE_MANIFEST_PATH)?;
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&members[index].1).map_err(|_| invalid("manifest"))?;
    rewrite(&mut manifest);
    members[index].1 = serde_json::to_vec(&manifest).map_err(|_| invalid("manifest"))?;
    write_members(&members)
}

/// The archive with the JSONL rows at `path` rewritten by `rewrite`, and that
/// file's manifest entry (rows, bytes, BLAKE3) resealed.
pub(crate) fn rewrite_archive_rows<T>(
    bytes: &[u8],
    path: &str,
    rewrite: impl FnOnce(Vec<T>) -> Vec<T>,
) -> Result<Vec<u8>>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut members = read_members(bytes)?;
    let index = member_index(&members, path)?;
    let rows = members[index]
        .1
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<T>(line).map_err(|_| invalid("rows")))
        .collect::<Result<Vec<_>>>()?;
    let rewritten = rewrite(rows);
    let mut content = Vec::new();
    for row in &rewritten {
        content.extend_from_slice(&serde_json::to_vec(row).map_err(|_| invalid("rows"))?);
        content.push(b'\n');
    }
    let manifest_index = member_index(&members, VAULT_ARCHIVE_MANIFEST_PATH)?;
    let mut manifest: WholeVaultDocumentManifest =
        serde_json::from_slice(&members[manifest_index].1).map_err(|_| invalid("manifest"))?;
    let record = manifest
        .records
        .iter_mut()
        .find(|record| record.path == path)
        .ok_or_else(|| invalid("record file not listed"))?;
    record.rows = rewritten.len() as u64;
    record.bytes = content.len() as u64;
    record.blake3 = crate::entity_id::bytes_to_hex_lower(blake3::hash(&content).as_bytes());
    members[index].1 = content;
    members[manifest_index].1 = serde_json::to_vec(&manifest).map_err(|_| invalid("manifest"))?;
    write_members(&members)
}
