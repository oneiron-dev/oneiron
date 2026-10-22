//! Projects a stored records archive onto a subset of the records it was
//! cut from (FIX-LIST 8224, `ProjectStoredSnapshot`): the frozen archive
//! itself, never a fresh export of the live vault, which has moved on since.
//!
//! A JSONL row that names any of the archive's records stays only when every
//! one it names is kept; a row that names none stays only when a kept row
//! names one of its files (a result body a kept run names). An attached file
//! stays only when a kept row names it, and streams across unread. Every
//! member the manifest lists is rebuilt with its new rows, length and BLAKE3,
//! and the manifest names only what stayed, so the projection reads back
//! through the same member checks as any archive. Row order is kept.
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Cursor, Read, Write};

use serde_json::Value;

use super::{VAULT_ARCHIVE_MANIFEST_PATH, WholeVaultDocumentManifest, archive_file_path};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// What one row of a member came to.
enum RowFate {
    Keep,
    Drop,
    /// Names no archived record: kept when a kept row names one of these
    /// files.
    ByFiles(BTreeSet<String>),
}

/// The archive `archive`, cut from the records `archived`, holding only what
/// `kept` (a subset of them) leaves it, as this module says.
pub(crate) fn project_stored_archive(
    archive: &[u8],
    archived: &BTreeSet<EntityId>,
    kept: &BTreeSet<EntityId>,
) -> Result<Vec<u8>> {
    let mut source = zip::ZipArchive::new(Cursor::new(archive)).map_err(|_| invalid())?;
    let mut manifest: WholeVaultDocumentManifest = {
        let mut member = source
            .by_name(VAULT_ARCHIVE_MANIFEST_PATH)
            .map_err(|_| invalid())?;
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes).map_err(|_| invalid())?;
        serde_json::from_slice(&bytes).map_err(|_| invalid())?
    };
    let listed: BTreeSet<String> = manifest.files.iter().map(|file| file.blake3.clone()).collect();
    let mut referenced = BTreeSet::new();
    let mut members = Vec::with_capacity(manifest.records.len());
    for record in &manifest.records {
        let member = source.by_name(&record.path).map_err(|_| invalid())?;
        let mut rows = Vec::new();
        for line in BufReader::new(member).split(b'\n') {
            let line = line.map_err(|_| invalid())?;
            if line.is_empty() {
                continue;
            }
            let row: Value = serde_json::from_slice(&line).map_err(|_| invalid())?;
            let mut names = BTreeSet::new();
            let mut files = BTreeSet::new();
            refs(&row, archived, &listed, &mut names, &mut files);
            let fate = if names.is_empty() {
                RowFate::ByFiles(files)
            } else if names.is_subset(kept) {
                referenced.extend(files);
                RowFate::Keep
            } else {
                RowFate::Drop
            };
            rows.push((line, fate));
        }
        members.push(rows);
    }
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let mut bodies = Vec::with_capacity(members.len());
    for (record, rows) in manifest.records.iter_mut().zip(members) {
        let mut body = Vec::new();
        let mut count = 0_u64;
        for (line, fate) in rows {
            let stays = match fate {
                RowFate::Keep => true,
                RowFate::Drop => false,
                RowFate::ByFiles(files) => files.iter().any(|file| referenced.contains(file)),
            };
            if stays {
                body.extend_from_slice(&line);
                body.push(b'\n');
                count += 1;
            }
        }
        record.rows = count;
        record.bytes = body.len() as u64;
        record.blake3 = blake3::hash(&body).to_hex().to_string();
        bodies.push(body);
    }
    manifest.files.retain(|file| referenced.contains(&file.blake3));
    manifest.import_omissions.retain(|omission| {
        EntityId::from_hex(&omission.entity_id).is_ok_and(|id| !archived.contains(&id) || kept.contains(&id))
    });
    let head = serde_json::to_vec_pretty(&manifest).map_err(|_| invalid())?;
    out.start_file(VAULT_ARCHIVE_MANIFEST_PATH, options)
        .map_err(|_| invalid())?;
    out.write_all(&head)?;
    for (record, body) in manifest.records.iter().zip(&bodies) {
        out.start_file(record.path.as_str(), options)
            .map_err(|_| invalid())?;
        out.write_all(body)?;
    }
    for file in &manifest.files {
        let path = archive_file_path(&file.blake3);
        let mut member = source.by_name(&path).map_err(|_| invalid())?;
        out.start_file(path.as_str(), options)
            .map_err(|_| invalid())?;
        std::io::copy(&mut member, &mut out)?;
    }
    Ok(out.finish().map_err(|_| invalid())?.into_inner())
}

/// The archived records and the listed files `value` names, anywhere in it:
/// as a string, or as an object key.
fn refs(
    value: &Value,
    archived: &BTreeSet<EntityId>,
    listed: &BTreeSet<String>,
    names: &mut BTreeSet<EntityId>,
    files: &mut BTreeSet<String>,
) {
    match value {
        Value::String(text) => note(text, archived, listed, names, files),
        Value::Array(items) => {
            for item in items {
                refs(item, archived, listed, names, files);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                note(key, archived, listed, names, files);
                refs(item, archived, listed, names, files);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// One string of a row: a listed file's name, an archived record's id, or
/// neither.
fn note(
    text: &str,
    archived: &BTreeSet<EntityId>,
    listed: &BTreeSet<String>,
    names: &mut BTreeSet<EntityId>,
    files: &mut BTreeSet<String>,
) {
    if listed.contains(text) {
        files.insert(text.to_owned());
    } else if let Ok(id) = EntityId::from_hex(text)
        && archived.contains(&id)
    {
        names.insert(id);
    }
}

fn invalid() -> Error {
    Error::InvariantViolation("stored removal archive does not project")
}
