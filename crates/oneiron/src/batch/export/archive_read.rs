//! Reads the whole-vault archive (OF-222) back into its typed document. Each
//! member is checked against the manifest (length and BLAKE3) before a row is
//! read, each attached file must hash to its name, and the archive holds no
//! member the manifest does not list. No ceiling caps the whole (rule 5). The
//! document then passes the same validation and admission doors as before;
//! nothing here grants authority.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;

use serde_json::Value;

use super::{
    ArchiveRecordKind, ArchiveSecretCustody, PortableSlotBindings, VAULT_ARCHIVE_FILES_DIR,
    VAULT_ARCHIVE_MANIFEST_PATH, VAULT_ARCHIVE_RECORDS_DIR, WholeVaultDocument,
    WholeVaultDocumentManifest, blake3_hex,
};
use crate::error::{Error, Result};
use crate::serialize::ExportBody;

/// An archive's document, and the custody records the owner's own archive
/// carries beside it (never part of the document, and never nulled).
pub(crate) struct VaultArchive {
    pub(crate) document: WholeVaultDocument,
    pub(crate) secrets: Vec<ArchiveSecretCustody>,
    /// Every attached file by BLAKE3, each checked against its name and
    /// length: result bodies stage from these bytes, and an ASSET's file body
    /// (OF-222) is read from them.
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}

pub(crate) fn read_vault_archive(bytes: &[u8]) -> Result<VaultArchive> {
    let mut members = unpack(bytes)?;
    let manifest_bytes = members
        .remove(VAULT_ARCHIVE_MANIFEST_PATH)
        .ok_or_else(|| invalid("whole-vault archive has no manifest"))?;
    let manifest: WholeVaultDocumentManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| invalid("invalid whole-vault archive manifest"))?;
    manifest.validate()?;

    let mut files = BTreeMap::new();
    for file in &manifest.files {
        let bytes = members
            .remove(&super::archive_file_path(&file.blake3))
            .ok_or_else(|| invalid("archive file listed but absent"))?;
        if bytes.len() as u64 != file.bytes || blake3_hex(&bytes) != file.blake3 {
            return Err(invalid("archive file does not match its digest"));
        }
        if files.insert(file.blake3.clone(), bytes).is_some() {
            return Err(invalid("archive file listed twice"));
        }
    }

    let mut sections: BTreeMap<ArchiveRecordKind, Vec<Value>> = BTreeMap::new();
    for records in &manifest.records {
        let expected_path = match records.kind.fixed_path() {
            Some(path) => records.path == path,
            None => {
                records.path.starts_with("records/entity/")
                    && ArchiveRecordKind::Claim.fixed_path() != Some(records.path.as_str())
                    && ArchiveRecordKind::Skill.fixed_path() != Some(records.path.as_str())
            }
        };
        if !expected_path {
            return Err(invalid("archive record file has the wrong path"));
        }
        let bytes = members
            .remove(&records.path)
            .ok_or_else(|| invalid("archive record file listed but absent"))?;
        if bytes.len() as u64 != records.bytes || blake3_hex(&bytes) != records.blake3 {
            return Err(invalid("archive record file does not match its digest"));
        }
        let rows = sections.entry(records.kind).or_default();
        let mut count = 0;
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let row: Value =
                serde_json::from_slice(line).map_err(|_| invalid("invalid archive record row"))?;
            if records.kind == ArchiveRecordKind::Entity {
                let entity_type = row
                    .get("entity_type")
                    .and_then(Value::as_u64)
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(|| invalid("archive entity row without a type"))?;
                if ArchiveRecordKind::entity_path(entity_type) != records.path {
                    return Err(invalid("archive entity row is in another type's file"));
                }
            }
            rows.push(row);
            count += 1;
        }
        if count != records.rows {
            return Err(invalid("archive record file row count disagrees"));
        }
    }
    if let Some(stray) = members.keys().next() {
        return Err(Error::InvalidConfig(format!(
            "whole-vault archive member {stray:?} is not in its manifest"
        )));
    }

    let secrets = sections
        .remove(&ArchiveRecordKind::SecretCustody)
        .unwrap_or_default()
        .into_iter()
        .map(|row| {
            serde_json::from_value(row).map_err(|_| invalid("invalid archive custody record"))
        })
        .collect::<Result<Vec<ArchiveSecretCustody>>>()?;
    // OF-370: the kind slots come back from their rows, each kind once; an
    // archive without slot rows carries no embedding setup.
    let slot_bindings = match sections.remove(&ArchiveRecordKind::SlotBinding) {
        Some(rows) => serde_json::to_value(PortableSlotBindings::from_archive_rows(rows)?)
            .map_err(|_| invalid("invalid archive slot bindings"))?,
        None => Value::Null,
    };
    let mut entities = sections
        .remove(&ArchiveRecordKind::Entity)
        .unwrap_or_default();
    let mut take = |kind| Value::Array(sections.remove(&kind).unwrap_or_default());
    // Store order: entity ids ascend, as the snapshot enumerated them.
    entities.sort_by(|a, b| {
        let id = |row: &Value| row.get("id").and_then(Value::as_str).map(str::to_owned);
        id(a).cmp(&id(b))
    });
    let mut document = serde_json::json!({
        "manifest": serde_json::to_value(&manifest)
            .map_err(|_| invalid("invalid whole-vault archive manifest"))?,
        "evidence_ledger": {
            "entities": entities,
            "edges": take(ArchiveRecordKind::Edge),
        },
        "claims": take(ArchiveRecordKind::Claim),
        "packs": take(ArchiveRecordKind::Pack),
        "skills": take(ArchiveRecordKind::Skill),
        "agent_packs": take(ArchiveRecordKind::AgentPack),
        "derivation_envelopes": take(ArchiveRecordKind::DerivationEnvelope),
        "run_results": {
            "runs": take(ArchiveRecordKind::Run),
            "bodies": take(ArchiveRecordKind::ResultBody),
        },
        "embedding_spaces": take(ArchiveRecordKind::EmbeddingSpace),
        "slot_bindings": slot_bindings,
        "epoch_floors": take(ArchiveRecordKind::EpochFloor),
    });
    let mut cited = BTreeSet::new();
    cite_result_bodies(&document, &files, &mut cited)?;
    attach_trees(&mut document, &files, &mut cited)?;
    let document: WholeVaultDocument = serde_json::from_value(document)
        .map_err(|_| invalid("invalid whole-vault archive rows"))?;
    // OF-222: an ASSET's file body names one attached file, at its length.
    for row in document.entities() {
        if let ExportBody::File(file) = &row.body {
            file.resolve(&files)
                .map_err(|_| invalid("archive entity file is absent or another length"))?;
            cited.insert(file.blake3().to_owned());
        }
    }
    if cited.len() != files.len() {
        return Err(invalid("archive file no record names"));
    }
    Ok(VaultArchive {
        document,
        secrets,
        files,
    })
}

/// Every member, by name, read whole. No ceiling caps the archive (rule 5):
/// each member is held to its declared length here, and to its manifest
/// length and BLAKE3 after.
fn unpack(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|_| invalid("invalid whole-vault archive"))?;
    let mut members = BTreeMap::new();
    for index in 0..archive.len() {
        let member = archive
            .by_index(index)
            .map_err(|_| invalid("invalid whole-vault archive member"))?;
        let name = member.name().to_owned();
        if !(name == VAULT_ARCHIVE_MANIFEST_PATH
            || (name.starts_with(VAULT_ARCHIVE_RECORDS_DIR) && name.ends_with(".jsonl"))
            || name
                .strip_prefix(VAULT_ARCHIVE_FILES_DIR)
                .is_some_and(|hex| {
                    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                }))
            || name.contains("..")
            || name.contains('\\')
        {
            return Err(Error::InvalidConfig(format!(
                "whole-vault archive member {name:?} is not an archive path"
            )));
        }
        let declared = member.size();
        let mut body = Vec::new();
        member
            .take(declared.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|_| invalid("unreadable whole-vault archive member"))?;
        if body.len() as u64 != declared {
            return Err(invalid("whole-vault archive member length disagrees"));
        }
        if members.insert(name, body).is_some() {
            return Err(invalid("whole-vault archive member appears twice"));
        }
    }
    Ok(members)
}

/// Each result body the export did not withhold, text or binary, names an
/// attached file by its BLAKE3; the import stages those bytes before any row
/// names them.
fn cite_result_bodies(
    document: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    cited: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(bodies) = document
        .pointer("/run_results/bodies")
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    for body in bodies {
        let fields = body
            .as_object()
            .ok_or_else(|| invalid("invalid archive result body"))?;
        if !fields.get("content").is_none_or(Value::is_null) {
            return Err(invalid("archive result body carries inline content"));
        }
        if fields
            .get("withheld")
            .is_some_and(|reason| !reason.is_null())
        {
            continue;
        }
        let blake3 = fields
            .get("blake3")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("archive result body without a digest"))?
            .to_owned();
        if !files.contains_key(&blake3) {
            return Err(invalid("archive result body file is absent"));
        }
        cited.insert(blake3);
    }
    Ok(())
}

/// A source-tree file's `file` comes back as its text.
fn attach_trees(
    document: &mut Value,
    files: &BTreeMap<String, Vec<u8>>,
    cited: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(sections) = document.as_object_mut() else {
        return Ok(());
    };
    for (name, section) in sections.iter_mut() {
        let Some(rows) = section.as_array_mut() else {
            continue;
        };
        for row in rows {
            let tree = match name.as_str() {
                "skills" | "agent_packs" => row.get_mut("source_tree"),
                "packs" if row.get("kind").and_then(Value::as_str) == Some("source") => {
                    row.pointer_mut("/value/source_tree")
                }
                _ => None,
            };
            let Some(tree_files) = tree
                .and_then(|tree| tree.get_mut("files"))
                .and_then(Value::as_array_mut)
            else {
                continue;
            };
            for file in tree_files {
                let Some(fields) = file.as_object_mut() else {
                    continue;
                };
                let Some(reference) = fields.remove("file") else {
                    continue;
                };
                let blake3 = reference
                    .as_str()
                    .ok_or_else(|| invalid("invalid archive file reference"))?;
                if !fields.get("content").is_none_or(Value::is_null) {
                    return Err(invalid("archive tree file carries inline content"));
                }
                let text = files
                    .get(blake3)
                    .ok_or_else(|| invalid("archive tree file is absent"))?;
                let text = std::str::from_utf8(text)
                    .map_err(|_| invalid("archive tree file is not UTF-8 text"))?;
                fields.insert("content".to_owned(), Value::from(text));
                cited.insert(blake3.to_owned());
            }
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
