//! Writes the whole-vault archive (OF-222) from the credential-nulled document
//! value: every JSONL row and every attached file is cut from that value, so
//! nothing reaches the archive around the serializer's nulling pass.
use std::collections::BTreeMap;
use std::io::Write as _;

use serde_json::Value;

use crate::batch::export::{
    ArchiveFile, ArchiveRecordFile, ArchiveRecordKind, ArchiveSecretCustody,
    VAULT_ARCHIVE_MANIFEST_PATH, WholeVaultDocumentManifest, archive_file_path, blake3_hex,
};
use crate::error::{Error, Result};

/// The archive bytes and the manifest they carry. `secrets` are the owner's
/// custody records; they are written as they are, never through nulling.
pub(super) fn write_vault_archive(
    mut document: Value,
    secrets: &[ArchiveSecretCustody],
    mut binary_bodies: BTreeMap<String, Vec<u8>>,
) -> Result<(Vec<u8>, WholeVaultDocumentManifest)> {
    let mut files = BTreeMap::new();
    detach_result_bodies(&mut document, &mut files, &mut binary_bodies);
    for tree in source_trees(&mut document) {
        detach_tree(tree, &mut files);
    }
    let mut groups: BTreeMap<String, (ArchiveRecordKind, Vec<u8>, u64)> = BTreeMap::new();
    let mut push = |path: String, kind: ArchiveRecordKind, row: &Value| -> Result<()> {
        let entry = groups.entry(path).or_insert((kind, Vec::new(), 0));
        serde_json::to_writer(&mut entry.1, row).map_err(|_| encode_failed())?;
        entry.1.push(b'\n');
        entry.2 += 1;
        Ok(())
    };
    for row in take_array(&mut document, &["evidence_ledger", "entities"]) {
        let entity_type = row
            .get("entity_type")
            .and_then(Value::as_u64)
            .and_then(|byte| u8::try_from(byte).ok())
            .ok_or(Error::InvariantViolation(
                "archive entity row without a type",
            ))?;
        push(
            ArchiveRecordKind::entity_path(entity_type),
            ArchiveRecordKind::Entity,
            &row,
        )?;
    }
    for (kind, path) in [
        (ArchiveRecordKind::Edge, &["evidence_ledger", "edges"][..]),
        (ArchiveRecordKind::Claim, &["claims"][..]),
        (ArchiveRecordKind::Skill, &["skills"][..]),
        (ArchiveRecordKind::Pack, &["packs"][..]),
        (ArchiveRecordKind::AgentPack, &["agent_packs"][..]),
        (
            ArchiveRecordKind::DerivationEnvelope,
            &["derivation_envelopes"][..],
        ),
        (ArchiveRecordKind::Run, &["run_results", "runs"][..]),
        (
            ArchiveRecordKind::ResultBody,
            &["run_results", "bodies"][..],
        ),
    ] {
        let fixed = kind
            .fixed_path()
            .map(str::to_owned)
            .ok_or_else(encode_failed)?;
        for row in take_array(&mut document, path) {
            push(fixed.clone(), kind, &row)?;
        }
    }
    if let Some(path) = ArchiveRecordKind::SecretCustody.fixed_path() {
        for secret in secrets {
            let row = serde_json::to_value(secret).map_err(|_| encode_failed())?;
            push(path.to_owned(), ArchiveRecordKind::SecretCustody, &row)?;
        }
    }
    let manifest = document
        .get_mut("manifest")
        .map(Value::take)
        .ok_or_else(encode_failed)?;
    let mut manifest: WholeVaultDocumentManifest =
        serde_json::from_value(manifest).map_err(|_| encode_failed())?;
    manifest.records = groups
        .iter()
        .map(|(path, (kind, bytes, rows))| ArchiveRecordFile {
            path: path.clone(),
            kind: *kind,
            rows: *rows,
            bytes: bytes.len() as u64,
            blake3: blake3_hex(bytes),
        })
        .collect();
    manifest.files = files
        .iter()
        .map(|(blake3, bytes): (&String, &Vec<u8>)| ArchiveFile {
            blake3: blake3.clone(),
            bytes: bytes.len() as u64,
        })
        .collect();
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| encode_failed())?;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let mut member = |name: &str, bytes: &[u8]| -> Result<()> {
        zip.start_file(name, options).map_err(|_| encode_failed())?;
        zip.write_all(bytes).map_err(|_| encode_failed())
    };
    member(VAULT_ARCHIVE_MANIFEST_PATH, &manifest_bytes)?;
    for (path, (_, bytes, _)) in &groups {
        member(path, bytes)?;
    }
    for (blake3, bytes) in &files {
        member(&archive_file_path(blake3), bytes)?;
    }
    let bytes = zip.finish().map_err(|_| encode_failed())?.into_inner();
    Ok((bytes, manifest))
}

/// Each result body becomes the file named by its digest: its text, or the
/// bytes of a binary body that passed the release scan. A text body the
/// nulling pass changed no longer matches that digest, so it is withheld as
/// a credential rather than shipped under a name it does not hash to.
fn detach_result_bodies(
    document: &mut Value,
    files: &mut BTreeMap<String, Vec<u8>>,
    binary_bodies: &mut BTreeMap<String, Vec<u8>>,
) {
    let Some(bodies) = document
        .pointer_mut("/run_results/bodies")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for body in bodies {
        let Some(fields) = body.as_object_mut() else {
            continue;
        };
        let content = fields.get_mut("content").map(Value::take);
        if fields
            .get("withheld")
            .is_some_and(|reason| !reason.is_null())
        {
            continue;
        }
        let digest = fields
            .get("blake3")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match (content, digest) {
            (Some(Value::String(text)), Some(digest)) if blake3_hex(text.as_bytes()) == digest => {
                files.insert(digest, text.into_bytes());
            }
            (Some(Value::Null) | None, Some(digest))
                if binary_bodies
                    .get(&digest)
                    .is_some_and(|bytes| blake3_hex(bytes) == digest) =>
            {
                if let Some(bytes) = binary_bodies.remove(&digest) {
                    files.insert(digest, bytes);
                }
            }
            _ => {
                fields.insert("withheld".to_owned(), Value::from("credential"));
            }
        }
    }
}

/// The source trees the document carries: skill packages, pack sources and
/// agent bundles.
fn source_trees(document: &mut Value) -> Vec<&mut Value> {
    let mut trees = Vec::new();
    let Some(sections) = document.as_object_mut() else {
        return trees;
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
            if let Some(tree) = tree.filter(|tree| !tree.is_null()) {
                trees.push(tree);
            }
        }
    }
    trees
}

/// A tree file's text moves to `files/<blake3>`; its row keeps the path, its
/// own sha256 and the `file` it is stored under.
fn detach_tree(tree: &mut Value, files: &mut BTreeMap<String, Vec<u8>>) {
    let Some(rows) = tree.get_mut("files").and_then(Value::as_array_mut) else {
        return;
    };
    for row in rows {
        let Some(fields) = row.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(text)) = fields.get_mut("content").map(Value::take) {
            let blake3 = blake3_hex(text.as_bytes());
            fields.insert("file".to_owned(), Value::from(blake3.clone()));
            files.insert(blake3, text.into_bytes());
        }
    }
}

fn take_array(document: &mut Value, path: &[&str]) -> Vec<Value> {
    let mut cursor = Some(document);
    for key in path {
        cursor = cursor.and_then(|value| value.get_mut(*key));
    }
    match cursor.map(Value::take) {
        Some(Value::Array(rows)) => rows,
        _ => Vec::new(),
    }
}

fn encode_failed() -> Error {
    Error::InvariantViolation("whole-vault archive encoding failed")
}
