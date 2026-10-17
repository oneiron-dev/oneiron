//! Reads the whole-vault archive (OF-222) member by member from a seekable
//! source (FIX 2766, rule 5): only the ZIP's central directory and the
//! manifest are read whole. Every member is checked against the manifest
//! (length and BLAKE3) in one streaming pass before a row is read; the record
//! rows are then parsed into the typed document one line at a time, and an
//! attached file stays in the archive until a row needs it, checked against
//! its name again each time it is read. The archive holds no member the
//! manifest does not list. No ceiling caps the whole. The document then passes
//! the same validation and admission doors as before; nothing here grants
//! authority.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Seek};

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    ArchiveRecordKind, ArchiveSecretCustody, ExportDerivationEnvelope, ExportEdge, ExportEntity,
    ExportEpochFloor, ExportLedger, ExportResultBody, ExportRun, ExportRunResults,
    PortableEmbeddingSpace, PortableSlotBindings, VAULT_ARCHIVE_FILES_DIR,
    VAULT_ARCHIVE_MANIFEST_PATH, VAULT_ARCHIVE_RECORDS_DIR, WholeVaultDocument,
    WholeVaultDocumentManifest, archive_file_path,
};
use crate::error::{Error, Result};
use crate::serialize::ExportBody;

/// An archive's document, the custody records the owner's own archive carries
/// beside it (never part of the document, and never nulled), and its attached
/// files, still in the archive.
pub(crate) struct VaultArchive<R: Read + Seek> {
    pub(crate) document: WholeVaultDocument,
    pub(crate) secrets: Vec<ArchiveSecretCustody>,
    pub(crate) files: ArchiveFileSource<R>,
}

/// Where an archive's attached files are read from: result bodies stage from
/// them, and an ASSET's file body (OF-222) and a side row's long value (FIX
/// 2768) are read from them, one at a time.
pub(crate) trait ArchiveFiles {
    /// The length the manifest lists for the file named `blake3`, if it does.
    fn file_len(&self, blake3: &str) -> Option<u64>;

    /// The file named `blake3`, checked against its name and listed length.
    fn read_file(&self, blake3: &str) -> Result<Vec<u8>>;
}

/// The attached files of one archive, read from it on demand.
pub(crate) struct ArchiveFileSource<R: Read + Seek> {
    archive: RefCell<zip::ZipArchive<R>>,
    listed: BTreeMap<String, u64>,
}

impl<R: Read + Seek> ArchiveFiles for ArchiveFileSource<R> {
    fn file_len(&self, blake3: &str) -> Option<u64> {
        self.listed.get(blake3).copied()
    }

    fn read_file(&self, blake3: &str) -> Result<Vec<u8>> {
        let bytes = self
            .file_len(blake3)
            .ok_or_else(|| invalid("archive file listed but absent"))?;
        let mut archive = self.archive.borrow_mut();
        let member = archive
            .by_name(&archive_file_path(blake3))
            .map_err(|_| invalid("archive file listed but absent"))?;
        let mut body = Vec::new();
        member
            .take(bytes.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|_| invalid("unreadable whole-vault archive member"))?;
        if body.len() as u64 != bytes || super::blake3_hex(&body) != blake3 {
            return Err(invalid("archive file does not match its digest"));
        }
        Ok(body)
    }
}

pub(crate) fn read_vault_archive<R: Read + Seek>(source: R) -> Result<VaultArchive<R>> {
    let mut archive =
        zip::ZipArchive::new(source).map_err(|_| invalid("invalid whole-vault archive"))?;
    let mut members = BTreeSet::new();
    for index in 0..archive.len() {
        let name = archive
            .by_index_raw(index)
            .map_err(|_| invalid("invalid whole-vault archive member"))?
            .name()
            .to_owned();
        if !archive_path(&name) {
            return Err(Error::InvalidConfig(format!(
                "whole-vault archive member {name:?} is not an archive path"
            )));
        }
        if !members.insert(name) {
            return Err(invalid("whole-vault archive member appears twice"));
        }
    }
    let manifest_bytes = {
        let member = archive
            .by_name(VAULT_ARCHIVE_MANIFEST_PATH)
            .map_err(|_| invalid("whole-vault archive has no manifest"))?;
        let declared = member.size();
        let mut bytes = Vec::new();
        member
            .take(declared.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("unreadable whole-vault archive member"))?;
        if bytes.len() as u64 != declared {
            return Err(invalid("whole-vault archive member length disagrees"));
        }
        bytes
    };
    members.remove(VAULT_ARCHIVE_MANIFEST_PATH);
    let manifest: WholeVaultDocumentManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| invalid("invalid whole-vault archive manifest"))?;
    manifest.validate()?;

    // Every listed member is checked whole before any row is read.
    let mut listed = BTreeMap::new();
    for file in &manifest.files {
        let path = archive_file_path(&file.blake3);
        if !members.remove(&path) {
            return Err(invalid("archive file listed but absent"));
        }
        if listed.insert(file.blake3.clone(), file.bytes).is_some() {
            return Err(invalid("archive file listed twice"));
        }
        let (bytes, blake3) = member_digest(&mut archive, &path)?;
        if bytes != file.bytes || blake3 != file.blake3 {
            return Err(invalid("archive file does not match its digest"));
        }
    }
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
        if !members.remove(&records.path) {
            return Err(invalid("archive record file listed but absent"));
        }
        let (bytes, blake3) = member_digest(&mut archive, &records.path)?;
        if bytes != records.bytes || blake3 != records.blake3 {
            return Err(invalid("archive record file does not match its digest"));
        }
    }
    if let Some(stray) = members.first() {
        return Err(Error::InvalidConfig(format!(
            "whole-vault archive member {stray:?} is not in its manifest"
        )));
    }

    let mut rows = Rows::default();
    for records in &manifest.records {
        let member = archive
            .by_name(&records.path)
            .map_err(|_| invalid("archive record file listed but absent"))?;
        let mut lines = BufReader::new(member);
        let mut count = 0;
        let mut line = Vec::new();
        loop {
            line.clear();
            if lines
                .read_until(b'\n', &mut line)
                .map_err(|_| invalid("unreadable whole-vault archive member"))?
                == 0
            {
                break;
            }
            let row = line.strip_suffix(b"\n").unwrap_or(&line);
            if row.is_empty() {
                continue;
            }
            rows.push(records.kind, &records.path, row)?;
            count += 1;
        }
        if count != records.rows {
            return Err(invalid("archive record file row count disagrees"));
        }
    }

    let files = ArchiveFileSource {
        archive: RefCell::new(archive),
        listed,
    };
    let mut cited = BTreeSet::new();
    for body in &rows.bodies {
        if body.content.is_some() {
            return Err(invalid("archive result body carries inline content"));
        }
        if body.withheld.is_some() {
            continue;
        }
        if files.file_len(&body.blake3).is_none() {
            return Err(invalid("archive result body file is absent"));
        }
        cited.insert(body.blake3.clone());
    }
    // A source-tree file's `file` comes back as its text.
    let mut trees = |kind: ArchiveRecordKind, rows: Vec<Value>| -> Result<Vec<Value>> {
        rows.into_iter()
            .map(|mut row| {
                attach_tree(kind, &mut row, &files, &mut cited)?;
                Ok(row)
            })
            .collect()
    };
    let packs = typed(trees(ArchiveRecordKind::Pack, rows.packs)?)?;
    let skills: Vec<super::ExportSkillBundle> =
        typed(trees(ArchiveRecordKind::Skill, rows.skills)?)?;
    let agent_packs = typed(trees(ArchiveRecordKind::AgentPack, rows.agent_packs)?)?;
    // Store order: entity ids ascend, as the snapshot enumerated them.
    rows.entities.sort_by(|a, b| a.id.cmp(&b.id));
    let document = WholeVaultDocument {
        manifest,
        evidence_ledger: ExportLedger {
            entities: rows.entities,
            edges: rows.edges,
        },
        claims: rows.claims,
        packs,
        skills,
        agent_packs,
        derivation_envelopes: rows.derivation_envelopes,
        run_results: ExportRunResults {
            runs: rows.runs,
            bodies: rows.bodies,
        },
        embedding_spaces: rows.embedding_spaces,
        // OF-370: the kind slots come back from their rows, each kind once;
        // an archive without slot rows carries no embedding setup.
        slot_bindings: if rows.slot_bindings.is_empty() {
            None
        } else {
            Some(PortableSlotBindings::from_archive_rows(rows.slot_bindings)?)
        },
        epoch_floors: rows.epoch_floors,
        side_tables: rows.side_tables,
    };
    // OF-222: an ASSET's file body names one attached file, at its length.
    for row in document.entities() {
        if let ExportBody::File(file) = &row.body {
            if files.file_len(file.blake3()) != Some(file.bytes()) {
                return Err(invalid("archive entity file is absent or another length"));
            }
            cited.insert(file.blake3().to_owned());
        }
    }
    // FIX 2768: a side row's long binary value names one attached file too.
    for row in &document.side_tables {
        for file in row.files() {
            if files.file_len(file.blake3()) != Some(file.bytes()) {
                return Err(invalid("archive side row file is absent or another length"));
            }
            cited.insert(file.blake3().to_owned());
        }
    }
    if cited.len() != files.listed.len() {
        return Err(invalid("archive file no record names"));
    }
    Ok(VaultArchive {
        document,
        secrets: rows.secrets,
        files,
    })
}

/// The rows of every record member, each parsed into its typed row as it is
/// read. Rows holding a source tree wait as JSON until their files attach.
#[derive(Default)]
struct Rows {
    entities: Vec<ExportEntity>,
    claims: Vec<ExportEntity>,
    skills: Vec<Value>,
    edges: Vec<ExportEdge>,
    packs: Vec<Value>,
    agent_packs: Vec<Value>,
    derivation_envelopes: Vec<ExportDerivationEnvelope>,
    runs: Vec<ExportRun>,
    bodies: Vec<ExportResultBody>,
    secrets: Vec<ArchiveSecretCustody>,
    embedding_spaces: Vec<PortableEmbeddingSpace>,
    slot_bindings: Vec<Value>,
    epoch_floors: Vec<ExportEpochFloor>,
    side_tables: Vec<super::ArchiveSideRow>,
}

impl Rows {
    fn push(&mut self, kind: ArchiveRecordKind, path: &str, line: &[u8]) -> Result<()> {
        match kind {
            ArchiveRecordKind::Entity => {
                let row: ExportEntity = row(line)?;
                if ArchiveRecordKind::entity_path(row.entity_type) != path {
                    return Err(invalid("archive entity row is in another type's file"));
                }
                self.entities.push(row);
            }
            ArchiveRecordKind::Claim => self.claims.push(row(line)?),
            ArchiveRecordKind::Skill => self.skills.push(row(line)?),
            ArchiveRecordKind::Edge => self.edges.push(row(line)?),
            ArchiveRecordKind::Pack => self.packs.push(row(line)?),
            ArchiveRecordKind::AgentPack => self.agent_packs.push(row(line)?),
            ArchiveRecordKind::DerivationEnvelope => self.derivation_envelopes.push(row(line)?),
            ArchiveRecordKind::Run => self.runs.push(row(line)?),
            ArchiveRecordKind::ResultBody => self.bodies.push(row(line)?),
            ArchiveRecordKind::SecretCustody => {
                self.secrets.push(
                    serde_json::from_slice(line)
                        .map_err(|_| invalid("invalid archive custody record"))?,
                );
            }
            ArchiveRecordKind::EmbeddingSpace => self.embedding_spaces.push(row(line)?),
            ArchiveRecordKind::SlotBinding => self.slot_bindings.push(row(line)?),
            ArchiveRecordKind::EpochFloor => self.epoch_floors.push(row(line)?),
            ArchiveRecordKind::SideTable => self.side_tables.push(row(line)?),
        }
        Ok(())
    }
}

fn row<T: DeserializeOwned>(line: &[u8]) -> Result<T> {
    serde_json::from_slice(line).map_err(|_| invalid("invalid whole-vault archive rows"))
}

fn typed<T: DeserializeOwned>(rows: Vec<Value>) -> Result<Vec<T>> {
    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row).map_err(|_| invalid("invalid whole-vault archive rows"))
        })
        .collect()
}

/// Whether `name` is a member path the archive may hold.
fn archive_path(name: &str) -> bool {
    (name == VAULT_ARCHIVE_MANIFEST_PATH
        || (name.starts_with(VAULT_ARCHIVE_RECORDS_DIR) && name.ends_with(".jsonl"))
        || name
            .strip_prefix(VAULT_ARCHIVE_FILES_DIR)
            .is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            }))
        && !name.contains("..")
        && !name.contains('\\')
}

/// One member's length and BLAKE3, read in a stream: never held whole.
fn member_digest<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    path: &str,
) -> Result<(u64, String)> {
    let mut member = archive
        .by_name(path)
        .map_err(|_| invalid("invalid whole-vault archive member"))?;
    let declared = member.size();
    let mut hasher = blake3::Hasher::new();
    let mut read = 0_u64;
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        let count = member
            .read(&mut chunk)
            .map_err(|_| invalid("unreadable whole-vault archive member"))?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
        read += count as u64;
    }
    if read != declared {
        return Err(invalid("whole-vault archive member length disagrees"));
    }
    Ok((
        read,
        crate::entity_id::bytes_to_hex_lower(hasher.finalize().as_bytes()),
    ))
}

/// A source-tree row's files come back as their text, read from the archive
/// one at a time.
fn attach_tree(
    kind: ArchiveRecordKind,
    row: &mut Value,
    files: &dyn ArchiveFiles,
    cited: &mut BTreeSet<String>,
) -> Result<()> {
    let tree = match kind {
        ArchiveRecordKind::Pack if row.get("kind").and_then(Value::as_str) == Some("source") => {
            row.pointer_mut("/value/source_tree")
        }
        ArchiveRecordKind::Pack => None,
        _ => row.get_mut("source_tree"),
    };
    let Some(tree_files) = tree
        .and_then(|tree| tree.get_mut("files"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
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
        if files.file_len(blake3).is_none() {
            return Err(invalid("archive tree file is absent"));
        }
        let text = String::from_utf8(files.read_file(blake3)?)
            .map_err(|_| invalid("archive tree file is not UTF-8 text"))?;
        fields.insert("content".to_owned(), Value::from(text));
        cited.insert(blake3.to_owned());
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
