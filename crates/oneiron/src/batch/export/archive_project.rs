//! Projects a stored records archive onto a subset of the records it was
//! cut from (FIX-LIST 8224, `ProjectStoredSnapshot`): the frozen archive
//! itself, never a fresh export of the live vault, which has moved on since.
//!
//! A JSONL row belongs to the archived record its identity fields name
//! ([`ROW_IDENTITY_FIELDS`], as the export writer writes them): it stays
//! exactly when that record is kept, as a fresh export of the kept records
//! writes it, whatever else its body mentions. A row whose identity fields
//! name no archived record keeps the names rule: it stays only when every
//! archived record it names anywhere is kept, and one that names none stays
//! only when a kept row refers to one of its files (a result body a kept run
//! names). A file reference is a digest in a field the writer writes file
//! descriptors in ([`FILE_DESCRIPTOR_FIELDS`]), never any string equal to
//! one. An attached file stays only when a kept row refers to it, and
//! streams across unread. Every member the manifest lists is rebuilt with
//! its new rows, length and BLAKE3. Every manifest list naming a record keeps
//! only what a kept or unarchived record declares, and the declarations the
//! readback checks against the rows (a provenanced edge's refusal, an
//! agent's missing birth source) are derived again from the kept rows, so
//! the projection reads back through the same checks as any archive. Row
//! order is kept.
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Cursor, Read, Write};

use serde_json::Value;

use super::archive_index::edge_key;
use super::bundle_validation::provenance_subject_key;
use super::{
    ArchiveRecordKind, BundleOmissionReason, ExportBundleOmission, ExportEdge, ExportEntity,
    ExportImportRefusal, VAULT_ARCHIVE_MANIFEST_PATH, WholeVaultDocumentManifest,
    archive_file_path,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Where the export writer (`serialize::vault_document`) writes an attached
/// file's digest, by member kind: field names from the row's root, `*` for
/// each item of an array, `**` for any depth below. An entity body that is a
/// stored file (`ExportBody::File`, `{blake3, bytes}` under `body.value`); a
/// source tree's file moved to `files/`, under `file`; a run output's and a
/// result body's `blake3`; a side row's value, or a leaf of its tree, stored
/// as a file (`ExportBodyFile` again).
const FILE_DESCRIPTOR_FIELDS: &[(ArchiveRecordKind, &[&str])] = &[
    (ArchiveRecordKind::Entity, &["body", "value", "blake3"]),
    (ArchiveRecordKind::Claim, &["body", "value", "blake3"]),
    (
        ArchiveRecordKind::Skill,
        &["entity", "body", "value", "blake3"],
    ),
    (
        ArchiveRecordKind::Skill,
        &["source_tree", "files", "*", "file"],
    ),
    (
        ArchiveRecordKind::Pack,
        &["value", "source_tree", "files", "*", "file"],
    ),
    (
        ArchiveRecordKind::AgentPack,
        &["source_tree", "files", "*", "file"],
    ),
    (ArchiveRecordKind::Run, &["outputs", "*", "blake3"]),
    (ArchiveRecordKind::ResultBody, &["blake3"]),
    (
        ArchiveRecordKind::SideTable,
        &["value", "value", "**", "blake3"],
    ),
];

/// The fields naming the record a member's row is of, as the export writer
/// writes them: an entity's `id`, a skill bundle's `entity.id`, an edge's two
/// ends, a pack source's and an agent bundle's `entity_id`, a derivation
/// envelope's claim `id`, a run's `run_id`, a custody record's `id` and an
/// epoch floor's `session`. A side row is not listed: its key names the
/// carriers a fresh export carries it with, so it keeps the names rule.
const ROW_IDENTITY_FIELDS: &[(ArchiveRecordKind, &[&str])] = &[
    (ArchiveRecordKind::Entity, &["id"]),
    (ArchiveRecordKind::Claim, &["id"]),
    (ArchiveRecordKind::Skill, &["entity", "id"]),
    (ArchiveRecordKind::Edge, &["source"]),
    (ArchiveRecordKind::Edge, &["target"]),
    (ArchiveRecordKind::Pack, &["value", "entity_id"]),
    (ArchiveRecordKind::AgentPack, &["entity_id"]),
    (ArchiveRecordKind::DerivationEnvelope, &["id"]),
    (ArchiveRecordKind::Run, &["run_id"]),
    (ArchiveRecordKind::SecretCustody, &["id"]),
    (ArchiveRecordKind::EpochFloor, &["session"]),
];

/// What one row of a member came to.
enum RowFate {
    Keep,
    Drop,
    /// Names no archived record: kept when a kept row refers to one of these
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
    let listed: BTreeSet<String> = manifest
        .files
        .iter()
        .map(|file| file.blake3.clone())
        .collect();
    let mut referenced = BTreeSet::new();
    let mut declared = KeptDeclarations::default();
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
            let files: BTreeSet<String> = strings_at(&row, record.kind, FILE_DESCRIPTOR_FIELDS)
                .into_iter()
                .filter(|digest| listed.contains(*digest))
                .map(str::to_owned)
                .collect();
            let mut names: BTreeSet<EntityId> = strings_at(&row, record.kind, ROW_IDENTITY_FIELDS)
                .into_iter()
                .filter_map(|text| EntityId::from_hex(text).ok())
                .filter(|id| archived.contains(id))
                .collect();
            if names.is_empty() {
                names_in(&row, archived, &mut names);
            }
            let fate = if names.is_empty() {
                RowFate::ByFiles(files)
            } else if names.is_subset(kept) {
                referenced.extend(files);
                declared.row(record.kind, &line)?;
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
    manifest
        .files
        .retain(|file| referenced.contains(&file.blake3));
    // Each list entry stays with the record it names: kept, or never archived.
    let stays = |id: &str| {
        EntityId::from_hex(id).is_ok_and(|id| !archived.contains(&id) || kept.contains(&id))
    };
    manifest
        .import_omissions
        .retain(|omission| stays(omission.entity_id.as_str()));
    manifest.import_refusals.retain(|refusal| match refusal {
        ExportImportRefusal::Entity { entity_id, .. } => stays(entity_id.as_str()),
        ExportImportRefusal::ProvenancedEdge { .. } => false,
    });
    manifest
        .bundle_omissions
        .retain(|omission| stays(omission.entity_id.as_str()));
    manifest
        .side_rows_withheld
        .retain(|withheld| withheld.owner.as_deref().is_none_or(stays));
    manifest
        .diary_holds
        .retain(|hold| stays(hold.agent.as_str()));
    declared.declare(&mut manifest, archived, kept);
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

/// What the kept rows declare that the readback derives from rows other
/// than the one an entry names: the edges the kept provenance claims are
/// about, the kept provenanced edges, and the kept agents with a fork hash.
#[derive(Default)]
struct KeptDeclarations {
    subjects: BTreeSet<Vec<u8>>,
    edges: Vec<(Vec<u8>, ExportImportRefusal)>,
    forked_agents: Vec<EntityId>,
}

/// An agent bundle row, as far as its birth source reads it.
#[derive(serde::Deserialize)]
struct ForkedAgent {
    entity_id: String,
    #[serde(rename = "forkHash")]
    fork_hash: Option<String>,
}

impl KeptDeclarations {
    /// One kept row of a `kind` member.
    fn row(&mut self, kind: ArchiveRecordKind, line: &[u8]) -> Result<()> {
        match kind {
            ArchiveRecordKind::Claim => {
                let claim: ExportEntity = serde_json::from_slice(line).map_err(|_| invalid())?;
                self.subjects.extend(provenance_subject_key(&claim));
            }
            ArchiveRecordKind::Edge => {
                let edge: ExportEdge = serde_json::from_slice(line).map_err(|_| invalid())?;
                if edge.provenance.is_some() {
                    let source = EntityId::from_hex(&edge.source).map_err(|_| invalid())?;
                    let target = EntityId::from_hex(&edge.target).map_err(|_| invalid())?;
                    self.edges.push((
                        edge_key(&source, edge.kind, &target),
                        ExportImportRefusal::ProvenancedEdge {
                            source: edge.source,
                            edge_kind: edge.kind,
                            target: edge.target,
                        },
                    ));
                }
            }
            ArchiveRecordKind::AgentPack => {
                let agent: ForkedAgent = serde_json::from_slice(line).map_err(|_| invalid())?;
                if agent.fork_hash.is_some() {
                    self.forked_agents
                        .push(EntityId::from_hex(&agent.entity_id).map_err(|_| invalid())?);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Writes the declarations the kept rows make into `manifest`, whose
    /// lists already hold only what kept or unarchived records declare: each
    /// kept provenanced edge no kept claim is about and neither end of which
    /// is archive-only refuses, in edge order after the entity refusals; and
    /// a kept agent whose birth source was archived but not kept misses it,
    /// first among that agent's bundle omissions.
    fn declare(
        mut self,
        manifest: &mut WholeVaultDocumentManifest,
        archived: &BTreeSet<EntityId>,
        kept: &BTreeSet<EntityId>,
    ) {
        let archive_only: BTreeSet<String> = manifest
            .import_omissions
            .iter()
            .map(|omission| omission.entity_id.clone())
            .collect();
        self.edges.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, refusal) in self.edges {
            if let ExportImportRefusal::ProvenancedEdge { source, target, .. } = &refusal
                && !self.subjects.contains(&key)
                && !archive_only.contains(source)
                && !archive_only.contains(target)
            {
                manifest.import_refusals.push(refusal);
            }
        }
        for agent in self.forked_agents {
            let Ok(carrier) = crate::agent_def::birth_source_id(&agent) else {
                continue;
            };
            let entity_id = agent.to_hex();
            let missing = ExportBundleOmission {
                entity_id: entity_id.clone(),
                reason: BundleOmissionReason::AgentBirthSourceUnavailable,
            };
            if !archived.contains(&carrier)
                || kept.contains(&carrier)
                || manifest.bundle_omissions.contains(&missing)
            {
                continue;
            }
            let at = manifest
                .bundle_omissions
                .partition_point(|omission| omission.entity_id < entity_id);
            manifest.bundle_omissions.insert(at, missing);
        }
    }
}

/// The strings `row`, a row of a `kind` member, holds at the `fields` listed
/// for that kind.
fn strings_at<'r>(
    row: &'r Value,
    kind: ArchiveRecordKind,
    fields: &[(ArchiveRecordKind, &[&str])],
) -> Vec<&'r str> {
    let mut found = Vec::new();
    for (_, path) in fields.iter().filter(|(of, _)| *of == kind) {
        strings_on(row, path, &mut found);
    }
    found
}

/// The strings at `path` below `value`.
fn strings_on<'r>(value: &'r Value, path: &[&str], found: &mut Vec<&'r str>) {
    match path.split_first() {
        None => found.extend(value.as_str()),
        Some((&"*", rest)) => {
            for item in value.as_array().into_iter().flatten() {
                strings_on(item, rest, found);
            }
        }
        Some((&"**", rest)) => {
            strings_on(value, rest, found);
            match value {
                Value::Array(items) => {
                    for item in items {
                        strings_on(item, path, found);
                    }
                }
                Value::Object(map) => {
                    for item in map.values() {
                        strings_on(item, path, found);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }
        Some((field, rest)) => {
            if let Some(item) = value.get(*field) {
                strings_on(item, rest, found);
            }
        }
    }
}

/// The archived records `value` names anywhere in it: as a string, or as an
/// object key.
fn names_in(value: &Value, archived: &BTreeSet<EntityId>, names: &mut BTreeSet<EntityId>) {
    match value {
        Value::String(text) => note(text, archived, names),
        Value::Array(items) => {
            for item in items {
                names_in(item, archived, names);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                note(key, archived, names);
                names_in(item, archived, names);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// One string of a row: an archived record's id, or not.
fn note(text: &str, archived: &BTreeSet<EntityId>, names: &mut BTreeSet<EntityId>) {
    if let Ok(id) = EntityId::from_hex(text)
        && archived.contains(&id)
    {
        names.insert(id);
    }
}

fn invalid() -> Error {
    Error::InvariantViolation("stored removal archive does not project")
}
