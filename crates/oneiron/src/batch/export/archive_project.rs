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
//! names). A row with no identity field that names nothing and refers to no
//! file (a built-in adapter's pack row) stays, as every export writes it
//! (FIX-LIST 11110). A side row goes with the record and carriers its table
//! reads from it, a record's rows of one group together or not at all, and a
//! kept record's group that does not stay whole is named in the manifest as
//! a fresh export of the kept records names it ([`project_side_rows`]).
//!
//! A kept agent's bundle is rebuilt from the kept rows with the export's own
//! builder (FIX-LIST 11109), as the readback re-derives it: its knowledge
//! facet holds only the kept claims about it and its skills only the kept
//! skills, so no text of a record the projection leaves out stays in a kept
//! file. A file reference is a digest in a field the writer writes file
//! descriptors in ([`FILE_DESCRIPTOR_FIELDS`]), never any string equal to
//! one. An attached file stays only when a kept row refers to it and goes as
//! it is stored; a rebuilt bundle's text members stay in its row. Every member
//! the manifest lists is rebuilt with its new rows, length and BLAKE3. Every
//! manifest list naming a record keeps only what a kept or unarchived record
//! declares, and the declarations the readback checks against the rows (a
//! provenanced edge's refusal, an agent's missing birth source, a rebuilt
//! bundle's own omission) are derived again from the kept rows, so the
//! projection reads back through the same checks as any archive. Row order
//! is kept.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Cursor, Read, Write};

use serde_json::Value;

use super::archive_index::edge_key;
use super::archive_side_tables::project_side_rows;
use super::bundle_validation::{agent_omission_reason, provenance_subject_key};
use super::{
    AgentBundleOmission, ArchiveRecordFile, ArchiveRecordKind, ArchiveSideRow,
    BundleOmissionReason, ExportBundleOmission, ExportEdge, ExportEntity, ExportImportRefusal,
    VAULT_ARCHIVE_MANIFEST_PATH, WholeVaultDocumentManifest, archive_file_path,
};
use crate::agent_def::KnowledgeFormat;
use crate::claim::{ClaimSubject, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::serialize::ExportBodyFile;
use crate::skill::SkillRecord;

/// Where the export writer (`serialize::vault_document`) writes an attached
/// file's digest, by member kind: field names from the row's root, `*` for
/// each item of an array, `**` for any depth below. An entity body that is a
/// stored file (`ExportBody::File`, `{blake3, bytes}` under `body.value`); a
/// source tree's member stored as a file (`ExportBodyFile` under
/// `content.value`, FIX 10101), a hub source body's members too; a run
/// output's and a result body's `blake3`; a side row's value, or a leaf of
/// its tree, stored as a file (`ExportBodyFile` again).
const FILE_DESCRIPTOR_FIELDS: &[(ArchiveRecordKind, &[&str])] = &[
    (ArchiveRecordKind::Entity, &["body", "value", "blake3"]),
    (
        ArchiveRecordKind::Entity,
        &[
            "body",
            "value",
            "source_tree",
            "files",
            "*",
            "content",
            "value",
            "blake3",
        ],
    ),
    (ArchiveRecordKind::Claim, &["body", "value", "blake3"]),
    (
        ArchiveRecordKind::Skill,
        &["entity", "body", "value", "blake3"],
    ),
    (
        ArchiveRecordKind::Skill,
        &["source_tree", "files", "*", "content", "value", "blake3"],
    ),
    (
        ArchiveRecordKind::Pack,
        &[
            "value",
            "source_tree",
            "files",
            "*",
            "content",
            "value",
            "blake3",
        ],
    ),
    (
        ArchiveRecordKind::AgentPack,
        &["source_tree", "files", "*", "content", "value", "blake3"],
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
/// epoch floor's `session`. A side row is not listed: it goes with the record
/// its table reads from it, judged with its group ([`project_side_rows`]).
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
    let mut referenced = BTreeSet::new();
    let mut declared = KeptDeclarations::default();
    let mut members = Vec::with_capacity(manifest.records.len());
    // Judged once every member is read: the side rows, with their member,
    // row and files, and the kept agent bundles, by member and row.
    let (mut sides, mut side_at) = (Vec::new(), Vec::new());
    let mut agents = Vec::new();
    for (at, record) in manifest.records.iter().enumerate() {
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
                .map(str::to_owned)
                .collect();
            if record.kind == ArchiveRecordKind::SideTable {
                sides.push(serde_json::from_value::<ArchiveSideRow>(row).map_err(|_| invalid())?);
                side_at.push((at, rows.len(), files));
                rows.push((line, RowFate::Drop));
                continue;
            }
            let identity = strings_at(&row, record.kind, ROW_IDENTITY_FIELDS);
            let mut names: BTreeSet<EntityId> = identity
                .iter()
                .filter_map(|text| EntityId::from_hex(text).ok())
                .filter(|id| archived.contains(id))
                .collect();
            if names.is_empty() {
                names_in(&row, archived, &mut names);
            }
            let fate = if names.is_empty() {
                if identity.is_empty() && files.is_empty() {
                    RowFate::Keep
                } else {
                    RowFate::ByFiles(files)
                }
            } else if names.is_subset(kept) {
                declared.row(record.kind, &line)?;
                if record.kind == ArchiveRecordKind::AgentPack {
                    agents.push((at, rows.len()));
                } else {
                    referenced.extend(files);
                }
                RowFate::Keep
            } else {
                RowFate::Drop
            };
            rows.push((line, fate));
        }
        members.push(rows);
    }
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
    let side_stays = project_side_rows(
        &sides,
        kept,
        &mut manifest.side_rows_withheld,
        &mut |file: &ExportBodyFile| archived_file(&mut source, file),
    )?;
    for ((at, row, files), staying) in side_at.into_iter().zip(side_stays) {
        if staying {
            referenced.extend(files);
            members[at][row].1 = RowFate::Keep;
        }
    }
    // FIX-LIST 11109: each kept agent bundle is rebuilt from the kept rows;
    // its text members stay in its row (FIX 10101), and a member stored as a
    // file keeps the archive file it names.
    if !agents.is_empty() {
        let mut ids = Vec::with_capacity(agents.len());
        for &(at, row) in &agents {
            ids.push(agent_of(&members[at][row].0)?);
        }
        let kept_agents: BTreeSet<EntityId> = ids.iter().map(|(id, _)| *id).collect();
        let rows = KeptAgentRows::read(&manifest.records, &members, &kept_agents)?;
        for ((at, row), (id, fork_hash)) in agents.into_iter().zip(ids) {
            let rebuilt = rows.rebuild(id, fork_hash, &mut declared)?;
            referenced.extend(
                strings_at(
                    &rebuilt,
                    ArchiveRecordKind::AgentPack,
                    FILE_DESCRIPTOR_FIELDS,
                )
                .into_iter()
                .map(str::to_owned),
            );
            members[at][row].0 = serde_json::to_vec(&rebuilt).map_err(|_| invalid())?;
        }
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

/// The archive file `file` names, read whole and checked against its length
/// and BLAKE3.
fn archived_file(
    source: &mut zip::ZipArchive<Cursor<&[u8]>>,
    file: &ExportBodyFile,
) -> Result<Vec<u8>> {
    let mut member = source
        .by_name(&archive_file_path(file.blake3()))
        .map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    member.read_to_end(&mut bytes).map_err(|_| invalid())?;
    if bytes.len() as u64 != file.bytes() || blake3::hash(&bytes).to_hex().as_str() != file.blake3()
    {
        return Err(invalid());
    }
    Ok(bytes)
}

/// An agent bundle row's agent and fork hash.
fn agent_of(line: &[u8]) -> Result<(EntityId, Option<String>)> {
    let agent: ForkedAgent = serde_json::from_slice(line).map_err(|_| invalid())?;
    let id = EntityId::from_hex(&agent.entity_id).map_err(|_| invalid())?;
    Ok((id, agent.fork_hash))
}

/// The kept rows a kept agent's bundle is rebuilt from, as the readback
/// re-derives it: each kept agent's AGENT_DEF row, every kept skill's record,
/// and the kept claims about a kept agent.
struct KeptAgentRows {
    definitions: BTreeMap<EntityId, ExportEntity>,
    skills: Vec<(EntityId, SkillRecord)>,
    claims: Vec<ExportEntity>,
}

/// A skill row, as far as its record reads it.
#[derive(serde::Deserialize)]
struct SkillRow {
    entity: ExportEntity,
}

impl KeptAgentRows {
    /// The kept rows of `members` (the members `records` lists, each row with
    /// its fate) the bundles of `agents` are rebuilt from.
    fn read(
        records: &[ArchiveRecordFile],
        members: &[Vec<(Vec<u8>, RowFate)>],
        agents: &BTreeSet<EntityId>,
    ) -> Result<Self> {
        let definitions_path = ArchiveRecordKind::entity_path(ENTITY_TYPE_AGENT_DEF);
        let mut rows = Self {
            definitions: BTreeMap::new(),
            skills: Vec::new(),
            claims: Vec::new(),
        };
        for (record, member) in records.iter().zip(members) {
            for (line, fate) in member {
                if !matches!(fate, RowFate::Keep) {
                    continue;
                }
                match record.kind {
                    ArchiveRecordKind::Entity if record.path == definitions_path => {
                        let row: ExportEntity =
                            serde_json::from_slice(line).map_err(|_| invalid())?;
                        let id = EntityId::from_hex(&row.id).map_err(|_| invalid())?;
                        if row.entity_type == ENTITY_TYPE_AGENT_DEF && agents.contains(&id) {
                            rows.definitions.insert(id, row);
                        }
                    }
                    ArchiveRecordKind::Skill => {
                        let skill: SkillRow =
                            serde_json::from_slice(line).map_err(|_| invalid())?;
                        if let Ok(id) = EntityId::from_hex(&skill.entity.id)
                            && let Ok(body) = skill.entity.body.to_bytes()
                            && let Ok(record) = crate::skill::decode_skill_record(&body)
                        {
                            rows.skills.push((id, record));
                        }
                    }
                    ArchiveRecordKind::Claim => {
                        let claim: ExportEntity =
                            serde_json::from_slice(line).map_err(|_| invalid())?;
                        if claim
                            .body
                            .to_bytes()
                            .ok()
                            .and_then(|bytes| decode_claim_body(&bytes, false).ok())
                            .is_some_and(|body| {
                                matches!(body.subject, ClaimSubject::Entity(about)
                                    if agents.contains(&about))
                            })
                        {
                            rows.claims.push(claim);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(rows)
    }

    /// The bundle of the kept agent `id`, whose stored bundle carries
    /// `fork_hash`, rebuilt from these rows with the export's builder in its
    /// knowledge form, as the row the export's writer writes: each text
    /// member in the row, through the writer's own document credential pass
    /// for a source-tree row. Its own omission is noted in `declared`.
    fn rebuild(
        &self,
        id: EntityId,
        fork_hash: Option<String>,
        declared: &mut KeptDeclarations,
    ) -> Result<Value> {
        let definition = self.definitions.get(&id).ok_or_else(invalid)?;
        let forked = fork_hash.is_some();
        let bundle = crate::serialize::agent_bundle(
            definition,
            &self.skills,
            &self.claims,
            fork_hash,
            KnowledgeFormat::CURRENT,
        )?;
        declared.agents.push(KeptAgent {
            id,
            forked,
            omission: bundle.omission,
        });
        let row = serde_json::to_value(&bundle).map_err(|_| invalid())?;
        Ok(crate::serialize::null_document_tree_row(&row))
    }
}

/// What the kept rows declare that the readback derives from rows other
/// than the one an entry names: the edges the kept provenance claims are
/// about, the kept provenanced edges, and the kept agents' rebuilt bundles.
#[derive(Default)]
struct KeptDeclarations {
    subjects: BTreeSet<Vec<u8>>,
    edges: Vec<(Vec<u8>, ExportImportRefusal)>,
    agents: Vec<KeptAgent>,
}

/// A kept agent: whether its bundle has a fork hash, and its rebuilt
/// bundle's own omission.
struct KeptAgent {
    id: EntityId,
    forked: bool,
    omission: Option<AgentBundleOmission>,
}

/// An agent bundle row, as far as its rebuild and birth source read it.
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
            _ => {}
        }
        Ok(())
    }

    /// Writes the declarations the kept rows make into `manifest`, whose
    /// lists already hold only what kept or unarchived records declare: each
    /// kept provenanced edge no kept claim is about and neither end of which
    /// is archive-only refuses, in edge order after the entity refusals; a
    /// kept agent's rebuilt bundle declares its own omission, last among
    /// that agent's bundle omissions; and a kept agent whose birth source
    /// was archived but not kept misses it, first among them.
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
        let rebuilt: BTreeSet<String> = self.agents.iter().map(|agent| agent.id.to_hex()).collect();
        manifest.bundle_omissions.retain(|omission| {
            omission.reason == BundleOmissionReason::AgentBirthSourceUnavailable
                || !rebuilt.contains(&omission.entity_id)
        });
        for agent in &self.agents {
            if let Some(omission) = agent.omission {
                let entity_id = agent.id.to_hex();
                let at = manifest
                    .bundle_omissions
                    .partition_point(|declared| declared.entity_id <= entity_id);
                manifest.bundle_omissions.insert(
                    at,
                    ExportBundleOmission {
                        entity_id,
                        reason: agent_omission_reason(omission),
                    },
                );
            }
        }
        for agent in self.agents.iter().filter(|agent| agent.forked) {
            let Ok(carrier) = crate::agent_def::birth_source_id(&agent.id) else {
                continue;
            };
            let entity_id = agent.id.to_hex();
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
