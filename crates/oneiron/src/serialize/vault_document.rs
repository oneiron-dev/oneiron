//! Whole-vault export (OF-222), written row by row (FIX 2766, rule 5): each
//! snapshot row becomes its typed document row, passes the credential-nulling
//! transform at the depth it holds in the document, and is spooled as one
//! JSONL row of its member; an attached file is spooled once by its digest. No
//! whole document, value, row group or file map is ever held. The archive or
//! the OKF bundle is cut from the spools once the snapshot and its diary reads
//! are done. No retrieval projection, truncation or token budget.
//!
//! A section's rows are objects, and the document pass reads a section's own
//! array only for joined text and byte runs, which an array of objects never
//! holds; so a row nulled alone at its depth from the document root is the row
//! the whole-document pass leaves.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};

use serde::Serialize;
use serde_json::Value;

use super::credential_nulling::{null_document_credentials, null_document_member};
use super::export_value::{ExportBody, ExportBodyFile, ExportValue, attaches_as_file};
use crate::Vault;
use crate::batch::export::{
    ArchiveRecordKind, ArchiveSecretCustody, ArchiveSideWithheld, ArchiveSideWithheldReason,
    ExportAdapterDescriptor, ExportCut, ExportDerivationEnvelope, ExportDiaryHold, ExportDiaryRead,
    ExportEdge, ExportEmbeddingSetup, ExportEntity, ExportEpochFloor, ExportManifest, ExportPack,
    ExportPackSource, ExportReaderFold, ExportResultBody, ExportRun, ExportRunOutput,
    ExportSkillBundle, ExportSnapshotBody, ExportSnapshotEntity, ExportSnapshotEntityBody,
    ExportSnapshotRun, ExportSourceVault, FileSpool, OmissionLedger, RecordSpool, SideRowBytes,
    VAULT_ARCHIVE_FORMAT, VAULT_OKF_FORMAT, WHOLE_VAULT_DOCUMENT_VERSION,
    WholeVaultDocumentManifest, WholeVaultExportReceipt, archive_slot_rows,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL,
};

/// What the export knows once its snapshot is read and its diary reads are
/// logged: the manifest's own fields, and the rows that left after it.
pub(crate) struct DocumentTail {
    pub(crate) storage: ExportManifest,
    pub(crate) exported_at: u64,
    pub(crate) agent_fork_hashes: BTreeMap<EntityId, String>,
    pub(crate) diary_reads: Vec<ExportDiaryRead>,
    pub(crate) diary_holds: Vec<ExportDiaryHold>,
    /// OF-490: diaries whose read could not be logged; they leave the
    /// archive with their edges.
    pub(crate) unlogged: BTreeSet<EntityId>,
    pub(crate) secrets_included: bool,
    /// FIX 12066: the custody secrets only the fold knows here, named for
    /// their holders: the manifest lists them.
    pub(crate) fold_only_secrets: Vec<EntityId>,
    /// OF-370: the vault's embedding setup, when this export carries it.
    pub(crate) embedding_setup: Option<ExportEmbeddingSetup>,
    /// The rows this export is derived from, as a host lists them beside it
    /// (DEC-0005): each row the snapshot read past its locality, the ones it
    /// carries, counts or folds into another section among them.
    pub(crate) sources: Vec<EntityId>,
}

/// The whole-vault document as its rows are spooled.
pub(crate) struct DocumentWriter<'v> {
    vault: &'v Vault,
    cut: ExportCut,
    /// OF-222, FIX 3681: an archive, whole-vault or records, carries each
    /// stored file an ASSET body is as it is stored; OKF keeps today's cut.
    attaches_files: bool,
    groups: BTreeMap<String, RecordSpool>,
    files: FileSpool,
    ledger: OmissionLedger,
    /// The AGENT_DEF ids the vault holds, read before the rows, so the claims
    /// an agent's knowledge is selected from are kept as they pass.
    agent_ids: BTreeSet<EntityId>,
    /// Each agent's birth-source ASSET, kept as it passes.
    birth_sources: BTreeSet<EntityId>,
    agents: Vec<ExportEntity>,
    skills: Vec<(EntityId, crate::skill::SkillRecord)>,
    knowledge: Vec<ExportEntity>,
    birth_bodies: BTreeMap<EntityId, ExportBody>,
    /// Each result body's row by digest, nulled and with its file detached.
    bodies: BTreeMap<String, Value>,
    side_withheld: Vec<ArchiveSideWithheld>,
}

impl<'v> DocumentWriter<'v> {
    /// A writer whose spools live under `vault`'s staging directory. The
    /// built-in adapter descriptors lead the pack member.
    pub(crate) fn new(
        vault: &'v Vault,
        cut: ExportCut,
        attaches_files: bool,
        adapters: Vec<ExportAdapterDescriptor>,
        agent_ids: BTreeSet<EntityId>,
    ) -> Result<Self> {
        let birth_sources = agent_ids
            .iter()
            .filter_map(|id| crate::agent_def::birth_source_id(id).ok())
            .collect();
        let mut writer = Self {
            vault,
            cut,
            attaches_files,
            groups: BTreeMap::new(),
            files: FileSpool::new(vault)?,
            ledger: OmissionLedger::default(),
            agent_ids,
            birth_sources,
            agents: Vec::new(),
            skills: Vec::new(),
            knowledge: Vec::new(),
            birth_bodies: BTreeMap::new(),
            bodies: BTreeMap::new(),
            side_withheld: Vec::new(),
        };
        for adapter in adapters {
            writer.push_nulled(
                ArchiveRecordKind::Pack,
                &ExportPack::BuiltinAdapter(adapter),
                2,
            )?;
        }
        Ok(writer)
    }

    /// One live entity: its row, and the derivation index, source package
    /// or pack source it carries.
    pub(crate) fn entity(&mut self, raw: ExportSnapshotEntity<'_>) -> Result<()> {
        let entity_type = raw.header.entity_type;
        // OF-222: a stored file an ASSET body is goes beside the document
        // once, by digest, as it is stored; its row carries the descriptor
        // of the bytes its copy hashed and counted. A file-plane ASSET's
        // file streams in from the snapshot, never held whole (FIX 3677).
        let body = match raw.body {
            _ if raw.tainted => ExportBody::Nulled,
            ExportSnapshotEntityBody::File(mut file) if self.attaches_files => {
                let files = &mut self.files;
                let blake3 = files.attach_reader(file.bytes, file.blake3, &mut file.reader)?;
                ExportBody::File(ExportBodyFile::checked(blake3, file.bytes))
            }
            ExportSnapshotEntityBody::File(mut file) => {
                let mut body = Vec::new();
                file.reader.read_to_end(&mut body)?;
                self.exported_body(&body, entity_type)?
            }
            ExportSnapshotEntityBody::Bytes(body)
                if self.attaches_files && attaches_as_file(entity_type, &body) =>
            {
                let blake3 = self.files.attach(&body)?;
                ExportBody::File(ExportBodyFile::checked(blake3, body.len() as u64))
            }
            ExportSnapshotEntityBody::Bytes(body) => self.exported_body(&body, entity_type)?,
        };
        let id = raw.id.to_hex();
        if entity_type == ENTITY_TYPE_CLAIM
            && let ExportBody::MessagePack(ExportValue::Map(entries)) = &body
            && let Some((_, evidence)) = entries
                .iter()
                .find(|(key, _)| matches!(key, ExportValue::String(key) if key == "evid"))
        {
            let envelope = ExportDerivationEnvelope {
                id: id.clone(),
                evidence: evidence.clone(),
                receipts: crate::batch::export::receipt_sources_for_body(
                    &body,
                    &raw.task_receipts,
                    raw.archived_receipts.as_ref(),
                )?,
            };
            self.push_nulled(ArchiveRecordKind::DerivationEnvelope, &envelope, 2)?;
        }
        let entity = ExportEntity {
            id,
            short_ref: raw.short_ref,
            entity_type,
            occurred_start: raw.header.occurred_start,
            occurred_end: raw.header.occurred_end,
            learned_at: raw.header.learned_at,
            body,
        };
        self.ledger.entity(&entity)?;
        if let Some(source) = raw.pack_source {
            let tree = super::source_tree::export_source_tree_with_files(
                source.files(),
                &mut self.files,
                raw.tainted,
            )?;
            let pack = ExportPack::Source(ExportPackSource {
                entity_id: entity.id.clone(),
                source_tree: tree,
            });
            self.push_tree(ArchiveRecordKind::Pack, &pack)?;
        }
        match entity_type {
            ENTITY_TYPE_CLAIM => {
                if self.about_an_agent(&entity) {
                    self.knowledge.push(entity.clone());
                }
                self.push_entity(ArchiveRecordKind::Claim, &entity, 2)
            }
            ENTITY_TYPE_SKILL => {
                let package = raw.skill_package;
                let source_format = package.as_ref().map(|package| package.format);
                let source_tree = package
                    .map(|package| {
                        super::source_tree::export_source_tree_with_files(
                            &package.files,
                            &mut self.files,
                            raw.tainted,
                        )
                    })
                    .transpose()?;
                self.skills
                    .extend(super::vault_bundles::skill_records(std::iter::once(
                        &entity,
                    )));
                let bundle = ExportSkillBundle {
                    entity,
                    source_tree,
                    source_format,
                };
                self.ledger.skill(&bundle);
                self.push_tree(ArchiveRecordKind::Skill, &bundle)
            }
            _ => {
                if entity_type == ENTITY_TYPE_AGENT_DEF {
                    self.agents.push(entity.clone());
                }
                if entity_type == ENTITY_TYPE_ASSET && self.birth_sources.contains(&raw.id) {
                    self.birth_bodies.insert(raw.id, entity.body.clone());
                }
                self.push_entity(ArchiveRecordKind::Entity, &entity, 3)
            }
        }
    }

    /// One structural graph edge between two carried rows.
    pub(crate) fn edge(&mut self, edge: &ExportEdge) -> Result<()> {
        self.ledger.edge(edge);
        self.push_nulled(ArchiveRecordKind::Edge, edge, 3)
    }

    /// One run's result manifests (OF-190 B++), a withheld occurrence with its
    /// reason and no body, each fold receipt beside the occurrence it
    /// describes.
    pub(crate) fn run(&mut self, run: ExportSnapshotRun) -> Result<()> {
        let hex = crate::entity_id::bytes_to_hex_lower;
        let row = ExportRun {
            receipts: run
                .receipts
                .iter()
                .map(|(receipt, withheld)| ExportReaderFold {
                    path: receipt.folded.path.clone(),
                    receipt: match withheld {
                        Some(_) => receipt.refs_only(),
                        None => serde_json::to_value(receipt).unwrap_or_default(),
                    },
                    withheld: withheld.map(str::to_owned),
                })
                .collect(),
            run_id: run.run_id.to_hex(),
            outputs: run
                .outputs
                .into_iter()
                .map(|(output, withheld)| ExportRunOutput {
                    blake3: withheld.is_none().then(|| hex(&output.raw_blake3)),
                    bytes: output.raw_len,
                    kind: match output.kind {
                        crate::code_run::CodeRunOutputKind::Text => "text",
                        crate::code_run::CodeRunOutputKind::Binary => "binary",
                    }
                    .to_owned(),
                    lines: output.lines,
                    complete: output.complete,
                    path: output.path,
                    withheld: withheld.map(str::to_owned),
                })
                .collect(),
        };
        self.push_nulled(ArchiveRecordKind::Run, &row, 3)
    }

    /// One result body a clean occurrence names, once. It is copied as it
    /// streams onto the end of the archive's file spool, unindexed, checked
    /// to its end against its length and digest, and read there by the
    /// release door's scan, never held whole (FIX 5392) and on disk once
    /// (FIX 7213); a body the scan passes is indexed there and goes in
    /// `files/` as it is, never base64-encoded into the text around that
    /// scan (Docs Q20), and its row carries no content. Any other staged body
    /// is cut off again. A row the nulling pass leaves naming other bytes
    /// than the copy hashes to is withheld as a credential rather than
    /// shipped under a name it does not hash to.
    pub(crate) fn result_body(
        &mut self,
        digest: [u8; 32],
        body: ExportSnapshotBody<'_>,
    ) -> Result<()> {
        let hex = crate::entity_id::bytes_to_hex_lower(&digest);
        let mut clean = None;
        let withheld = match body.body {
            Err(reason) => Some(reason),
            Ok(reader) => {
                let files = &mut self.files;
                let staged = files.stage(body.bytes, |out| reader.copy_checked(out))?;
                let found = files.scan_staged(&staged, |spooled| {
                    crate::batch::secret_scan::scan_file_content_from("", spooled)
                })?;
                match found {
                    Some(_) => {
                        files.discard_staged(staged)?;
                        Some("credential")
                    }
                    None => {
                        clean = Some(staged);
                        None
                    }
                }
            }
        };
        let row = ExportResultBody {
            blake3: hex.clone(),
            bytes: body.bytes,
            content: None,
            withheld: withheld.map(str::to_owned),
        };
        let mut row = nulled(&row, "", 3)?;
        let mut keep = None;
        if let Some(fields) = row.as_object_mut() {
            let content = fields.get_mut("content").map(Value::take);
            if !fields
                .get("withheld")
                .is_some_and(|reason| !reason.is_null())
            {
                let named = fields
                    .get("blake3")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                match (content, named, clean.as_ref()) {
                    (Some(Value::Null) | None, Some(named), Some(_)) if named == hex => {
                        keep = Some(named);
                    }
                    _ => {
                        fields.insert("withheld".to_owned(), Value::from("credential"));
                    }
                }
            }
        }
        if let Some(staged) = clean {
            match keep {
                Some(named) => self.files.commit_staged(named, staged)?,
                None => self.files.discard_staged(staged)?,
            }
        }
        self.bodies.insert(hex, row);
        Ok(())
    }

    /// One owner custody record, written as it is: never through nulling,
    /// because carrying it is the point.
    pub(crate) fn secret(&mut self, secret: &ArchiveSecretCustody) -> Result<()> {
        let row = serde_json::to_value(secret).map_err(|_| encode_failed())?;
        self.push(ArchiveRecordKind::SecretCustody, &row)
    }

    /// One session's epoch floor (OF-013).
    pub(crate) fn epoch_floor(&mut self, floor: &ExportEpochFloor) -> Result<()> {
        self.push_nulled(ArchiveRecordKind::EpochFloor, floor, 2)
    }

    /// FIX 2768: one side row in its table's codec, read alone by the nulling
    /// pass at its depth; one the pass would change, one in its table's own
    /// binary codec the release scan reads a credential in, or one that does
    /// not read back through its table, is held out and named in the
    /// manifest. A long binary value goes beside the document as a file.
    pub(crate) fn side_row(&mut self, raw: SideRowBytes) -> Result<()> {
        let Some((row, files)) = raw.portable()? else {
            self.side_withheld
                .push(raw.withheld(ArchiveSideWithheldReason::NotPortable));
            return Ok(());
        };
        let value = serde_json::to_value(&row).map_err(|_| encode_failed())?;
        if raw.opaque_credential() || null_document_member("", &value, 2) != value {
            self.side_withheld
                .push(raw.withheld(ArchiveSideWithheldReason::Credential));
            return Ok(());
        }
        for bytes in files {
            self.files.attach(&bytes)?;
        }
        self.push(ArchiveRecordKind::SideTable, &value)
    }

    /// FIX 3681: the side-row families held out whole, each named once with
    /// its carried record: a row of one names a carrier not carried, or does
    /// not read.
    pub(crate) fn side_rows_withheld(
        &mut self,
        withheld: impl IntoIterator<Item = ArchiveSideWithheld>,
    ) {
        self.side_withheld.extend(withheld);
    }

    /// Builds the agent bundles and the manifest, then writes the archive, or
    /// the OKF bundle, to `sink`.
    pub(crate) fn finish<W: Write + Seek>(
        mut self,
        tail: DocumentTail,
        sink: W,
    ) -> Result<(W, WholeVaultExportReceipt)> {
        let agents: Vec<&ExportEntity> = self.agents.iter().collect();
        let bundles = super::vault_bundles::agent_bundles(
            &agents,
            &self.skills,
            &self.knowledge,
            &tail.agent_fork_hashes,
            crate::agent_def::KnowledgeFormat::CURRENT,
        )?;
        for bundle in &bundles {
            self.ledger
                .agent(bundle, |carrier| self.birth_bodies.get(carrier));
            self.push_tree(ArchiveRecordKind::AgentPack, bundle)?;
        }
        // OF-370: each setup descriptor is read alone by this document's
        // nulling pass first; one the pass would change leaves whole, counted
        // in the manifest, and the rest go through the pass at their depth.
        let (spaces, slots, embedding_setup_withheld) = match tail
            .embedding_setup
            .map(|setup| setup.released(|value| null_document_credentials(value) != *value))
            .transpose()?
        {
            Some(setup) => (setup.spaces, Some(setup.slots), setup.withheld),
            None => (Vec::new(), None, Default::default()),
        };
        for space in &spaces {
            self.push_nulled(ArchiveRecordKind::EmbeddingSpace, space, 2)?;
        }
        if let Some(slots) = slots {
            let slots = serde_json::to_value(&slots).map_err(|_| encode_failed())?;
            let slots = null_document_member("slot_bindings", &slots, 1);
            let mut section = serde_json::json!({ "slot_bindings": slots });
            for row in archive_slot_rows(&mut section) {
                self.push(ArchiveRecordKind::SlotBinding, &row)?;
            }
        }
        for row in std::mem::take(&mut self.bodies).into_values() {
            self.push(ArchiveRecordKind::ResultBody, &row)?;
        }
        // The gate logged the diary reads after the snapshot. An entry whose
        // read could not be logged leaves the archive, with its edges.
        if !tail.unlogged.is_empty() {
            let gone: BTreeSet<String> = tail.unlogged.iter().map(EntityId::to_hex).collect();
            self.ledger.forget(&gone);
            let named = |row: &Value, field: &str| {
                row.get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|id| gone.contains(id))
            };
            let notes = ArchiveRecordKind::entity_path(crate::registry::ENTITY_TYPE_NOTE);
            if let Some(spool) = self.groups.remove(&notes) {
                let kept = spool.filtered(self.vault, |row| named(row, "id"))?;
                self.groups.insert(notes, kept);
            }
            if let Some(path) = ArchiveRecordKind::Edge.fixed_path()
                && let Some(spool) = self.groups.remove(path)
            {
                let kept = spool.filtered(self.vault, |row| {
                    named(row, "source") || named(row, "target")
                })?;
                self.groups.insert(path.to_owned(), kept);
            }
        }
        let (import_refusals, import_omissions, bundle_omissions) = self.ledger.finish();
        let storage = tail.storage.with_serializer_nulling();
        let manifest = WholeVaultDocumentManifest {
            manifest_version: WHOLE_VAULT_DOCUMENT_VERSION,
            format: match self.cut {
                ExportCut::Archive => VAULT_ARCHIVE_FORMAT,
                ExportCut::Okf => VAULT_OKF_FORMAT,
            }
            .to_owned(),
            serializer: storage.serializer().clone(),
            secrets_nulled: true,
            source_vault: ExportSourceVault {
                vault_id: storage.authority().map(|a| a.vault_id().to_owned()),
                exported_at: tail.exported_at,
            },
            storage,
            import_omissions,
            import_refusals,
            bundle_omissions,
            source_boundaries: vec![
                crate::batch::export::ExportSourceBoundary::BuiltinAdapterCodeNotStored,
            ],
            records: Vec::new(),
            files: Vec::new(),
            diary_holds: tail.diary_holds,
            secrets_included: tail.secrets_included,
            fold_only_secrets: Vec::new(),
            embedding_setup_withheld,
            side_rows_withheld: self.side_withheld,
        };
        // The manifest's strings go through the same pass, at its depth. The
        // member and file lists are added after: paths, counts and digests.
        let mut manifest: WholeVaultDocumentManifest =
            serde_json::from_value(nulled(&manifest, "manifest", 1)?)
                .map_err(|_| encode_failed())?;
        // Ids only, added after the pass as the member lists are (FIX 12066).
        manifest.fold_only_secrets = tail
            .fold_only_secrets
            .iter()
            .map(EntityId::to_hex)
            .collect();
        let sink = match self.cut {
            ExportCut::Archive => {
                manifest.records = self
                    .groups
                    .iter()
                    .map(|(path, spool)| spool.record(path))
                    .collect();
                manifest.files = self.files.manifest();
                super::vault_archive::write_vault_archive(
                    sink,
                    &manifest,
                    &mut self.groups,
                    &mut self.files,
                )?
            }
            ExportCut::Okf => {
                super::okf_bundle::write_okf_bundle(sink, &mut self.groups, tail.exported_at)?
            }
        };
        Ok((
            sink,
            WholeVaultExportReceipt {
                manifest,
                diary_reads: tail.diary_reads,
                sources: tail.sources,
                thread_roots: Default::default(),
                holder_requests: Vec::new(),
            },
        ))
    }

    /// A stored body as its typed export; a hub source's members stored as
    /// files are spooled as the bytes its credential scan read (FIX 10101).
    fn exported_body(&mut self, body: &[u8], entity_type: u8) -> Result<ExportBody> {
        let exported = ExportBody::from_bytes(body, entity_type);
        if let ExportBody::HubSource(source) = &exported {
            source.attach_files(body, &mut self.files)?;
        }
        Ok(exported)
    }

    /// Whether a claim row selects an agent's knowledge: its subject is an
    /// agent this vault holds.
    fn about_an_agent(&self, row: &ExportEntity) -> bool {
        !self.agent_ids.is_empty()
            && row
                .body
                .to_bytes()
                .ok()
                .and_then(|bytes| crate::claim::decode_claim_body(&bytes, false).ok())
                .is_some_and(|claim| {
                    matches!(claim.subject, crate::claim::ClaimSubject::Entity(id)
                        if self.agent_ids.contains(&id))
                })
    }

    /// An entity row at `depth`. A file body's descriptor, or a hub source
    /// member's, the pass changed refuses the export, naming its entity, so no
    /// bytes go under a reference that no longer names them.
    fn push_entity(
        &mut self,
        kind: ArchiveRecordKind,
        entity: &ExportEntity,
        depth: usize,
    ) -> Result<()> {
        let typed = serde_json::to_value(entity).map_err(|_| encode_failed())?;
        let row = null_document_member("", &typed, depth);
        if !file_members_kept(&typed, &row, "/body/value/source_tree/files") {
            return Err(Error::InvalidConfig(format!(
                "whole-vault export: the credential pass changed entity {}'s source file reference",
                entity.id
            )));
        }
        if let ExportBody::File(file) = &entity.body {
            let descriptor = serde_json::to_value(ExportBody::File(file.clone()))
                .map_err(|_| encode_failed())?;
            if row.get("body") != Some(&descriptor) {
                return Err(Error::InvalidConfig(format!(
                    "whole-vault export: the credential pass changed entity {}'s file reference",
                    entity.id
                )));
            }
        }
        let path = match kind {
            ArchiveRecordKind::Entity => ArchiveRecordKind::entity_path(entity.entity_type),
            kind => kind.fixed_path().ok_or_else(encode_failed)?.to_owned(),
        };
        self.push_at(kind, path, &row)
    }

    /// A row holding a source tree, at depth 2. Its text members stay in the
    /// row; a member stored as a file keeps the descriptor of the bytes
    /// spooled for it (FIX 10101), and one the pass changed refuses the export.
    fn push_tree(&mut self, kind: ArchiveRecordKind, row: &impl Serialize) -> Result<()> {
        let typed = serde_json::to_value(row).map_err(|_| encode_failed())?;
        let row = null_document_member("", &typed, 2);
        let files = match kind {
            ArchiveRecordKind::Pack => "/value/source_tree/files",
            _ => "/source_tree/files",
        };
        if !file_members_kept(&typed, &row, files) {
            return Err(Error::InvalidConfig(
                "whole-vault export: the credential pass changed a source file reference"
                    .to_owned(),
            ));
        }
        self.push(kind, &row)
    }

    fn push_nulled(
        &mut self,
        kind: ArchiveRecordKind,
        row: &impl Serialize,
        depth: usize,
    ) -> Result<()> {
        let row = nulled(row, "", depth)?;
        self.push(kind, &row)
    }

    fn push(&mut self, kind: ArchiveRecordKind, row: &Value) -> Result<()> {
        let path = kind.fixed_path().ok_or_else(encode_failed)?.to_owned();
        self.push_at(kind, path, row)
    }

    fn push_at(&mut self, kind: ArchiveRecordKind, path: String, row: &Value) -> Result<()> {
        let vault = self.vault;
        let spool = match self.groups.entry(path) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(RecordSpool::new(vault, kind)?)
            }
        };
        spool.push(row)
    }
}

/// Whether the pass left each member stored as a file of the source tree
/// at `files` in `typed` as it was, in `kept`.
fn file_members_kept(typed: &Value, kept: &Value, files: &str) -> bool {
    let Some(members) = typed.pointer(files).and_then(Value::as_array) else {
        return true;
    };
    members.iter().enumerate().all(|(index, member)| {
        let content = member.get("content");
        content
            .and_then(|content| content.get("kind"))
            .and_then(Value::as_str)
            != Some("file")
            || kept.pointer(&format!("{files}/{index}/content")) == content
    })
}

/// `row` as the document's pass leaves it at `depth` under `key`.
fn nulled(row: &impl Serialize, key: &str, depth: usize) -> Result<Value> {
    let value = serde_json::to_value(row).map_err(|_| encode_failed())?;
    Ok(null_document_member(key, &value, depth))
}

fn encode_failed() -> Error {
    Error::InvariantViolation("whole-vault document serialization failed")
}
