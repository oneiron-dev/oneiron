//! Validating archive import through ordinary admission doors, never sync replay.
//! FIX 3678: the archive is read into the import's disk-backed row index, and
//! each pass reads one row at a time from it; the dependency queues, id sets
//! and maps grow in the index as well, so no archive-wide row state stays in
//! memory. The rows still go in through one write transaction.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use serde::Deserialize;

use super::archive_index::{
    ArchiveIndex, EntityAt, FLAG_EXPRESSION, FLAG_PACK_BODY, FLAG_PROVENANCE, IndexedArchive,
    QUEUE_EXPRESSION, QUEUE_PROVENANCE, QUEUE_ROW, Section, Tag, id_at, id_list, ids_of, ready_key,
};
use super::{
    ArchiveFiles, ArchiveRecordKind, ExportDerivationEnvelope, ExportEdge, ExportEntity,
    ExportEpochFloor, ExportResultBody, ExportRun, ExportSkillBundle, WholeVaultDocument,
    WholeVaultImportReceipt,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimSource, ClaimSubject, decode_claim_body, encode_claim_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION,
    ENTITY_TYPE_SKILL, ENTITY_TYPE_WORKFLOW,
};
use crate::serialize::{ExportBody, ExportBodyFile};
use crate::temporal::TimeRange;
use crate::vault::live_entity_row_in_txn;
use crate::write_envelope::WriteActor;

impl Vault {
    /// Validates a whole-vault archive (OF-222) and the document its records
    /// assemble into, without writing anything. The returned data remains
    /// untrusted. A manifest is not an approval grant.
    pub fn read_whole_vault_archive(&self, bytes: &[u8]) -> Result<WholeVaultDocument> {
        self.read_whole_vault_archive_from(std::io::Cursor::new(bytes))
    }

    /// [`Self::read_whole_vault_archive`] from a file or other seekable
    /// source, read member by member (FIX 2766): the archive is never held
    /// whole, and its attached files stay in it. The rows are validated
    /// through the import's row index (FIX 3678); only the document this
    /// returns is built whole, because it is what the caller asked for.
    pub fn read_whole_vault_archive_from<R: Read + Seek>(
        &self,
        source: R,
    ) -> Result<WholeVaultDocument> {
        let scratch = self.store.archive_scratch_env()?;
        let mut archive = super::read_vault_archive_indexed(self, &scratch, source)?;
        archive.validate(self)?;
        archive.document()
    }

    /// Reimports a whole-vault archive atomically, into a fresh vault or
    /// beside rows it already holds. IDs, times, ordinary body fields and
    /// public edges survive, and an ASSET's stored file comes back byte for
    /// byte (OF-222). Ordinary claims become Imported + Proposed (Rejected
    /// stays Rejected); lifecycle and scope are retained. Expression histories
    /// require [`Self::import_whole_vault_archive_with_actor`] and a local Auto grant.
    /// Skills return as candidates;
    /// agent definitions are disabled and proposed until locally reviewed.
    ///
    /// Same-ID divergent rows are refused, never overwritten. Maintenance rows,
    /// witness messages, notes, other reserved claims and owned/provenanced edges need
    /// their owning import adapter and fail through the existing public doors.
    /// Such a failure aborts the entire transaction, not a partial import.
    /// The manifest explicitly marks hub configuration and foreign skill signals
    /// archive-only. They are never restored as local policy or trusted verdicts;
    /// imported file bundles run the native scanner and Candidate admission door.
    /// The archive's embedding setup (OF-370) declares the spaces and binds the
    /// slots this vault lacks; it never overwrites this vault's own setup, and
    /// a conflict with it is reported, never a refusal of the import.
    pub fn import_whole_vault_archive(&self, bytes: &[u8]) -> Result<WholeVaultImportReceipt> {
        self.import_whole_vault_archive_from(std::io::Cursor::new(bytes))
    }

    /// [`Self::import_whole_vault_archive`] from a file or other seekable
    /// source, read member by member (FIX 2766): no archive member, row
    /// group or file map is held whole, each attached file is read when its
    /// row goes in, and the import is still one atomic write transaction.
    /// The rows wait in a disk-backed row index (FIX 3678), never in memory.
    pub fn import_whole_vault_archive_from<R: Read + Seek>(
        &self,
        source: R,
    ) -> Result<WholeVaultImportReceipt> {
        self.import_whole_vault_archive_as(source, None)
    }

    /// Imports with a current local actor authenticated by the host. Never use
    /// an actor taken from the archive. The actor must already exist locally.
    /// Expression preferences require a local Imported-source Auto grant; this
    /// argument confers no grant and cannot restore foreign author authority.
    pub fn import_whole_vault_archive_with_actor(
        &self,
        bytes: &[u8],
        actor: &WriteActor,
    ) -> Result<WholeVaultImportReceipt> {
        self.import_whole_vault_archive_from_with_actor(std::io::Cursor::new(bytes), actor)
    }

    /// [`Self::import_whole_vault_archive_with_actor`] from a seekable source,
    /// read member by member (FIX 2766).
    pub fn import_whole_vault_archive_from_with_actor<R: Read + Seek>(
        &self,
        source: R,
        actor: &WriteActor,
    ) -> Result<WholeVaultImportReceipt> {
        self.import_whole_vault_archive_as(source, Some(actor))
    }

    fn import_whole_vault_archive_as<R: Read + Seek>(
        &self,
        source: R,
        actor: Option<&WriteActor>,
    ) -> Result<WholeVaultImportReceipt> {
        let scratch = self.store.archive_scratch_env()?;
        let mut archive = super::read_vault_archive_indexed(self, &scratch, source)?;
        archive.validate(self)?;
        if actor.is_none() && archive.expressions {
            return Err(actor_required());
        }
        let authority =
            self.classify_vault_import_manifest(&archive.manifest.storage.to_json_pretty()?, None)?;
        // Classification is advisory provenance, not an admission capability.
        // Even a forged same-chain manifest cannot enable replay or Auto here.
        for entry in &archive.manifest.import_omissions {
            let id = parse_id(&entry.entity_id)?;
            archive.index.put(Tag::Omitted, id.as_bytes(), &[])?;
        }
        // Run result bodies are staged once the transaction is open, each as
        // its first occurrence goes in; only a body the export did not
        // withhold comes back: the same bytes attached for an ASSET (OF-222)
        // bring back no withheld result.
        let mut bodies = archive.spool.rows(ArchiveRecordKind::ResultBody);
        while let Some((_, body)) = bodies.next_parsed::<ExportResultBody>(&archive.spool)? {
            if body.withheld.is_none() {
                archive
                    .index
                    .put(Tag::Released, body.blake3.as_bytes(), &[])?;
            }
        }
        // The custody values a result body's sweep replaces, and the body
        // instances it spills into, read and minted before the writer opens.
        let known = super::result_reserve::staged_result_sinks(self, &archive)?;
        // FIX 3677: every body file stays pinned until the import commits or
        // aborts, so the collector takes none a row here is compared with or
        // staged into. The File ASSETs' instances are minted now, as the
        // results' are; the values custody holds are read in the writer.
        let _bodies = self.pin_all_result_bodies();
        let mint = super::asset_reserve::reserved_asset_mint(self, &archive)?;
        let mut wtxn = self.store.env.write_txn()?;
        let assets = super::asset_reserve::ArchiveAssets {
            mint,
            known: self.asset_stream_known_in_txn(&mut wtxn)?,
        };
        if let Some(actor) = actor {
            super::expression_import::validate_local_actor(self, &wtxn, actor)?;
        }
        withhold_unborn_projects(self, &wtxn, &mut archive)?;
        let projects = map_project_root(self, &wtxn, &mut archive)?;
        omit_project_revisions(self, &mut archive)?;
        // Each runtime pack row maps onto this vault's pack handles; the
        // mapping is read again, alike, as each row goes in.
        let mut after = None;
        while let Some((id, at)) = archive.next_entity(after.as_ref())? {
            if at.section == Section::Ledger && at.has(FLAG_PACK_BODY) {
                imported_row(self, &wtxn, &archive, &at, None)?;
            }
            after = Some(id);
        }
        let model_imports =
            super::provenance_import::restore_models(self, &mut wtxn, &mut archive)?;
        super::provenance_import::index_mapped_edges(&mut archive)?;
        super::provenance_import::index_provenance(&mut archive)?;
        super::expression_import::index_expressions(&mut archive)?;
        let mut pending = 0;
        let mut unchanged_entities = model_imports.unchanged;
        let mut after = None;
        while let Some((id, at)) = archive.next_entity(after.as_ref())? {
            after = Some(id);
            if archive.index.contains(Tag::Omitted, id.as_bytes())?
                || archive.index.contains(Tag::Model, id.as_bytes())?
                || at.has(FLAG_PROVENANCE)
                || at.has(FLAG_EXPRESSION)
            {
                continue;
            }
            if self.store.off_record_sessions.contains_entity(&id)? {
                return Err(invalid("import ID belongs to an off-record overlay"));
            }
            let row = imported_row(self, &wtxn, &archive, &at, projects.as_ref())?;
            let existing = match &row.body {
                // OF-222, FIX 3677: a file body meets no lossy form and no
                // copy of the row stored under its id.
                ExportBody::File(file) => {
                    if file_row_stored(self, &wtxn, &id, &row, file, &archive.files)? {
                        validate_existing_source(self, &wtxn, &row, &archive, &at)?;
                        unchanged_entities += 1;
                        continue;
                    }
                    None
                }
                _ => crate::ports::EntityStoreRead::port_entity_raw(&self.store, &wtxn, &id)?,
            };
            if let Some(existing) = existing {
                if !live_entity_row_in_txn(&self.store, &wtxn, &id)?.is_live() {
                    return Err(invalid("import ID collides with a deleted entity"));
                }
                // A file-plane ASSET compares as its body, never the manifest
                // its row keeps (FIX 3677).
                let existing = self.materialized_row_in_txn(&wtxn, &id, existing)?;
                if matches_row(&row, &existing, &row.body) {
                    validate_existing_source(self, &wtxn, &row, &archive, &at)?;
                    unchanged_entities += 1;
                    continue;
                }
                let body = imported_body(&row, &archive.index, &archive.files)?;
                if matches_row(
                    &row,
                    &existing,
                    &ExportBody::from_bytes(&body, row.entity_type),
                ) {
                    validate_existing_source(self, &wtxn, &row, &archive, &at)?;
                    unchanged_entities += 1;
                    continue;
                }
                return Err(invalid("import ID collides with different entity data"));
            }
            self.store.validate_public_entity_type(row.entity_type)?;
            // Only the row's id and what it waits on stay pending, in the
            // row index (FIX 2766, 3678): its body is built again when it
            // goes in, and a file body, which waits on nothing, is read from
            // the archive only then.
            let waits_on = if matches!(row.body, ExportBody::File(_)) {
                Vec::new()
            } else {
                dependencies(
                    row.entity_type,
                    &imported_body(&row, &archive.index, &archive.files)?,
                )?
            };
            archive
                .index
                .put(Tag::Pending, id.as_bytes(), &id_list(&waits_on))?;
            archive.index.put(Tag::Waiting, id.as_bytes(), &[])?;
            archive.index.put(Tag::Inserted, id.as_bytes(), &[])?;
            pending += 1;
        }
        let mut inserted_entities = pending + model_imports.inserted;
        // Resolve reference dependencies without assuming UUID or export order.
        // A cycle or an unavailable subject fails without a partial commit.
        // Each round queues what waits on no pending id, then restores it.
        while archive.index.any(Tag::Waiting, &[])? {
            let mut ready = super::provenance_import::mark_ready(&mut archive)?;
            ready |= super::expression_import::mark_ready(&mut archive)?;
            ready |= mark_ready_rows(&mut archive)?;
            if !ready {
                return Err(invalid("cyclic import subject or fork dependencies"));
            }
            while let Some((key, _)) = archive.index.next(Tag::Ready, &[], None)? {
                archive.index.remove(Tag::Ready, &key)?;
                let id = id_at(&key, 1)?;
                let (inserted, unchanged) = match key[0] {
                    QUEUE_PROVENANCE => {
                        let (inserted, unchanged) =
                            super::provenance_import::restore(id, self, &mut wtxn, &mut archive)?;
                        (inserted.into_iter().collect::<Vec<_>>(), unchanged)
                    }
                    QUEUE_EXPRESSION => {
                        let actor = actor.ok_or_else(actor_required)?;
                        super::expression_import::restore(id, self, &mut wtxn, actor, &mut archive)?
                    }
                    _ => {
                        let projects = projects.as_ref();
                        insert_ready_row(self, &mut wtxn, &mut archive, id, projects, &assets)?;
                        (Vec::new(), 0)
                    }
                };
                inserted_entities += inserted.len();
                unchanged_entities += unchanged;
                for id in inserted {
                    archive.index.put(Tag::Inserted, id.as_bytes(), &[])?;
                }
            }
        }
        let mut agents = archive.spool.rows(ArchiveRecordKind::AgentPack);
        while let Some((_, bundle)) = agents.next_parsed::<AgentForkBinding>(&archive.spool)? {
            let id = parse_id(&bundle.entity_id)?;
            if archive.index.contains(Tag::Inserted, id.as_bytes())? {
                crate::agent_def::import_agent_fork_hash_in_txn(
                    &self.store,
                    &mut wtxn,
                    &id,
                    bundle.fork_hash.as_deref(),
                )?;
            }
        }
        // FIX 5972: an archived `regenerates` link is proven on its
        // MESSAGEs' restored axes, so it lands after every other edge. One
        // its restored pair does not prove stays out, counted (FIX 6206).
        let mut skipped_unproven_regenerates_edges = 0;
        for regenerates in [false, true] {
            let mut edges = archive.spool.rows(ArchiveRecordKind::Edge);
            while let Some((_, edge)) = edges.next_parsed::<ExportEdge>(&archive.spool)? {
                if (edge.kind == EdgeKind::Regenerates as u8) != regenerates {
                    continue;
                }
                let edge = super::provenance_import::mapped_edge(&edge, &archive.index)?;
                if archive
                    .index
                    .contains(Tag::Omitted, parse_id(&edge.source)?.as_bytes())?
                    || archive
                        .index
                        .contains(Tag::Omitted, parse_id(&edge.target)?.as_bytes())?
                {
                    continue;
                }
                let landed = import_edge(self, &mut wtxn, &edge, &archive.index)?;
                if landed == EdgeImport::UnprovenRegenerates {
                    skipped_unproven_regenerates_edges += 1;
                }
            }
        }
        let mut archived_receipt_sources = 0;
        let mut envelopes = archive.spool.rows(ArchiveRecordKind::DerivationEnvelope);
        while let Some((_, envelope)) =
            envelopes.next_parsed::<ExportDerivationEnvelope>(&archive.spool)?
        {
            let holder = parse_id(&envelope.id)?;
            if !archive.index.contains(Tag::Omitted, holder.as_bytes())? {
                archived_receipt_sources += self.restore_claim_receipt_sources_in_txn(
                    &mut wtxn,
                    &holder,
                    &envelope.receipts,
                )?;
            }
        }
        // FIX 2768: the side tables come back once the records and carriers
        // they index are in: each family's records, then indexes, then heads.
        let (restored_side_rows, unchanged_side_rows) =
            super::archive_side_tables::restore_side_rows_in_txn(&self.store, &mut wtxn, &archive)?;
        let (imported_results, withheld_results) =
            put_run_results_in_txn(self, &mut wtxn, &mut archive, known)?;
        let (restored_secrets, unchanged_secrets, skipped_revoked_secrets, missing_secrets) =
            restore_secrets_in_txn(self, &mut wtxn, &mut archive)?;
        // OF-013: each session's floor rises to the archive's and never falls,
        // so numbering here never goes back under an epoch a purge removed.
        let mut floors = archive.spool.rows(ArchiveRecordKind::EpochFloor);
        while let Some((_, floor)) = floors.next_parsed::<ExportEpochFloor>(&archive.spool)? {
            crate::compaction::raise_session_epoch_floor_in_txn(
                &self.store,
                &mut wtxn,
                &parse_id(&floor.session)?,
                floor.epoch,
                floor.turn_end,
            )?;
        }
        // OF-370: the embedding setup declares and binds only what is absent
        // here; its vectors are recomputed after the commit, never before.
        let embedding_setup =
            super::import_embedding_setup_in_txn(&self.store, &mut wtxn, &archive)?;
        let setup_rows = self.publish_embedding_setup_in_txn(&mut wtxn)?;
        wtxn.commit()?;
        self.embedding_setup_committed(setup_rows);
        let mut remapped_entities = BTreeMap::new();
        for entry in archive.index.entries(Tag::Model)? {
            let (archived, local) = entry?;
            if archived != local {
                remapped_entities.insert(id_at(archived, 0)?.to_hex(), id_at(local, 0)?.to_hex());
            }
        }
        Ok(WholeVaultImportReceipt {
            authority,
            inserted_entities,
            unchanged_entities,
            archived_receipt_sources,
            omitted_entities: archive.index.count(Tag::Omitted)?,
            remapped_entities,
            imported_results,
            withheld_results,
            restored_secrets,
            unchanged_secrets,
            skipped_revoked_secrets,
            skipped_unproven_regenerates_edges,
            missing_secrets,
            embedding_setup,
            restored_side_rows,
            unchanged_side_rows,
        })
    }
}

/// An agent bundle row's id and fork hash.
#[derive(Deserialize)]
struct AgentForkBinding {
    entity_id: String,
    #[serde(rename = "forkHash")]
    fork_hash: Option<String>,
}

/// Queues each pending row none of whose references is pending; whether any.
fn mark_ready_rows<R: Read + Seek>(archive: &mut IndexedArchive<'_, R>) -> Result<bool> {
    let mut any = false;
    let mut at: Option<Vec<u8>> = None;
    while let Some((id, waits)) = archive.index.next(Tag::Pending, &[], at.as_deref())? {
        let mut blocked = false;
        for reference in ids_of(&waits)? {
            blocked |= archive.index.contains(Tag::Waiting, reference.as_bytes())?;
        }
        if !blocked {
            archive
                .index
                .put(Tag::Ready, &ready_key(QUEUE_ROW, &id_at(&id, 0)?), &[])?;
            any = true;
        }
        at = Some(id);
    }
    Ok(any)
}

/// Writes one pending row whose references are in, through its type's door.
fn insert_ready_row<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
    id: EntityId,
    projects: Option<&ProjectRootMap>,
    assets: &super::asset_reserve::ArchiveAssets,
) -> Result<()> {
    if !archive.index.remove(Tag::Pending, id.as_bytes())? {
        return Err(Error::InvariantViolation("import queue lost row"));
    }
    archive.index.remove(Tag::Waiting, id.as_bytes())?;
    let at = archive
        .entity_at(&id)?
        .ok_or(Error::InvariantViolation("import queue lost row"))?;
    let row = imported_row(vault, wtxn, archive, &at, projects)?;
    let occurred = TimeRange {
        start: row.occurred_start,
        end: row.occurred_end,
    };
    // OF-222, FIX 3677: an ASSET's file body streams from the archive into
    // the ASSET stager, checked to its end, and its put takes the batch door
    // every ASSET put takes, in this writer: a body the stager publishes as
    // a file goes as its manifest, any other as its bytes, as a slice put
    // holds them.
    if let ExportBody::File(file) = &row.body {
        let mut staged = None;
        file.with_reader(&archive.files, &mut |body| {
            let known = assets.known.clone();
            staged = Some(vault.stage_asset_body(body, None, known, assets.mint.as_ref())?);
            Ok(())
        })?;
        let staged = staged.ok_or(Error::InvariantViolation("archive file body not staged"))?;
        return vault.put_asset_body_in_txn(wtxn, &id, occurred, row.learned_at, &staged);
    }
    let body = imported_body(&row, &archive.index, &archive.files)?;
    match row.entity_type {
        ENTITY_TYPE_CLAIM => {
            let claim = decode_import_claim(&body)?;
            if crate::subject_model::is_subject_model_predicate(&claim.predicate) {
                vault.restore_subject_claim_in_txn(wtxn, &id, &claim, occurred, row.learned_at)
            } else if crate::actor_claims::is_actor_claim_predicate(&claim.predicate) {
                vault.restore_actor_projection_in_txn(wtxn, &id, &claim, occurred, row.learned_at)
            } else if claim.predicate == crate::skill_reliability::PREDICATE_SKILL_RELIABILITY {
                vault.restore_reliability_claim_in_txn(wtxn, &id, &claim, occurred, row.learned_at)
            } else if claim.predicate == crate::claim::PREDICATE_SKILL_EDIT_COST {
                vault.restore_skill_cost_in_txn(wtxn, &id, &claim, occurred, row.learned_at)
            } else {
                vault.put_claim_in_txn(wtxn, &id, &claim, occurred, row.learned_at)
            }
        }
        ENTITY_TYPE_SKILL => {
            let record = crate::skill::decode_skill_record(&body)?;
            if at.section != Section::Skill {
                return Err(Error::InvariantViolation("skill bundle missing"));
            }
            let bundle: ExportSkillBundle = archive.hydrated(ArchiveRecordKind::Skill, at.loc)?;
            if let Some(tree) = &bundle.source_tree {
                vault.import_archived_skill_in_txn(
                    wtxn,
                    &id,
                    &record,
                    (
                        bundle
                            .source_format
                            .ok_or_else(|| invalid("skill source format missing"))?,
                        tree.import_files()?,
                    ),
                    occurred,
                    row.learned_at,
                )
            } else {
                vault.put_skill_record_in_txn(wtxn, &id, &record, occurred, row.learned_at)
            }
        }
        _ => vault
            .batch_in()
            .put(&id, row.entity_type, occurred, row.learned_at, &body)
            .apply(wtxn),
    }
}

/// The source root this vault maps onto its own root project (see
/// [`map_project_root`]): the project type, and both roots' ids.
struct ProjectRootMap {
    kind: u8,
    source: String,
    target: String,
}

/// The row `at` as the import writes it: a project row's parent moves from
/// the source root to this vault's root, and a runtime pack row is mapped
/// onto this vault's pack handle for its kind.
fn imported_row<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    at: &EntityAt,
    projects: Option<&ProjectRootMap>,
) -> Result<ExportEntity> {
    let mut row = archive.entity_row(at)?;
    if let Some(projects) = projects
        && at.section == Section::Ledger
        && row.entity_type == projects.kind
    {
        let mut body: crate::workspace_roster::ProjectRecord =
            rmp_serde::from_slice(&row.body.to_bytes()?)
                .map_err(|_| invalid("project row body"))?;
        // Only the tree position moves; the claims scope id stays a label.
        for parent in &mut body.parents {
            if *parent == projects.source {
                parent.clone_from(&projects.target);
            }
        }
        let bytes = rmp_serde::to_vec_named(&body).map_err(|_| invalid("project row body"))?;
        row.body = ExportBody::from_bytes(&bytes, row.entity_type);
    }
    if at.section == Section::Ledger
        && let ExportBody::Pack(value) = &row.body
    {
        let (handle, envelope) = vault
            .store
            .remap_pack_instance_in_txn(txn, &value.envelope()?)?;
        row.entity_type = handle;
        row.body = ExportBody::from_bytes(&envelope.to_bytes()?, handle);
    }
    Ok(row)
}

/// Writes each run's results whose bodies came back as that run's
/// occurrences; a result the export withheld stays a manifest in the
/// archive. Returns the counts of both. Each body is staged from the archive
/// as its occurrence goes in, checked against its digest and length, so the
/// manifests and line indexes are rebuilt from the bytes; the secret scan
/// reads them again as they go in. No body is held between two occurrences
/// (FIX 3678): a later occurrence of the same bytes stages them again.
fn put_run_results_in_txn<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
    known: crate::code_run::StagedSinks,
) -> Result<(usize, usize)> {
    let (mut imported, mut withheld) = (0, 0);
    // The values custody knows, read in this writer and kept no longer
    // (KS-3): each body's sweep replaces them with their handles.
    let swept = crate::secret_custody::KnownValues::load_in_writer(&vault.store, wtxn)?
        .map(std::sync::Arc::new);
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        let run_id = parse_id(&run.run_id)?;
        for output in &run.outputs {
            let Some(blake3) = &output.blake3 else {
                withheld += 1;
                continue;
            };
            let digest = parse_digest(blake3)?;
            let Some(listed) = archive.files.file_len(blake3) else {
                withheld += 1;
                continue;
            };
            if !archive.index.contains(Tag::Released, blake3.as_bytes())? {
                withheld += 1;
                continue;
            }
            // Only a body's first occurrence is held to its manifest's length.
            if archive.index.insert(Tag::Staged, &digest, &[])? && listed != output.bytes {
                return Err(invalid("run result body does not match its digest"));
            }
            // Masked at write as a run's reply body is (FIX 5718 part 3).
            let may_spill = swept.is_some() || listed > vault.code_result_inline_bytes();
            let body = archive.files.read_file(blake3)?;
            let body = vault.admit_imported_result_in_txn(
                wtxn,
                run_id,
                &output.path,
                body,
                swept.as_ref(),
                may_spill,
            )?;
            let finished = vault.stage_code_run_output_from(
                output.path.clone(),
                vault.code_run_output_sink_knowing(known.clone(), swept.clone())?,
                std::io::Cursor::new(body),
            )?;
            let occurrence = finished.at(output.path.clone(), output.complete)?;
            vault.put_code_run_output_in_txn(wtxn, &finished, &occurrence, Some(run_id))?;
            imported += 1;
        }
    }
    // A receipt comes back with the occurrence it describes, and only whole:
    // a withheld one's refs stay in the archive. Every run's outputs are in
    // first, so a ref to another run's output resolves; one that resolves to
    // nothing (not in the archive, nor in this vault) is named unresolved.
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        let run_id = parse_id(&run.run_id)?;
        for fold in run.receipts.iter().filter(|fold| fold.withheld.is_none()) {
            let mut came_back = false;
            for output in run.outputs.iter().filter(|output| output.path == fold.path) {
                if let Some(digest) = output
                    .blake3
                    .as_deref()
                    .and_then(|blake3| parse_digest(blake3).ok())
                {
                    came_back |= archive.index.contains(Tag::Staged, &digest)?;
                }
            }
            if !came_back {
                continue;
            }
            let mut receipt: crate::code_run::ReaderFoldReceipt =
                serde_json::from_value(fold.receipt.clone())
                    .map_err(|_| invalid("run fold receipt"))?;
            if receipt.folded.owner != run_id || receipt.folded.path != fold.path {
                return Err(invalid("run fold receipt names another occurrence"));
            }
            let rtxn: &heed::RoTxn<'_> = wtxn;
            receipt.mark_unresolved(|named| {
                Ok(crate::provenance::body::owned_body_in_txn(
                    &vault.store,
                    rtxn,
                    &named.owner,
                    &named.occurrence,
                )?
                .is_some())
            })?;
            vault.put_code_run_reader_fold_in_txn(wtxn, &receipt)?;
        }
    }
    Ok((imported, withheld))
}

fn parse_digest(text: &str) -> Result<[u8; 32]> {
    let mut digest = [0; 32];
    if text.len() != 64 {
        return Err(invalid("run result digest"));
    }
    for (byte, pair) in digest.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = std::str::from_utf8(pair)
            .ok()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(|| invalid("run result digest"))?;
    }
    Ok(digest)
}

/// The owner's own archive's custody records, each restored under its own id
/// through the custody registration door, in the import's transaction. A
/// record already here byte for byte is unchanged; any other collision is
/// refused, never overwritten. A record the archive carried as its handle
/// only is returned as a missing secret to re-enter; one an admitted revoke
/// ended is counted as skipped (FIX 4852).
fn restore_secrets_in_txn<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<(
    usize,
    usize,
    usize,
    Vec<crate::secret_custody::SecretCustodyMetadata>,
)> {
    use base64::Engine as _;
    let (mut restored, mut unchanged, mut skipped, mut missing) = (0, 0, 0, Vec::new());
    let mut secrets = archive.spool.rows(ArchiveRecordKind::SecretCustody);
    while let Some((_, secret)) =
        secrets.next_parsed::<super::ArchiveSecretCustody>(&archive.spool)?
    {
        let id = parse_id(&secret.id)?;
        if !archive.index.insert(Tag::Secret, id.as_bytes(), &[])?
            || archive.index.contains(Tag::Entity, id.as_bytes())?
        {
            return Err(invalid("archive custody record id appears twice"));
        }
        if secret.metadata.name != secret.name {
            return Err(invalid(
                "archive custody record name disagrees with its metadata",
            ));
        }
        let Some(body) = &secret.body else {
            missing.push(secret.metadata.clone());
            continue;
        };
        let body = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| invalid("invalid archive custody record body"))?;
        let mut record = crate::secret_custody::decode_secret_custody_body(&body)?;
        if record.metadata() != secret.metadata {
            return Err(invalid("archive custody record disagrees with its body"));
        }
        if let Some(existing) =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, wtxn, &id)?
        {
            if existing.get(ENTITY_METADATA_HEADER_LEN..) == Some(body.as_slice())
                && EntityMetadataHeader::parse(&existing).is_some_and(|header| {
                    header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                })
            {
                unchanged += 1;
                continue;
            }
            return Err(invalid(
                "import ID collides with a different custody record",
            ));
        }
        if crate::secret_custody::restore_secret_custody_in_txn(vault, wtxn, &id, &mut record)? {
            restored += 1;
        } else {
            skipped += 1;
        }
    }
    Ok((restored, unchanged, skipped, missing))
}

fn validate_existing_source<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &ExportEntity,
    archive: &IndexedArchive<'_, R>,
    at: &EntityAt,
) -> Result<()> {
    if at.section != Section::Skill {
        return Ok(());
    }
    let bundle: ExportSkillBundle = archive.hydrated(ArchiveRecordKind::Skill, at.loc)?;
    if let Some(tree) = &bundle.source_tree {
        let files = tree.import_files()?;
        let stored = vault
            .export_hub_package_in_txn(txn, &parse_id(&row.id)?)?
            .ok_or_else(|| invalid("existing skill has no matching stored source package"))?;
        if stored.export_files()? != files || Some(stored.format) != bundle.source_format {
            return Err(invalid(
                "existing skill source package differs from archive",
            ));
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}

fn actor_required() -> Error {
    invalid("expression preferences require a host-authenticated local WriteActor")
}

/// An archived PROJECT row, which the archive marks as needing its owning
/// adapter, goes through the generic door only where this vault derives its
/// depth birth. Elsewhere, as in an owner-rooted vault that never knew it, the
/// row and its home room are withheld instead of stranding the import.
fn withhold_unborn_projects<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<()> {
    let Ok(project_kind) = vault.project_type_byte() else {
        return Ok(());
    };
    // One per refusal the manifest lists: no more than it holds.
    let mut withheld = BTreeSet::new();
    for refusal in &archive.manifest.import_refusals {
        let super::ExportImportRefusal::Entity {
            entity_id,
            reason: super::ImportRefusalReason::OwningEntityAdapterRequired,
        } = refusal
        else {
            continue;
        };
        let id = parse_id(entity_id)?;
        if archive
            .index
            .get(Tag::Entity, id.as_bytes())?
            .map(|at| EntityAt::decode(&at))
            .transpose()?
            .is_some_and(|at| at.entity_type == project_kind)
            && crate::gate::project_depth::birth_for_project(&vault.store, txn, id)?.is_none()
            && !crate::gate::project_depth::implicit_birth_applies(
                &vault.store,
                txn,
                vault.privacy_posture(),
                id,
            )?
        {
            withheld.insert(id.to_hex());
            archive.index.put(Tag::Omitted, id.as_bytes(), &[])?;
        }
    }
    let mut after = None;
    while let Some(id) = archive.next_of_type(ENTITY_TYPE_CONVERSATION, after.as_ref())? {
        after = Some(id);
        let (_, row) = archive
            .entity(&id)?
            .ok_or(Error::InvariantViolation("archive index lost a room"))?;
        if let Ok(room) =
            rmp_serde::from_slice::<crate::workspace_roster::ProjectRoom>(&row.body.to_bytes()?)
            && withheld.contains(&room.project_id)
        {
            archive.index.put(Tag::Omitted, id.as_bytes(), &[])?;
        }
    }
    Ok(())
}

/// This vault is its own root project: the source root maps onto it instead
/// of landing as a second parentless root. A signed project's slip authority
/// lives in the source vault's log, which never becomes local rights here,
/// so signed rows and their descendants stay archive data in the archive.
/// The project tree's shape (signature, home room and parents, no text) is
/// kept in the row index; the parent move itself is made as each project row
/// goes in ([`imported_row`]).
fn map_project_root<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<Option<ProjectRootMap>> {
    let Ok(kind) = vault.project_type_byte() else {
        return Ok(None);
    };
    let Some(target) = crate::workspace_roster::root_project_in(&vault.store, txn)? else {
        return Ok(None);
    };
    let mut source = None;
    let mut after = None;
    while let Some(id) = archive.next_of_type(kind, after.as_ref())? {
        after = Some(id);
        let Some((at, row)) = archive.entity(&id)? else {
            continue;
        };
        if at.section != Section::Ledger || archive.index.contains(Tag::Omitted, id.as_bytes())? {
            continue;
        }
        let body: crate::workspace_roster::ProjectRecord =
            rmp_serde::from_slice(&row.body.to_bytes()?)
                .map_err(|_| invalid("project row body"))?;
        if source.is_none() && body.parents.is_empty() {
            source = Some(id);
        }
        let home = body.home_room.as_bytes();
        let mut shape = vec![u8::from(body.write_proof.is_some())];
        shape.extend_from_slice(&(home.len() as u64).to_be_bytes());
        shape.extend_from_slice(home);
        // A parent that is no id never names an archived project.
        for parent in &body.parents {
            if let Ok(parent) = parse_id(parent) {
                shape.extend_from_slice(parent.as_bytes());
            }
        }
        archive.index.put(Tag::Project, id.as_bytes(), &shape)?;
    }
    let Some(source) = source else {
        return Ok(None);
    };
    if source == target {
        return Ok(None);
    }
    archive
        .index
        .put(Tag::ProjectArchived, source.as_bytes(), &[])?;
    let mut after: Option<Vec<u8>> = None;
    while let Some((id, shape)) = archive.index.next(Tag::Project, &[], after.as_deref())? {
        if project_shape(&shape)?.0 {
            archive.index.put(Tag::ProjectArchived, &id, &[])?;
        }
        after = Some(id);
    }
    // Descendants of a signed row keep it as their parent: archive them too.
    let mut grew = true;
    while grew {
        grew = false;
        let mut after: Option<Vec<u8>> = None;
        while let Some((id, shape)) = archive.index.next(Tag::Project, &[], after.as_deref())? {
            if !archive.index.contains(Tag::ProjectArchived, &id)? {
                let mut archived_parent = false;
                for parent in project_shape(&shape)?.2 {
                    archived_parent |= parent != source
                        && archive
                            .index
                            .contains(Tag::ProjectArchived, parent.as_bytes())?;
                }
                if archived_parent {
                    archive.index.put(Tag::ProjectArchived, &id, &[])?;
                    grew = true;
                }
            }
            after = Some(id);
        }
    }
    let mut after: Option<Vec<u8>> = None;
    while let Some((id, shape)) = archive.index.next(Tag::Project, &[], after.as_deref())? {
        if archive.index.contains(Tag::ProjectArchived, &id)? {
            archive.index.put(Tag::Omitted, &id, &[])?;
            let home = parse_id(&project_shape(&shape)?.1)?;
            archive.index.put(Tag::Omitted, home.as_bytes(), &[])?;
        }
        after = Some(id);
    }
    Ok(Some(ProjectRootMap {
        kind,
        source: source.to_hex(),
        target: target.to_hex(),
    }))
}

/// A project's shape as [`map_project_root`] keeps it: whether it is signed,
/// its home room and its parents.
fn project_shape(shape: &[u8]) -> Result<(bool, String, Vec<EntityId>)> {
    let corrupt = || Error::InvariantViolation("archive index project shape");
    let (signed, rest) = shape.split_first().ok_or_else(corrupt)?;
    let len = rest
        .get(..8)
        .and_then(|len| <[u8; 8]>::try_from(len).ok())
        .map(u64::from_be_bytes)
        .and_then(|len| usize::try_from(len).ok())
        .ok_or_else(corrupt)?;
    let home = rest.get(8..8 + len).ok_or_else(corrupt)?;
    let home = String::from_utf8(home.to_vec()).map_err(|_| corrupt())?;
    let parents = ids_of(rest.get(8 + len..).ok_or_else(corrupt)?)?;
    Ok((*signed != 0, home, parents))
}

/// Signed project history is archive data: its slips name the source vault's
/// authority, so its revisions stay in the archive beside the signed rows.
fn omit_project_revisions<R: Read + Seek>(
    vault: &Vault,
    archive: &mut IndexedArchive<'_, R>,
) -> Result<()> {
    let Some(kind) = crate::workspace_roster::project_revision_type(&vault.store) else {
        return Ok(());
    };
    let mut after = None;
    while let Some(id) = archive.next_of_type(kind, after.as_ref())? {
        archive.index.put(Tag::Omitted, id.as_bytes(), &[])?;
        after = Some(id);
    }
    Ok(())
}

pub(super) fn parse_id(text: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(text)?;
    if id.to_hex() != text {
        return Err(invalid("entity ID must be lowercase hex"));
    }
    Ok(id)
}

pub(super) fn matches_row(row: &ExportEntity, raw: &[u8], expected: &ExportBody) -> bool {
    matches_header(row, raw)
        && ExportBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..], row.entity_type) == *expected
}

/// Whether the row this vault stores under `id` is the archived `row`, whose
/// body is the archive file `file` (OF-222, FIX 3677): `false` when it
/// stores none. A file body matches only the very bytes it names, read a
/// chunk at a time from the archive and from the stored row where it lies
/// (a file-plane ASSET's stored file read and checked as it streams), never
/// copied; any other stored row under its id, a deleted one included, is a
/// collision, never read through a lossy form.
fn file_row_stored(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: &ExportEntity,
    file: &ExportBodyFile,
    files: &dyn ArchiveFiles,
) -> Result<bool> {
    let store = &vault.store;
    let stored = crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, id, |raw| {
        // `live_entity_row_in_txn`'s verdict, without its copy of the body.
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, id)?;
        if state.deleted || state.stale {
            return Err(invalid("import ID collides with a deleted entity"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let manifest = match header.entity_type {
            ENTITY_TYPE_ASSET => crate::store::asset_file_in_txn(store, txn, id, body)?,
            _ => None,
        };
        let len = manifest.as_ref().map_or(body.len() as u64, |manifest| manifest.facts.len);
        let mut same = false;
        if matches_header(row, raw) && len == file.bytes() {
            file.with_reader(files, &mut |archived| {
                same = match &manifest {
                    None => same_bytes(&mut &*body, archived)?,
                    Some(manifest) => {
                        let read = |stored: &mut dyn Read| same_bytes(stored, archived);
                        vault.with_admitted_asset_file_in_txn(txn, manifest, read)?
                    }
                };
                Ok(())
            })?;
        }
        if !same {
            return Err(invalid("import ID collides with different entity data"));
        }
        Ok(())
    })?;
    Ok(stored.is_some())
}

/// Whether `ours` and `theirs` read as the same bytes, a chunk at a time;
/// `false` at their first difference.
fn same_bytes(ours: &mut dyn Read, theirs: &mut dyn Read) -> Result<bool> {
    let (mut mine, mut other) = (vec![0_u8; 64 * 1024], vec![0_u8; 64 * 1024]);
    loop {
        let read = fill(ours, &mut mine)?;
        if read == 0 {
            return Ok(fill(theirs, &mut other[..1])? == 0);
        }
        if fill(theirs, &mut other[..read])? != read || mine[..read] != other[..read] {
            return Ok(false);
        }
    }
}

/// Reads into `buf` until it is full or `read` ends; how much it read.
fn fill(read: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut at = 0;
    while at < buf.len() {
        match read.read(&mut buf[at..]) {
            Ok(0) => break,
            Ok(count) => at += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(at)
}

/// The stored row's type and times are the archived row's.
fn matches_header(row: &ExportEntity, raw: &[u8]) -> bool {
    EntityMetadataHeader::parse(raw).is_some_and(|header| {
        header.entity_type == row.entity_type
            && header.occurred_start == row.occurred_start
            && header.occurred_end == row.occurred_end
            && header.learned_at == row.learned_at
    })
}

/// The body the import writes; an ASSET's file body is its archive file's
/// bytes, as they were stored (OF-222). A claim's subject is mapped onto this
/// vault's MODEL rows through the row index.
fn imported_body(
    row: &ExportEntity,
    index: &ArchiveIndex<'_>,
    files: &dyn ArchiveFiles,
) -> Result<Vec<u8>> {
    let bytes = row.body.to_bytes_in(files)?;
    let mapped = |id: EntityId| super::provenance_import::mapped(index, id);
    match row.entity_type {
        ENTITY_TYPE_CLAIM => {
            let mut body = decode_import_claim(&bytes)?;
            match &mut body.subject {
                ClaimSubject::Entity(id) => *id = mapped(*id)?,
                ClaimSubject::Edge { source, target, .. } => {
                    *source = mapped(*source)?;
                    *target = mapped(*target)?;
                }
            }
            body.source = Some(ClaimSource::Imported);
            if body.approval != ClaimApprovalStatus::Rejected {
                body.approval = ClaimApprovalStatus::Proposed;
            }
            encode_claim_body(&body)
        }
        ENTITY_TYPE_SKILL => {
            let mut body = crate::skill::decode_skill_record(&bytes)?;
            body.source = ClaimSource::Imported;
            body.generated = false;
            body.human_authored = true;
            body.approval_status = ClaimApprovalStatus::Proposed;
            body.lifecycle_status = crate::skill::SkillLifecycle::Candidate;
            crate::skill::encode_skill_record(&body)
        }
        ENTITY_TYPE_AGENT_DEF => {
            let mut body = crate::agent_def::decode_agent_definition(&bytes)?;
            body.source = ClaimSource::Imported;
            body.generated = false;
            body.human_authored = true;
            body.approval_status = ClaimApprovalStatus::Proposed;
            body.enabled = false;
            body.ceiling = crate::agent_def::AgentCeiling::Proposed;
            crate::agent_def::encode_agent_definition(&body)
        }
        _ => Ok(bytes),
    }
}

fn dependencies(entity_type: u8, bytes: &[u8]) -> Result<Vec<EntityId>> {
    Ok(match entity_type {
        ENTITY_TYPE_CLAIM => {
            let body = decode_import_claim(bytes)?;
            let mut refs = match body.subject {
                ClaimSubject::Entity(id) => vec![id],
                ClaimSubject::Edge { source, target, .. } => vec![source, target],
            };
            if crate::actor_claims::is_actor_claim_predicate(&body.predicate) {
                refs.extend(crate::actor_claims::imported_actor_dependencies(&body)?);
            }
            if body.predicate == crate::subject_model::PREDICATE_ACTOR_SUBJECT_REF {
                refs.push(crate::subject_model::validate_actor_subject_claim_structure(&body)?.1);
            }
            refs
        }
        ENTITY_TYPE_SKILL => crate::skill::decode_skill_record(bytes)?
            .forked_from
            .into_iter()
            .collect(),
        ENTITY_TYPE_AGENT_DEF => crate::agent_def::decode_agent_definition(bytes)?
            .forked_from
            .into_iter()
            .collect(),
        ENTITY_TYPE_CONVERSATION => crate::workspace_roster::project_room_dependency(bytes)
            .into_iter()
            .collect(),
        ENTITY_TYPE_WORKFLOW => {
            let definition = crate::agent_def::workflow::decode_workflow(bytes)?;
            definition
                .steps
                .into_iter()
                .chain(definition.forked_from)
                .collect()
        }
        _ => Vec::new(),
    })
}

/// What [`import_edge`] did with one archived edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EdgeImport {
    /// Written, or already here as the archive has it.
    Landed,
    /// An archived `regenerates` link its restored pair does not prove,
    /// left out (FIX 5972); the import's last edge pass counts it (FIX 6206).
    UnprovenRegenerates,
}

/// Writes one archived edge; `inserted` names the rows this import put in or
/// queued, whose own doors may have minted the edge already.
pub(super) fn import_edge(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    edge: &ExportEdge,
    inserted: &ArchiveIndex<'_>,
) -> Result<EdgeImport> {
    let source = parse_id(&edge.source)?;
    let target = parse_id(&edge.target)?;
    let kind = EdgeKind::try_from_u8(edge.kind).ok_or_else(|| invalid("unknown edge kind"))?;
    if let Some(existing) =
        crate::ports::EdgeStoreRead::port_edge_get(&vault.store, wtxn, &source, kind, &target)?
    {
        let same = existing.weight == edge.weight
            && existing.created_at == edge.created_at
            && existing.vad.map(|v| [v.valence, v.arousal, v.dominance]) == edge.vad
            && existing
                .provenance
                .map(|p| [p.confirmation_status as u8, p.actor_class as u8])
                == edge.provenance;
        if same {
            return Ok(EdgeImport::Landed);
        }
        // A newly imported claim's typed door creates its own ClaimOf link, and
        // a newly imported project's projector its damped parent membership.
        // Restoring this exported link's original timestamp is safe.
        let door_minted = inserted.contains(Tag::Inserted, source.as_bytes())?
            && match kind {
                EdgeKind::ClaimOf => true,
                EdgeKind::BelongsTo => {
                    existing.weight == edge.weight
                        && crate::workspace_roster::is_project_entity(&vault.store, wtxn, source)?
                        && crate::workspace_roster::is_project_entity(&vault.store, wtxn, target)?
                }
                _ => false,
            };
        if !door_minted {
            return Err(invalid(
                "import edge collides with different stored metadata",
            ));
        }
    }
    if edge.provenance.is_some() {
        return Err(invalid(
            "provenanced edge import requires its owning claim adapter",
        ));
    }
    let vad = edge
        .vad
        .map_or(crate::affect::Vad::NEUTRAL, |v| crate::affect::Vad {
            valence: v[0],
            arousal: v[1],
            dominance: v[2],
        });
    // The stream alone creates this kind (FIX 5972): an archived link comes
    // back through the internal write, with its own value fields, only once
    // its restored pair proves what the stream proved, and is left out
    // otherwise. A byte-equal stored link returned above.
    if kind == EdgeKind::Regenerates {
        if crate::edge::regeneration_pair(&vault.store, wtxn, &source, &target)?
            != crate::edge::Regeneration::Admits
        {
            return Ok(EdgeImport::UnprovenRegenerates);
        }
        vault
            .batch_in()
            .edge_with_value_fields(
                &source,
                kind,
                &target,
                crate::batch::EdgeValueFields {
                    weight: edge.weight,
                    created_at: edge.created_at,
                    vad,
                    provenance: None,
                },
            )
            .apply(wtxn)?;
        return Ok(EdgeImport::Landed);
    }
    vault
        .batch_in()
        .edge_with_created_at_and_vad(&source, kind, &target, edge.weight, edge.created_at, vad)
        .apply(wtxn)?;
    Ok(EdgeImport::Landed)
}

fn decode_import_claim(bytes: &[u8]) -> Result<crate::claim::ClaimBody> {
    let body = decode_claim_body(bytes, true)?;
    if crate::subject_model::is_subject_model_predicate(&body.predicate) {
        crate::subject_model::imported_subject_body(&body)
    } else if crate::actor_claims::is_actor_claim_predicate(&body.predicate) {
        crate::actor_claims::imported_actor_body(&body)
    } else if body.predicate == crate::skill_reliability::PREDICATE_SKILL_RELIABILITY {
        crate::skill_reliability::imported_reliability_body(&body)
    } else if body.predicate == crate::claim::PREDICATE_SKILL_EDIT_COST {
        crate::edit_distance::attribution::imported_skill_cost_body(&body)
    } else {
        decode_claim_body(bytes, false)
    }
}
