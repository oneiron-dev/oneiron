//! Snapshot enumeration for whole-vault export. No raw bytes leave this module
//! except as input to the serializer's mandatory credential-nulling transform,
//! and a stored file an archive carries as it is (OF-222). Each row goes to the
//! serializer as it is read (FIX 2766): the snapshot holds ids and indexes,
//! never the vault's bodies.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};

use super::snapshot_body::{asset_folded, row_body, row_live_in_txn};
use super::{
    ArchiveSecretCustody, ExportAdapterDescriptor, ExportCut, ExportDiaryLedger, ExportEdge,
    ExportManifest, ExportScope, ExportSecretsNulledManifest, ExportSnapshotEntityBody,
    WholeVaultExport, WholeVaultExportReceipt, carries_embedding_setup,
    whole_vault_export_excludes_entity,
};
use crate::Vault;
use crate::authority::{HolderExportNeed, HolderExportRequest};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::CallerLocality;
use crate::edge::{EdgeActorClass, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::serialize::{DocumentTail, DocumentWriter};
use crate::settings::ReadDestination;
use crate::write_envelope::WriteActor;

/// One run's result manifests, as its replay record names them, each with
/// why the egress door withholds the run's occurrence of it, if it does.
pub(crate) struct ExportSnapshotRun {
    pub(crate) run_id: EntityId,
    pub(crate) outputs: Vec<(crate::code_run::CodeRunRawOutput, Option<&'static str>)>,
    /// The run's fold receipts, each with why the egress door withholds the
    /// occurrence it describes, if it does.
    pub(crate) receipts: Vec<(crate::code_run::ReaderFoldReceipt, Option<&'static str>)>,
}

/// One result body a clean occurrence names: its bytes as they stream, read
/// under the snapshot and checked to their end (FIX 5392), or why they are
/// not exported.
pub(crate) struct ExportSnapshotBody<'t> {
    pub(crate) bytes: u64,
    pub(crate) body:
        std::result::Result<crate::code_run::CodeRunResultBodyReader<'t>, &'static str>,
}

/// One live row as the snapshot reads it, with what it carries beside it.
pub(crate) struct ExportSnapshotEntity<'t> {
    pub(crate) id: EntityId,
    pub(crate) short_ref: Option<String>,
    pub(crate) header: EntityMetadataHeader,
    pub(crate) body: ExportSnapshotEntityBody<'t>,
    pub(crate) tainted: bool,
    /// A SKILL's stored source package.
    pub(crate) skill_package: Option<crate::skill_hub::HubPackage>,
    /// The pack source an ASSET body is.
    pub(crate) pack_source: Option<crate::skill_hub::pack_catalog::PackSource>,
    /// The task receipts a CLAIM cites, by id.
    pub(crate) task_receipts: BTreeMap<String, crate::receipt::ReceiptRecord>,
    /// A CLAIM's archived receipt sources.
    pub(crate) archived_receipts: Option<BTreeMap<String, super::ExportReceiptSource>>,
}

impl Vault {
    /// Exports all live base entities and their graph as the whole-vault
    /// archive (OF-222), not a retrieval selection, in memory: for a door
    /// that answers in one frame. [`Self::export_whole_vault_to`] writes it
    /// to a file instead. Live off-record overlay rows, deleted shells,
    /// archive tombstones, credential custody rows and unpublished LFS chunks
    /// are excluded. No caller can disable nulling.
    ///
    /// The owner's own archive carries custody secret values unless
    /// `include_secrets` is false (owner ruling 2026-10-17: "all your data is
    /// all your data"); then each custody record goes as its handle only.
    ///
    /// Its diary reads are the vault owner's (OF-490).
    pub fn export_whole_vault(&self, include_secrets: bool) -> Result<WholeVaultExport> {
        self.export_in_memory(|vault, spool| vault.export_whole_vault_to(include_secrets, spool))
    }

    /// [`Self::export_whole_vault`] written to `sink` as it is built (FIX
    /// 2766): the rows are spooled under the vault's staging directory and
    /// copied into the ZIP one member and one file at a time, so a vault
    /// larger than memory exports. The copy is the owner's, in the vault's
    /// export audit, and each private thread it carries that he is not in is
    /// told of it (FIX 6427).
    pub fn export_whole_vault_to<W: Write + Seek>(
        &self,
        include_secrets: bool,
        sink: W,
    ) -> Result<WholeVaultExportReceipt> {
        let reader = owner_reader()?;
        let (_, mut receipt) = self.export_whole_vault_with_admission(
            CallerLocality::OnDevice,
            include_secrets,
            reader,
            |_| Ok::<_, Error>(()),
            sink,
        )?;
        let format = crate::memory::EXPORT_TARGET_ARCHIVE;
        crate::memory::record_raw_export(self, reader.entity_ref(), format, &mut receipt);
        Ok(receipt)
    }

    /// The archive of exactly `records` and the graph between them, for a
    /// reader off this device: an export-first removal's export (OF-163),
    /// in the same shape as a whole-vault archive and re-importable alike.
    /// No run's results go with it; a run names no world to scope it by.
    /// Each record's side rows and stored files go with it as they do in the
    /// whole-vault archive, never past `records`, and no vault-wide row does
    /// (FIX 3681). Its diary reads are `reader`'s, the owner who receives it.
    /// `freeze` reads in the archive's own snapshot, before its rows, so
    /// what it answers (the removal's frozen positions, FIX-LIST 8224) and
    /// the bytes archived are one state.
    pub(crate) fn export_records_archive<T>(
        &self,
        records: &BTreeSet<EntityId>,
        reader: WriteActor,
        freeze: impl FnOnce(&heed::RoTxn<'_>) -> Result<T>,
    ) -> Result<(WholeVaultExport, T)> {
        let mut frozen = None;
        let archive = self.export_in_memory(|vault, spool| {
            vault
                .export_archive_snapshot(
                    CallerLocality::OffDevice,
                    Some(records),
                    ExportCut::Archive,
                    false,
                    reader,
                    |rtxn| {
                        frozen = Some(freeze(rtxn)?);
                        Ok::<_, Error>(())
                    },
                    spool,
                )
                .map(|(_, receipt)| receipt)
        })?;
        let frozen = frozen.ok_or(Error::InvariantViolation("records archive froze nothing"))?;
        Ok((archive, frozen))
    }

    /// "Export to OKF" (OF-222): the vault as an Open Knowledge Format v0.1
    /// bundle (a ZIP of markdown concepts with YAML frontmatter) for other
    /// tools. Lossy by design and labelled as not a full copy; it carries no
    /// custody secret and does not re-import as a vault. The same diary reads
    /// and credential nulling as the archive apply.
    pub fn export_okf(&self) -> Result<WholeVaultExport> {
        self.export_in_memory(|vault, spool| vault.export_okf_to(spool))
    }

    /// [`Self::export_okf`] written to `sink` as it is built (FIX 2766), in
    /// the vault's export audit as the archive is (FIX 6427).
    pub fn export_okf_to<W: Write + Seek>(&self, sink: W) -> Result<WholeVaultExportReceipt> {
        let reader = owner_reader()?;
        let (_, mut receipt) = self.export_okf_with_admission(
            CallerLocality::OnDevice,
            reader,
            |_| Ok::<_, Error>(()),
            sink,
        )?;
        let format = crate::memory::EXPORT_TARGET_OKF;
        crate::memory::record_raw_export(self, reader.entity_ref(), format, &mut receipt);
        Ok(receipt)
    }

    pub(crate) fn export_okf_with_admission<W: Write + Seek, E: From<Error>>(
        &self,
        destination: impl Into<ReadDestination>,
        reader: WriteActor,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
        sink: W,
    ) -> std::result::Result<(W, WholeVaultExportReceipt), E> {
        self.export_archive_snapshot(
            destination,
            None,
            ExportCut::Okf,
            false,
            reader,
            admit,
            sink,
        )
    }

    /// The actor facade supplies an owner admission evaluated in the SAME
    /// snapshot as the rows. The host-level Vault export retains its existing
    /// direct door; transport callers must use the admitted memory facade.
    /// For a caller off this device the snapshot holds no row a device-local
    /// world keeps here (DEC-0005), so no edge, package or receipt of one
    /// follows; one whose world cannot be read stays too. A caller whose
    /// connection proved its machine is judged by that machine's own world
    /// read settings (mesh PR2b).
    /// `reader` is whose diary reads the export makes (OF-490).
    pub(crate) fn export_whole_vault_with_admission<W: Write + Seek, E: From<Error>>(
        &self,
        destination: impl Into<ReadDestination>,
        include_secrets: bool,
        reader: WriteActor,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
        sink: W,
    ) -> std::result::Result<(W, WholeVaultExportReceipt), E> {
        self.export_archive_snapshot(
            destination,
            None,
            ExportCut::Archive,
            include_secrets,
            reader,
            admit,
            sink,
        )
    }

    /// An export built through a spool file and read back whole, for a door
    /// that answers in one frame.
    fn export_in_memory(
        &self,
        export: impl FnOnce(&Self, &mut std::fs::File) -> Result<WholeVaultExportReceipt>,
    ) -> Result<WholeVaultExport> {
        let mut spool = self.archive_spool_file()?;
        let receipt = export(self, &mut spool)?;
        spool.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        spool.read_to_end(&mut bytes)?;
        Ok(WholeVaultExport {
            bytes,
            manifest: receipt.manifest,
            diary_reads: receipt.diary_reads,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn export_archive_snapshot<W: Write + Seek, E: From<Error>>(
        &self,
        destination: impl Into<ReadDestination>,
        only: Option<&BTreeSet<EntityId>>,
        cut: ExportCut,
        include_secrets: bool,
        reader: WriteActor,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
        sink: W,
    ) -> std::result::Result<(W, WholeVaultExportReceipt), E> {
        let destination: ReadDestination = destination.into();
        let locality = destination.locality();
        let artifact = self.whole_vault_export_manifest_artifact(
            ExportSecretsNulledManifest::from_redacted(false),
        )?;
        let storage = ExportManifest::from_json_for_import(artifact.bytes())?;
        let _bodies = self.pin_all_result_bodies();
        // An archive that opens credential values holds the custody read
        // guard from before its snapshot through its last open (KS-6); one
        // that does not take goes on, each value whose key goes mid-read as
        // its handle.
        let _custody = (include_secrets && only.is_none() && cut == ExportCut::Archive)
            .then(|| crate::secret_custody::archive_custody_guard(&self.store))
            .flatten();
        let rtxn = self.store.env.read_txn().map_err(Error::from)?;
        admit(&rtxn)?;
        let scope = match (only, cut) {
            (Some(_), _) => ExportScope::Records,
            (None, ExportCut::Archive) => ExportScope::WholeVault,
            (None, ExportCut::Okf) => ExportScope::Okf,
        };
        let adapters = crate::ingest::INGEST_SOURCE_REGISTRY
            .source_configs()
            .map(|config| ExportAdapterDescriptor {
                source_id: config.source_id.to_owned(),
                adapter_skill_id: config.adapter_skill.map(|a| a.skill_id.to_owned()),
                adapter_version: config.adapter_skill.map(|a| a.version.to_owned()),
            })
            .collect();
        // The agents' ids come first, so the claims each agent's portable
        // knowledge is selected from are kept as they pass, and no others.
        let agent_ids = crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            &rtxn,
            crate::registry::ENTITY_TYPE_AGENT_DEF,
            None,
        )?
        .collect::<Result<BTreeSet<_>>>()?;
        let mut writer =
            DocumentWriter::new(self, cut, cut == ExportCut::Archive, adapters, agent_ids)?;
        // Every row read past the locality filter below: a row the archive
        // carries, a custody record it carries as a value or a handle, a
        // diary it carries or counts as held, and a receipt source, pack
        // source or skill source carrier another section is folded from.
        let mut sources = BTreeSet::new();
        // A run names no world, so a caller off this device gets no run's
        // results: none of a device-local world's may leave it (DEC-0005).
        // Each run whose results go with it is a source, on this device only.
        if locality == CallerLocality::OnDevice && only.is_none() && cut == ExportCut::Archive {
            sources.extend(self.export_run_results_in_txn(&rtxn, &mut writer)?);
        }
        let device_only = crate::settings::device_local_worlds_for(self, &rtxn, &destination)?;
        let mut included = BTreeSet::new();
        // The root of each thread a carried TURN is of (FIX 6427).
        let mut thread_roots = crate::workspace_roster::ExportThreadRoots::default();
        let mut agent_fork_hashes = BTreeMap::new();
        let mut diaries = ExportDiaryLedger::new(reader)?;
        // FIX 4624(b): each custody value the archive carries but that does
        // not open here, by id and generation, for its holder.
        let mut holder_requests = Vec::new();
        let attaches_files = cut == ExportCut::Archive;
        for entry in
            crate::ports::EntityStoreRead::port_entity_raw_records_borrowed(&self.store, &rtxn)?
        {
            let (id, raw) = entry?;
            if only.is_some_and(|only| !only.contains(&id))
                || whole_vault_export_excludes_entity(self, &id)?
            {
                continue;
            }
            if crate::settings::device_only_withholds_raw(
                &self.store,
                &rtxn,
                &device_only,
                &id,
                Some(&raw),
            )
            .or_else(|error| match error {
                Error::CorruptedIndex(_) => Ok(true),
                error => Err(error),
            })? {
                continue;
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("whole-vault entity header"))?;
            // Owner ruling 2026-10-17: the owner's own archive carries the
            // custody records, so a re-import keeps every key. A scoped
            // export (a removed owner's, a contact's, a share's) never does.
            if header.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
                if only.is_none()
                    && cut == ExportCut::Archive
                    && row_live_in_txn(&self.store, &rtxn, &id)?
                {
                    let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(
                        &self.store,
                        &rtxn,
                        &id,
                    )?
                    .map(|(name, hash)| format!("{name}:{hash:02x}"));
                    if let Some((secret, need)) = archive_custody_secret(
                        &self.store,
                        &id,
                        handle,
                        &raw[ENTITY_METADATA_HEADER_LEN..],
                        locality == CallerLocality::OnDevice,
                        include_secrets,
                    )? {
                        sources.insert(id);
                        writer.secret(&secret)?;
                        holder_requests.extend(need.map(HolderExportRequest::unrecorded));
                    }
                }
                continue;
            }
            if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                &self.store,
                &rtxn,
                &id,
                header.entity_type,
            )? || !row_live_in_txn(&self.store, &rtxn, &id)?
            {
                continue;
            }
            sources.insert(id);
            // A file-plane ASSET goes out as its body, never the manifest its
            // row keeps, and any other row as the snapshot holds it, never
            // copied (FIX 3677). A stored file the archive attaches as it is
            // streams out; one a probe below needs whole is read whole.
            let body = row_body(self, &rtxn, &id, header.entity_type, raw, attaches_files)?;
            if header.entity_type == crate::registry::ENTITY_TYPE_ASSET
                && asset_folded(self, &rtxn, &body)?
            {
                continue;
            }
            // OF-490: a diary goes out only as a read the owner's grant
            // covers and its agent has not asked to review first. A diary
            // whose author was erased is still a diary: the ledger holds it.
            if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                && let Some(note) = body.bytes()
                && let Some(author) = note_diary_author(self, &rtxn, &id, note)?
                && !diaries.admit(self, &rtxn, author, id)?
            {
                continue;
            }
            let mut skill_package = None;
            if header.entity_type == crate::registry::ENTITY_TYPE_SKILL
                && let Some(record) = body.bytes()
                && let Some(package) = self.export_hub_package_in_txn(&rtxn, &id)?
            {
                let record = crate::skill::decode_skill_record(record)?;
                if record.content_hash != Some(package.content_hash()?) {
                    return Err(Error::CorruptedIndex("stored skill package identity drift").into());
                }
                // SCAN C022: a package read from its replicated carrier goes
                // with the skill only when the carrier passes the filter every
                // listed row passes, and the carrier is then a source.
                let carrier = self.export_hub_package_carrier_in_txn(&rtxn, &id, &record)?;
                if !carrier_withheld(&self.store, &rtxn, &device_only, carrier.as_ref())? {
                    sources.extend(carrier);
                    skill_package = Some(package);
                }
            }
            // A pack source is the ASSET body itself, read as the pack
            // catalog reads it.
            let mut pack_source = None;
            if header.entity_type == crate::registry::ENTITY_TYPE_ASSET
                && let Some(asset) = body.bytes()
                && let Some(source) = crate::skill_hub::pack_catalog::decode_source_body(asset)?
            {
                if source.entity_id()? != id {
                    return Err(Error::InvalidConfig(
                        "pack source: stored source identity drift".to_owned(),
                    )
                    .into());
                }
                pack_source = Some(source);
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF
                && let Some(hash) =
                    crate::agent_def::agent_fork_hash_in_txn(&self.store, &rtxn, &id)?
            {
                agent_fork_hashes.insert(id, hash.to_hex());
            }
            let tainted =
                !crate::secret_rotation::exhaust_taint_refs_in_txn(&self.store, &rtxn, &id)?
                    .is_empty();
            let mut task_receipts = BTreeMap::new();
            let mut archived_receipts = None;
            if !tainted
                && header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && let Some(claim) = body.bytes()
                && let Ok(claim) = crate::claim::decode_claim_body(claim, true)
            {
                // SCAN C022: each receipt source is folded from its carrier
                // only when the carrier passes the same filter, and the
                // carriers folded are sources.
                let (receipts, carriers) = crate::receipt::archived_receipt_carriers_in_txn(
                    &self.store,
                    &rtxn,
                    &id,
                    |carrier| carrier_withheld(&self.store, &rtxn, &device_only, Some(carrier)),
                )?;
                sources.extend(carriers);
                archived_receipts = Some(receipts);
                for receipt_id in super::receipt_sources::task_receipt_refs(&claim) {
                    if !task_receipts.contains_key(&receipt_id)
                        && let Some(receipt) = crate::receipt::attempt_pack_receipt_in_txn(
                            &self.store,
                            &rtxn,
                            &receipt_id,
                        )?
                    {
                        task_receipts.insert(receipt_id, receipt);
                    }
                }
            }
            included.insert(id);
            let short_ref =
                crate::ports::ShortIdStoreRead::port_short_id_reference(&self.store, &rtxn, &id)?
                    .map(|(name, hash)| format!("{name}:{hash:02x}"));
            // The entity-document head's projection, then the NOTE-specific
            // document, under this snapshot transaction, before the
            // serializer's unconditional credential nulling.
            let body = body.projected(self, &rtxn, &id, header.entity_type)?;
            if let ExportSnapshotEntityBody::Bytes(body) = &body {
                thread_roots.extend(crate::memory::turn_thread_root(header.entity_type, body));
            }
            writer.entity(ExportSnapshotEntity {
                id,
                short_ref,
                header,
                body,
                tainted,
                skill_package,
                pack_source,
                task_receipts,
                archived_receipts,
            })?;
        }
        for entry in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&self.store, &rtxn)? {
            let (key, value) = entry?;
            let edge = parse_strict_edge_record(&key, &value)?;
            if !included.contains(&edge.source) || !included.contains(&edge.target) {
                continue;
            }
            writer.edge(&ExportEdge {
                source: edge.source.to_hex(),
                kind: edge.kind as u8,
                target: edge.target.to_hex(),
                weight: edge.decoded.weight,
                created_at: edge.decoded.created_at,
                vad: edge
                    .decoded
                    .vad
                    .map(|v| [v.valence, v.arousal, v.dominance]),
                provenance: edge
                    .decoded
                    .provenance
                    .map(|p| [p.confirmation_status as u8, p.actor_class as u8]),
            })?;
        }
        // OF-370: a whole-vault archive carries the embedding setup, read in
        // this snapshot; a records archive and OKF carry none.
        let embedding_setup = if carries_embedding_setup(scope) {
            Some(super::embedding_setup_in_txn(&self.store, &rtxn)?)
        } else {
            None
        };
        // OF-013: the floors travel so an import never numbers an epoch under
        // one a purge removed. A floor whose session a device-local world
        // keeps stays here, as the session's own row does.
        if scope == ExportScope::WholeVault {
            for (session, epoch, turn_end) in
                crate::compaction::epoch_floors_in_txn(&self.store, &rtxn)?
            {
                if crate::settings::device_only_withholds(
                    &self.store,
                    &rtxn,
                    &device_only,
                    &session,
                )
                .or_else(|error| match error {
                    Error::CorruptedIndex(_) => Ok(true),
                    error => Err(error),
                })? {
                    continue;
                }
                sources.insert(session);
                writer.epoch_floor(&super::ExportEpochFloor {
                    session: session.to_hex(),
                    epoch,
                    turn_end,
                })?;
            }
        }
        // FIX 2768, 3681: each carried record's side rows go with it, in a
        // records archive as in the whole-vault one, read in this snapshot
        // against the rows it carries and never past them: a removed owner's
        // archive holds no row its scope did not read. A vault-wide row goes
        // only to a caller on this device. A carried record whose family names
        // a carrier left out is named in the manifest instead.
        if cut == ExportCut::Archive {
            let (rows, withheld) = super::archive_side_rows_in_txn(
                &self.store,
                &rtxn,
                &included,
                locality == CallerLocality::OnDevice,
            )?;
            for row in rows {
                writer.side_row(row)?;
            }
            writer.side_rows_withheld(withheld);
        }
        // FIX 11844: a custody secret only the fold knows here is named for
        // its holder too, as a held row's unopened value is above.
        if include_secrets && only.is_none() && cut == ExportCut::Archive {
            let fold_only = self.fold_only_holder_needs_in_txn(&rtxn);
            holder_requests.extend(fold_only.into_iter().map(HolderExportRequest::unrecorded));
        }
        // Each carried thread's binding, read in this snapshot, so its
        // members are told should its root go before the audit (FIX 6681).
        thread_roots.capture_in(&self.store.read(), &rtxn);
        drop(rtxn);
        // The gate logs the reads after the snapshot. An entry whose read
        // could not be logged leaves the archive, with its edges.
        let (diary_reads, diary_holds, unlogged) = diaries.finish(self);
        writer
            .finish(
                DocumentTail {
                    storage,
                    exported_at: crate::unix_seconds_now(),
                    agent_fork_hashes,
                    diary_reads,
                    diary_holds,
                    unlogged,
                    secrets_included: include_secrets
                        && only.is_none()
                        && cut == ExportCut::Archive,
                    embedding_setup,
                    sources: sources.into_iter().collect(),
                },
                sink,
            )
            .map(|(sink, mut receipt)| {
                receipt.thread_roots = thread_roots;
                receipt.holder_requests = holder_requests;
                (sink, receipt)
            })
            .map_err(E::from)
    }

    /// The run result closure (OF-190 B++): every run's manifests, each
    /// occurrence through the egress door before any bytes are shared
    /// (Docs Q08), each body a clean occurrence names, once, and each fold
    /// receipt beside the occurrence it describes. A withheld
    /// occurrence keeps its mark and names no body, so one clean occurrence
    /// of the same bytes neither clears it nor ships its body for it. A body
    /// no row holds any longer is withheld as absent. Each body goes to the
    /// writer as it is read.
    /// Returns the runs whose results it wrote.
    fn export_run_results_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        writer: &mut DocumentWriter<'_>,
    ) -> Result<Vec<EntityId>> {
        let mut runs = Vec::new();
        let mut bodies = BTreeSet::new();
        for (run_id, outputs) in self.code_run_result_manifests_in_txn(rtxn)? {
            let mut occurrences = Vec::with_capacity(outputs.len());
            for output in outputs {
                let withheld =
                    super::whole_vault_export_withholds_result(self, rtxn, run_id, &output)?;
                if withheld.is_none() && bodies.insert(output.raw_blake3) {
                    let body = self
                        .code_run_result_body_reader_in_txn(rtxn, &output)?
                        .ok_or("absent");
                    writer.result_body(
                        output.raw_blake3,
                        ExportSnapshotBody {
                            bytes: output.raw_len,
                            body,
                        },
                    )?;
                }
                occurrences.push((output, withheld));
            }
            // Each receipt goes beside the manifest of the occurrence it
            // describes, judged as that occurrence is.
            let receipts = self
                .code_run_reader_folds_in_txn(rtxn, run_id)?
                .into_iter()
                .filter_map(|receipt| {
                    occurrences
                        .iter()
                        .find(|(output, _)| output.path == receipt.folded.path)
                        .map(|(_, withheld)| (receipt, *withheld))
                })
                .collect();
            writer.run(ExportSnapshotRun {
                run_id,
                outputs: occurrences,
                receipts,
            })?;
            runs.push(run_id);
        }
        Ok(runs)
    }
}

/// The author of a NOTE row when it is a diary, read from its committed text:
/// a live agent, or no one once erased; `None` only for a row that is no
/// diary.
fn note_diary_author(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<crate::note::NoteActor>> {
    #[cfg(feature = "sync")]
    let body = crate::entity_doc::resolve_record_body(&vault.store, rtxn, id, body)?;
    #[cfg(not(feature = "sync"))]
    let _ = (vault, rtxn, id);
    Ok(super::diary_author(&body))
}

/// A custody record as an archive row. A revoked record is not exported.
/// The value goes with an active record when secrets are included, and for a
/// caller off this device (`on_device` false) only when it is portable: a
/// device-bound value never leaves this device (DEC-0005). Every other live
/// record goes as its handle, to re-enter after import. The stored body is
/// sealed (KS-6): the archive's is the plaintext DTO, its value opened
/// explicitly from current custody; one that does not open goes as its
/// handle, warned. A cloud registration slot's value never goes, on this
/// device or not: it is the engine's own, and its owner signs in again.
///
/// A portable value the archive carries that does not open here is named
/// beside its row, by id and generation, for its holder to seal to the owner
/// (FIX 4624(b)): only that one. A value withheld (secrets left out, a
/// revoked record, a cloud slot, a device-bound value going off its device)
/// is named nowhere.
fn archive_custody_secret(
    store: &crate::store::Store,
    id: &EntityId,
    handle: Option<String>,
    body: &[u8],
    on_device: bool,
    include_secrets: bool,
) -> Result<Option<(ArchiveSecretCustody, Option<HolderExportNeed>)>> {
    use crate::secret_custody::{CustodyClass, SecretCustodyStatus};
    use base64::Engine as _;
    let (record, value) = crate::secret_custody::archive_custody_body(store, id, body, |record| {
        include_secrets
            && record.status == SecretCustodyStatus::Active
            && !crate::secret_custody::is_cloud_registration_slot(&record.name)
            && (on_device || (!record.device_only && record.class == CustodyClass::CustodyPortable))
    })?;
    if record.status == SecretCustodyStatus::Revoked {
        return Ok(None);
    }
    // The archive carries this value and it did not open: it goes as its
    // handle, and its holder is asked for it when it may leave its device.
    let need = (value.is_unopened()
        && !record.device_only
        && record.class == CustodyClass::CustodyPortable)
        .then_some(HolderExportNeed {
            secret: *id,
            generation: record.rotation_generation,
        });
    let plain = value.into_opened();
    Ok(Some((
        ArchiveSecretCustody {
            id: id.to_hex(),
            name: record.name.clone(),
            handle,
            metadata: record.metadata(),
            body: plain.map(|plain| base64::engine::general_purpose::STANDARD.encode(&*plain)),
        },
        need,
    )))
}

/// Whether the export's locality filter withholds `carrier`, a row another
/// row's section is folded from (SCAN C022): the filter every listed row
/// passes, judged on the carrier's own row, and an unreadable one withheld as
/// an unreadable row is. No carrier is withheld when none was read.
fn carrier_withheld(
    store: &crate::store::Store,
    rtxn: &heed::RoTxn<'_>,
    device_only: &BTreeSet<EntityId>,
    carrier: Option<&EntityId>,
) -> Result<bool> {
    let Some(carrier) = carrier else {
        return Ok(false);
    };
    crate::settings::device_only_withholds(store, rtxn, device_only, carrier).or_else(|error| {
        match error {
            Error::CorruptedIndex(_) => Ok(true),
            error => Err(error),
        }
    })
}

/// The vault owner as a diary reader: the embedded and OKF exports' reader.
fn owner_reader() -> Result<WriteActor> {
    Ok(WriteActor::new(
        crate::vault::embedded_owner_actor_id()?,
        EdgeActorClass::Human,
    ))
}
