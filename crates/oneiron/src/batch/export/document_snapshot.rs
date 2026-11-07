//! Snapshot enumeration for whole-vault export. No raw bytes leave this module
//! except as input to the serializer's mandatory credential-nulling transform,
//! and a stored file an archive carries as it is (OF-222). Each row goes to the
//! serializer as it is read (FIX 2766): the snapshot holds ids and indexes,
//! never the vault's bodies.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Seek, Write};

use super::copy_release::{MailboxLineage, MemberMailPass, version_claim_names};
use super::snapshot_body::{asset_folded, row_body, row_live_in_txn};
use super::{
    ArchiveSecretCustody, ExportAdapterDescriptor, ExportCut, ExportDiaryLedger, ExportEdge,
    ExportManifest, ExportScope, ExportSecretsNulledManifest, ExportSnapshotEntityBody,
    WholeVaultExport, WholeVaultExportReceipt, carries_embedding_setup,
    whole_vault_export_excludes_entity_in_txn,
};
use crate::Vault;
use crate::authority::HolderExportRequest;
use crate::batch::export::secret_supplement_record::HolderExportNeed;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeActorClass, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::serialize::{DocumentTail, DocumentWriter};
use crate::settings::CallerLocality;
use crate::settings::ReadDestination;
use crate::write_envelope::WriteActor;

/// One run's result manifests, as its replay record names them, each with
/// why the egress door withholds the run's occurrence of it, if it does.
pub(crate) struct ExportSnapshotRun {
    pub(crate) run_id: EntityId,
    pub(crate) outputs: Vec<(
        crate::store::result_manifest::CodeRunRawOutput,
        Option<&'static str>,
    )>,
    /// Live result names that resolve to one of `outputs`, judged with it.
    pub(crate) bindings: Vec<(crate::code_run::CodeRunResultBinding, Option<&'static str>)>,
    pub(crate) determinism: Option<crate::code_run::CodeRunDeterminism>,
    /// The run's fold receipts, each with why the egress door withholds the
    /// occurrence it describes, if it does.
    pub(crate) receipts: Vec<(
        crate::store::reader_fold_receipt::ReaderFoldReceipt,
        Option<&'static str>,
    )>,
}

/// One result body a clean occurrence names: its bytes as they stream, read
/// under the snapshot and checked to their end (FIX 5392), or why they are
/// not exported.
pub(crate) struct ExportSnapshotBody<'t> {
    pub(crate) bytes: u64,
    pub(crate) body: std::result::Result<
        crate::store::result_body_reader::CodeRunResultBodyReader<'t>,
        &'static str,
    >,
}

/// One live row as the snapshot reads it, with what it carries beside it.
pub(crate) struct ExportSnapshotEntity<'t> {
    pub(crate) id: EntityId,
    pub(crate) short_ref: Option<String>,
    pub(crate) header: EntityMetadataHeader,
    pub(crate) body: ExportSnapshotEntityBody<'t>,
    pub(crate) tainted: bool,
    /// A SKILL's stored source package.
    pub(crate) skill_package: Option<crate::store::skill_package::HubPackage>,
    /// The pack source an ASSET body is.
    pub(crate) pack_source: Option<crate::skill_hub::pack_catalog::PackSource>,
    /// The native task receipts a CLAIM cites, by id, each as the copy
    /// carries it: its body, or why not (fix list row 15416).
    pub(crate) task_receipts: BTreeMap<String, super::ExportReceiptSource>,
    /// A CLAIM's archived receipt sources.
    pub(crate) archived_receipts: Option<BTreeMap<String, super::ExportReceiptSource>>,
    /// The row's birth envelope, read in this snapshot (FIX 1178); `None`
    /// outside an archive cut, and for a row no door stamped.
    pub(crate) birth: Option<crate::provenance::birth::RowBirth>,
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
        self.export_in_memory(ExportCut::Archive, include_secrets)
    }

    /// [`Self::export_whole_vault`] written to `sink` (FIX 2766): the rows
    /// are spooled under the vault's staging directory and copied into the
    /// ZIP one member and one file at a time, so a vault larger than memory
    /// exports. The copy is the owner's, in the vault's export audit, and
    /// each private thread it carries that he is not in is told of it (FIX
    /// 6427). It is made in a spool only this engine reads and reaches
    /// `sink` once it is recorded: one that carries another member's
    /// personal mailbox, once each mailbox's person is told (fix list row
    /// 15416).
    pub fn export_whole_vault_to<W: Write + Seek>(
        &self,
        include_secrets: bool,
        mut sink: W,
    ) -> Result<WholeVaultExportReceipt> {
        let mut copy = self.raw_owner_copy(ExportCut::Archive, include_secrets)?;
        copy.release_to(&mut sink)?;
        Ok(copy.receipt)
    }

    /// The archive of exactly `records` and the graph between them, for a
    /// reader off this device: an export-first removal's export (OF-163),
    /// in the same shape as a whole-vault archive and re-importable alike,
    /// written to `sink` as it is built (FIX 3679): no archive is read back
    /// whole. No run's results go with it; a run names no world to scope it
    /// by. Each record's side rows and stored files go with it as they do in
    /// the whole-vault archive, never past `records`, and no vault-wide row
    /// does (FIX 3681). Its diary reads are `reader`'s, the owner who
    /// receives it. `freeze` reads in the archive's own snapshot, before its
    /// rows, so what it answers (the removal's frozen positions, FIX-LIST
    /// 8224) and the bytes archived are one state.
    pub(crate) fn export_records_archive<W: Write + Seek, T>(
        &self,
        records: &BTreeSet<EntityId>,
        reader: WriteActor,
        freeze: impl FnOnce(&heed::RoTxn<'_>) -> Result<T>,
        sink: W,
    ) -> Result<(W, WholeVaultExportReceipt, T)> {
        let mut frozen = None;
        let (sink, receipt) = self.export_archive_snapshot(
            CallerLocality::OffDevice,
            Some(records),
            ExportCut::Archive,
            false,
            reader,
            false,
            MemberMailPass::Exempt,
            |rtxn| {
                frozen = Some(freeze(rtxn)?);
                Ok::<_, Error>(())
            },
            sink,
        )?;
        let frozen = frozen.ok_or(Error::InvariantViolation("records archive froze nothing"))?;
        Ok((sink, receipt, frozen))
    }

    /// "Export to OKF" (OF-222): the vault as an Open Knowledge Format v0.1
    /// bundle (a ZIP of markdown concepts with YAML frontmatter) for other
    /// tools. Lossy by design and labelled as not a full copy; it carries no
    /// custody secret and does not re-import as a vault. The same diary reads
    /// and credential nulling as the archive apply.
    pub fn export_okf(&self) -> Result<WholeVaultExport> {
        self.export_in_memory(ExportCut::Okf, false)
    }

    /// [`Self::export_okf`] written to `sink` (FIX 2766), in the vault's
    /// export audit and released once it is recorded, as the archive is (FIX
    /// 6427, fix list row 15416).
    pub fn export_okf_to<W: Write + Seek>(&self, mut sink: W) -> Result<WholeVaultExportReceipt> {
        let mut copy = self.raw_owner_copy(ExportCut::Okf, false)?;
        copy.release_to(&mut sink)?;
        Ok(copy.receipt)
    }

    /// `owner_export` as [`Self::export_whole_vault_with_admission`] takes
    /// it, written to `sink` as it is built.
    pub(crate) fn export_okf_with_admission<W: Write + Seek, E: From<Error>>(
        &self,
        destination: impl Into<ReadDestination>,
        reader: WriteActor,
        owner_export: bool,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
        sink: W,
    ) -> std::result::Result<(W, WholeVaultExportReceipt), E> {
        self.export_archive_snapshot(
            destination,
            None,
            ExportCut::Okf,
            false,
            reader,
            owner_export,
            MemberMailPass::Exempt,
            admit,
            sink,
        )
    }

    /// The actor facade supplies an owner admission evaluated in the SAME
    /// snapshot as the rows. The host-level Vault export retains its existing
    /// direct door; transport callers must use the admitted memory facade.
    /// The owner's own export is his will (owner ruling 1-EXPORT = B): for a
    /// caller off this device it carries the rows of every world his
    /// recipient choice withholds from where it goes, with their edges,
    /// packages, receipts, epoch floors, run results and vault-wide rows,
    /// and its receipt names each such world in a notice. A row whose world
    /// cannot be placed still stays here. A caller whose connection proved
    /// its machine is judged by that machine's own world read settings (mesh
    /// PR2b), for the notices and the custody values that may not leave.
    /// `reader` is whose diary reads the export makes (OF-490).
    /// `owner_export` false (an export a code run calls, FIX 9591) follows
    /// the world settings as before the ruling: no row of a world they
    /// withhold from `destination`, no run's results or vault-wide row off
    /// this device, and no notice.
    /// It writes to `sink` as it is built, and the members' mailbox rule
    /// does not judge it: the owner's own copy is made, recorded and only
    /// then released through [`Self::release_owner_copy`] (fix list row
    /// 15416).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn export_whole_vault_with_admission<W: Write + Seek, E: From<Error>>(
        &self,
        destination: impl Into<ReadDestination>,
        include_secrets: bool,
        reader: WriteActor,
        owner_export: bool,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
        sink: W,
    ) -> std::result::Result<(W, WholeVaultExportReceipt), E> {
        self.export_archive_snapshot(
            destination,
            None,
            ExportCut::Archive,
            include_secrets,
            reader,
            owner_export,
            MemberMailPass::Exempt,
            admit,
            sink,
        )
    }

    /// The embedded owner's own copy `cut`, built through a spool file and
    /// read back whole once it is recorded, for a door that answers in one
    /// frame.
    fn export_in_memory(&self, cut: ExportCut, include_secrets: bool) -> Result<WholeVaultExport> {
        let mut copy = self.raw_owner_copy(cut, include_secrets)?;
        let bytes = copy.read_whole()?;
        let receipt = copy.receipt;
        Ok(WholeVaultExport {
            bytes,
            manifest: receipt.manifest,
            diary_reads: receipt.diary_reads,
            notices: receipt.notices,
            mailbox_notices: receipt.mailbox_notices,
        })
    }

    /// `owner_export`: the owner's own whole-vault or OKF export (owner
    /// ruling 1-EXPORT = B), whose rows his recipient choice keeps none of;
    /// false for a removal's records archive and for an export a code run
    /// calls, which the world settings judge as before. `member_mail`: an
    /// Owner's copy also leaves out each row of another member's personal
    /// mailbox the vault's rule does not carry, and each row whose words came
    /// from one, before the row is read whole, and its receipt names each
    /// such mailbox and carries those it does (fix list row 15416).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn export_archive_snapshot<W: Write + Seek, E: From<Error>>(
        &self,
        destination: impl Into<ReadDestination>,
        only: Option<&BTreeSet<EntityId>>,
        cut: ExportCut,
        include_secrets: bool,
        reader: WriteActor,
        owner_export: bool,
        member_mail: MemberMailPass,
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
        // Fix list row 15416: an Owner's copy reads the vault's rule for the
        // other members' personal mailboxes in this snapshot, as the PERSON
        // it exports as, and judges every row by it before the row is read
        // whole: a separate conjunct beside the world settings below.
        let plan = member_mail.plan_in(self, &rtxn, reader)?;
        let dbs = self.store.read();
        let mut judge = plan
            .as_ref()
            .map(|plan| plan.judge(self, &dbs, &rtxn))
            .transpose()?;
        // What the side ledgers record each row's body was made from (a blob
        // version's made_by, a code revision's or proposal's references), read
        // once in this snapshot for an Owner's copy: every row below meets it
        // before its body is read (fix list row 15416).
        let mut lineage = MailboxLineage::read_in(&self.store, &rtxn, judge.is_some())?;
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
        // A run names no world, so another caller off this device gets no
        // run's results: none of a device-local world's may leave it
        // (DEC-0005). The owner's own whole-vault archive carries every run's
        // results wherever it goes (owner ruling 1-EXPORT = B); each
        // occurrence still meets the egress door. Each run whose results go
        // with it is a source.
        if (owner_export || locality == CallerLocality::OnDevice)
            && only.is_none()
            && cut == ExportCut::Archive
        {
            sources.extend(self.export_run_results_in_txn(
                &rtxn,
                &mut writer,
                judge.as_mut(),
                &mut lineage,
            )?);
        }
        // Every world the world settings withhold from this destination: the
        // owner's recipient choice for each. A row of one stays here, except
        // in the owner's own export, which carries it and names the world.
        let device_only = crate::settings::device_local_worlds_for(self, &rtxn, &destination)?;
        // The withheld worlds the owner's own export carries rows of, each
        // named in a notice.
        let mut barred_carried = BTreeSet::new();
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
                || whole_vault_export_excludes_entity_in_txn(&self.store, &rtxn, &id)?
            {
                continue;
            }
            let Some(row_barred) = barred_worlds_carried(
                &self.store,
                &rtxn,
                &device_only,
                &id,
                Some(&raw),
                owner_export,
            )?
            else {
                continue;
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("whole-vault entity header"))?;
            // Owner ruling 2026-10-17: the owner's own archive carries the
            // custody records, so a re-import keeps every key. A scoped
            // export (a removed owner's, a contact's, a share's) never does.
            if header.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
                if only.is_none()
                    && cut == ExportCut::Archive
                    && row_live_in_txn(&self.store, &rtxn, &id)?
                    && lineage.admits(judge.as_mut(), id, Some(&raw))?
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
                        lineage.ships([id]);
                        holder_requests.extend(need.map(HolderExportRequest::unrecorded));
                    }
                }
                continue;
            }
            // A member's mailbox the copy does not carry, and what was learned
            // from it, stay home before the row is read whole, in an archive
            // and an OKF copy alike: what its own lineage names, and what the
            // side ledgers record its body was made from. Bytes a blob
            // version holds stay home only when no recorded use of them goes
            // whole (fix list row 15416).
            if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                &self.store,
                &rtxn,
                &id,
                header.entity_type,
            )? || !row_live_in_txn(&self.store, &rtxn, &id)?
                || !lineage.admits(judge.as_mut(), id, Some(&raw))?
            {
                continue;
            }
            // A blob version's ledger claim names each row the version's
            // made_by names, as the version's record does, read through the
            // made_by codec: it goes only when the copy carries every one of
            // them, and they count as carried once the claim ships; one whose
            // made_by does not read stays home (fix list row 15416).
            if judge.is_some()
                && let Some(names) = version_claim_names(header.entity_type, &raw)
                && !lineage.supplements(judge.as_mut(), id, names.as_deref())?
            {
                continue;
            }
            // FIX 1496 S5: an epoch summary stays home when any transitive
            // source is excluded (use-limited or off-record), same as the
            // JSON bundle door, or is of a member's mailbox the copy does not
            // carry. Non-epoch rows answer None and pass through.
            if crate::compaction::epoch_sources_admitted_in(
                &self.store,
                &rtxn,
                &id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
                |source, _| {
                    Ok(
                        !whole_vault_export_excludes_entity_in_txn(&self.store, &rtxn, source)?
                            && lineage.folds(judge.as_mut(), id, Some(source))?,
                    )
                },
            )? == Some(false)
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
                let record = crate::write_envelope::skill_record::decode_skill_record(record)?;
                if record.content_hash != Some(package.content_hash()?) {
                    return Err(Error::CorruptedIndex("stored skill package identity drift").into());
                }
                // SCAN C022: a package read from its replicated carrier goes
                // with the skill only when the carrier passes the filter every
                // listed row passes, and the carrier is then a source.
                let carrier = self.export_hub_package_carrier_in_txn(&rtxn, &id, &record)?;
                if let Some(barred) = carrier_admitted(
                    &self.store,
                    &rtxn,
                    &device_only,
                    carrier.as_ref(),
                    owner_export,
                )? && lineage.folds(judge.as_mut(), id, carrier.as_ref())?
                {
                    barred_carried.extend(barred);
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
                && let Ok(claim) = crate::write_envelope::claim_body::decode_claim_body(claim, true)
            {
                // SCAN C022: each receipt source is folded from its carrier
                // only when the carrier passes the same filter, and the
                // carriers folded are sources.
                let (mut receipts, carriers) = crate::receipt::archived_receipt_carriers_in_txn(
                    &self.store,
                    &rtxn,
                    &id,
                    |carrier| {
                        let admitted = carrier_admitted(
                            &self.store,
                            &rtxn,
                            &device_only,
                            Some(carrier),
                            owner_export,
                        )?;
                        let Some(barred) = admitted else {
                            return Ok(true);
                        };
                        // An OKF copy writes no carrier, so its fold counts
                        // nothing as carried (fix list row 15416).
                        let folded = if cut == ExportCut::Archive {
                            lineage.folds(judge.as_mut(), id, Some(carrier))?
                        } else {
                            lineage.folds_unwritten(judge.as_mut(), Some(carrier))?
                        };
                        if folded {
                            barred_carried.extend(barred);
                        }
                        Ok(!folded)
                    },
                )?;
                sources.extend(carriers);
                // An archived source keeps its body only beside every row its
                // attempt read, judged as a native receipt's is below; one
                // made from a member's mailbox the copy leaves out, or from
                // rows not all known, goes as unavailable and still stands
                // for its id (fix list row 15416).
                lineage.archived_receipt_sources(judge.as_mut(), id, &mut receipts)?;
                // A native receipt goes only where no archived source of its
                // id stands, and keeps its body only beside every row its
                // attempt read, judged before the body is kept: one made from
                // a member's mailbox the copy leaves out, or from rows not
                // all known, goes as unavailable (fix list row 15416).
                for receipt_id in super::receipt_sources::task_receipt_refs(&claim) {
                    if !receipts.contains_key(&receipt_id)
                        && !task_receipts.contains_key(&receipt_id)
                        && let Some(receipt) = crate::receipt::attempt_pack_receipt_in_txn(
                            &self.store,
                            &rtxn,
                            &receipt_id,
                        )?
                    {
                        let source = lineage.receipt_source(
                            judge.as_mut(),
                            id,
                            receipt_id.clone(),
                            &receipt,
                        )?;
                        task_receipts.insert(receipt_id, source);
                    }
                }
                archived_receipts = Some(receipts);
            }
            barred_carried.extend(row_barred);
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
            // FIX 1178: the row's birth, read in this snapshot. The writer
            // holds it until the carried set is final and masks it then; the
            // lossy OKF cut carries no birth.
            let birth = if cut == ExportCut::Archive {
                crate::provenance::birth::row_birth_in_txn(&self.store, &rtxn, &id)?
            } else {
                None
            };
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
                birth,
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
        // one a purge removed. A floor whose session the archive leaves here
        // stays here, as the session's own row does: one of a world kept
        // here, and one of a member's mailbox the copy leaves out (fix list
        // row 15416).
        if scope == ExportScope::WholeVault {
            for (session, epoch, turn_end) in
                crate::compaction::epoch_floors_in_txn(&self.store, &rtxn)?
            {
                if barred_worlds_carried(
                    &self.store,
                    &rtxn,
                    &device_only,
                    &session,
                    None,
                    owner_export,
                )?
                .is_none()
                    || !lineage.admits(judge.as_mut(), session, None)?
                {
                    continue;
                }
                sources.insert(session);
                writer.epoch_floor(&super::ExportEpochFloor {
                    session: session.to_hex(),
                    epoch,
                    turn_end,
                })?;
                lineage.ships([session]);
            }
        }
        // FIX 2768, 3681: each carried record's side rows go with it, in a
        // records archive as in the whole-vault one, read in this snapshot
        // against the rows it carries and never past them: a removed owner's
        // archive holds no row its scope did not read. A vault-wide row goes
        // with the owner's own whole-vault archive wherever it goes (owner
        // ruling 1-EXPORT = B), never with a records archive. A carried
        // record whose family names a carrier left out is named in the
        // manifest instead, and in an Owner's copy so is one whose family
        // names, in any typed record it keeps, a row of a member's mailbox
        // the copy leaves out or a row whose words came from one, and so is a
        // code document whose history does (fix list row 15416). The rows a
        // side row names count as carried once the writer serializes it.
        if cut == ExportCut::Archive {
            let (rows, withheld) = super::archive_side_rows_in_txn(
                &self.store,
                &rtxn,
                &included,
                only.is_none() && (owner_export || locality == CallerLocality::OnDevice),
                judge.as_mut(),
            )?;
            for mut row in rows {
                let names = std::mem::take(&mut row.names);
                if writer.side_row(row)? {
                    lineage.ships(names);
                }
            }
            writer.side_rows_withheld(withheld);
        }
        // FIX 11844: a custody secret only the fold knows here is named for
        // its holder too, as a held row's unopened value is above.
        // The manifest names each by id, so the import shows it owed (FIX
        // 12066).
        let mut fold_only_secrets = Vec::new();
        if include_secrets && only.is_none() && cut == ExportCut::Archive {
            let fold_only = self.fold_only_holder_needs_in_txn(&rtxn);
            fold_only_secrets = fold_only.iter().map(|need| need.secret).collect();
            holder_requests.extend(fold_only.into_iter().map(HolderExportRequest::unrecorded));
        }
        // Each carried thread's binding, read in this snapshot, so its
        // members are told should its root go before the audit (FIX 6681).
        thread_roots.capture_in(&self.store.read(), &rtxn);
        // Owner ruling 1-EXPORT = B: one notice for each world the owner's
        // own export carries that his recipient choice would keep from where
        // it goes, naming it and why, judged in this snapshot. None on this
        // device.
        let mut notices = Vec::new();
        for (world, limit) in
            crate::settings::recipient_limits_in(self, &rtxn, &barred_carried, &destination)?
        {
            let name = crate::share_travel::world_label_in_txn(self, &rtxn, &world)?;
            notices.push(crate::share_travel::WorldRecipientNotice::export(
                world, name, limit,
            ));
        }
        let verdicts = judge.map(crate::source_audience::ExportJudge::settle);
        drop(rtxn);
        // The gate logs the reads after the snapshot. An entry whose read
        // could not be logged leaves the archive, with its edges.
        let (diary_reads, diary_holds, unlogged) = diaries.finish(self);
        // Each member's mailbox the copy left out is named to the Owner; a
        // member's mailbox counts as carried only through a row the copy
        // ships, or a receipt body it serializes (fix list row 15416).
        let (mailbox_notices, member_mail) = lineage.outcome(
            plan,
            verdicts,
            writer.carried_rows(),
            writer.carried_receipts(),
            &unlogged,
        );
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
                    fold_only_secrets,
                    embedding_setup,
                    sources: sources.into_iter().collect(),
                },
                sink,
            )
            .map(|(sink, mut receipt)| {
                receipt.thread_roots = thread_roots;
                receipt.holder_requests = holder_requests;
                receipt.notices = notices;
                receipt.mailbox_notices = mailbox_notices;
                receipt.member_mail = member_mail;
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
    /// writer as it is read. In an Owner's copy (`judge`), an occurrence also
    /// goes only beside every row it was made from, judged before its body
    /// is read, and one made from rows not all known stays home (fix list
    /// row 15416); `lineage` keeps those rows.
    /// Returns the runs whose results it wrote.
    fn export_run_results_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        writer: &mut DocumentWriter<'_>,
        mut judge: Option<&mut crate::source_audience::ExportJudge<'_, '_, '_>>,
        lineage: &mut MailboxLineage,
    ) -> Result<Vec<EntityId>> {
        let mut runs = Vec::new();
        let mut bodies = BTreeSet::new();
        for (run_id, outputs) in self.code_run_result_manifests_in_txn(rtxn)? {
            let replay = self.get_code_run_replay_record_in_txn(rtxn, &run_id)?;
            let determinism = replay.as_ref().and_then(|record| record.determinism);
            let bindings = replay.map(|record| record.bindings).unwrap_or_default();
            let mut occurrences = Vec::with_capacity(outputs.len());
            for output in outputs {
                let mut withheld =
                    super::whole_vault_export_withholds_result(self, rtxn, run_id, &output)?;
                if withheld.is_none() {
                    withheld = lineage
                        .output_withheld(judge.as_deref_mut(), output.input_rows.as_deref())?;
                }
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
            // A binding travels only beside the occurrence its handle and
            // path name; a dangling name is not evidence of a result. Same
            // bytes under another path are another occurrence, so a binding
            // never takes a same-hash occurrence's judgment. Withholding the
            // occurrence withholds the handle too, never the name, path or reason.
            let bindings = bindings
                .into_iter()
                .filter_map(|binding| {
                    occurrences
                        .iter()
                        .find(|(output, _)| {
                            output.handle == binding.handle && output.path == binding.path
                        })
                        .map(|(_, withheld)| (binding, *withheld))
                })
                .collect();
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
                bindings,
                determinism,
                receipts,
            })?;
            // A run whose replies an erase took before this export carries
            // its masked manifest and no live result, so it is no source
            // its release must find standing; a run captured live is one.
            if self.code_run_results_stand_in_txn(rtxn, &run_id)? != Some(false) {
                runs.push(run_id);
            }
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
) -> Result<Option<crate::store::note_body::NoteActor>> {
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
    use crate::secret_record::{CustodyClass, SecretCustodyStatus};
    use base64::Engine as _;
    let (record, value) = crate::secret_custody::archive_custody_body(store, id, body, |record| {
        include_secrets
            && record.status == SecretCustodyStatus::Active
            && !crate::secret_record::is_cloud_registration_slot(&record.name)
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

/// Whether the export's filter admits `carrier`, a row another row's section
/// is folded from (SCAN C022): the filter every listed row passes, judged on
/// the carrier's own row ([`barred_worlds_carried`]), and a carrier under a
/// use limit withheld. `None` when it is withheld, else the barred worlds the
/// owner's own export carries it in spite of. No carrier is withheld when
/// none was read.
fn carrier_admitted(
    store: &crate::store::Store,
    rtxn: &heed::RoTxn<'_>,
    device_only: &BTreeSet<EntityId>,
    carrier: Option<&EntityId>,
    owner_export: bool,
) -> Result<Option<BTreeSet<EntityId>>> {
    let Some(carrier) = carrier else {
        return Ok(Some(BTreeSet::new()));
    };
    if crate::store::legal_hold::use_limit_in_txn(store, rtxn, carrier)?.is_some() {
        return Ok(None);
    }
    barred_worlds_carried(store, rtxn, device_only, carrier, None, owner_export)
}

/// Whether the export's world filter admits `id` toward `barred`, every world
/// the world settings withhold from where it goes: `None` when it leaves the
/// row here, else the worlds of `barred` the archive carries it in spite of.
/// Outside the owner's own export (`owner_export` false) a row any barred
/// world keeps stays, and the set is empty. His own export carries a row his
/// recipient choice alone keeps (owner ruling 1-EXPORT = B), and the set
/// names those worlds; a row whose world cannot be placed stays, as its
/// release holds it. A row that cannot be read stays either way. `raw` is
/// the revision of `id` the snapshot serves; `None` judges the one stored.
fn barred_worlds_carried(
    store: &crate::store::Store,
    rtxn: &heed::RoTxn<'_>,
    barred: &BTreeSet<EntityId>,
    id: &EntityId,
    raw: Option<&[u8]>,
    owner_export: bool,
) -> Result<Option<BTreeSet<EntityId>>> {
    let judged = match (owner_export, raw) {
        (true, Some(raw)) => {
            crate::settings::device_only_recipient_worlds_raw(store, rtxn, barred, id, Some(raw))
        }
        (true, None) => crate::settings::device_only_recipient_worlds(store, rtxn, barred, id),
        (false, raw) => {
            let withheld = match raw {
                Some(raw) => {
                    crate::settings::device_only_withholds_raw(store, rtxn, barred, id, Some(raw))
                }
                None => crate::settings::device_only_withholds(store, rtxn, barred, id),
            };
            withheld.map(|withheld| (!withheld).then(BTreeSet::new))
        }
    };
    match judged {
        Err(Error::CorruptedIndex(_)) => Ok(None),
        judged => judged,
    }
}

/// The vault owner as a diary reader: the embedded and OKF exports' reader.
pub(super) fn owner_reader() -> Result<WriteActor> {
    Ok(WriteActor::new(
        crate::vault::embedded_owner_actor_id()?,
        EdgeActorClass::Human,
    ))
}
