//! Snapshot enumeration for whole-vault export. No raw bytes leave this module
//! except as input to the serializer's mandatory credential-nulling transform.
use std::collections::{BTreeMap, BTreeSet};

use super::{
    ArchiveSecretCustody, ExportAdapterDescriptor, ExportDiaryHold, ExportDiaryLedger, ExportDiaryRead, ExportEdge,
    ExportManifest, ExportSecretsNulledManifest, WholeVaultExport,
    whole_vault_export_excludes_entity,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::CallerLocality;
use crate::edge::parse_strict_edge_record;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::vault::live_entity_row_in_txn;

pub(crate) struct ExportSnapshot {
    pub(crate) entities: Vec<ExportSnapshotEntity>,
    pub(crate) edges: Vec<ExportEdge>,
    pub(crate) adapters: Vec<ExportAdapterDescriptor>,
    pub(crate) storage: ExportManifest,
    pub(crate) exported_at: u64,
    pub(crate) skill_packages: BTreeMap<EntityId, crate::skill_hub::HubPackage>,
    pub(crate) agent_fork_hashes: BTreeMap<EntityId, String>,
    pub(crate) pack_sources: BTreeMap<EntityId, crate::skill_hub::pack_catalog::PackSource>,
    pub(crate) task_receipts: BTreeMap<String, crate::receipt::ReceiptRecord>,
    pub(crate) archived_receipts: BTreeMap<EntityId, BTreeMap<String, super::ExportReceiptSource>>,
    pub(crate) run_results: Vec<ExportSnapshotRun>,
    pub(crate) result_bodies: BTreeMap<[u8; 32], ExportSnapshotBody>,
    pub(crate) diary_reads: Vec<ExportDiaryRead>,
    pub(crate) diary_holds: Vec<ExportDiaryHold>,
    pub(crate) secrets: Vec<ArchiveSecretCustody>,
}

/// One run's result manifests, as its replay record names them.
pub(crate) struct ExportSnapshotRun {
    pub(crate) run_id: EntityId,
    pub(crate) outputs: Vec<crate::code_run::CodeRunRawOutput>,
}

/// One result body: its bytes, or why the egress door withholds them.
pub(crate) struct ExportSnapshotBody {
    pub(crate) bytes: u64,
    pub(crate) body: std::result::Result<Vec<u8>, &'static str>,
}

pub(crate) struct ExportSnapshotEntity {
    pub(crate) id: EntityId,
    pub(crate) short_ref: Option<String>,
    pub(crate) header: EntityMetadataHeader,
    pub(crate) body: Vec<u8>,
    pub(crate) tainted: bool,
}

impl Vault {
    /// Exports all live base entities and their graph as the whole-vault
    /// archive (OF-222), not a retrieval selection. Live off-record overlay
    /// rows, deleted shells, archive tombstones, credential custody rows and
    /// unpublished LFS chunks are excluded. No caller can disable nulling.
    pub fn export_whole_vault(&self) -> Result<WholeVaultExport> {
        self.export_whole_vault_with_admission(CallerLocality::OnDevice, |_| Ok(()))
    }

    /// The archive of exactly `records` and the graph between them, for a
    /// reader off this device: an export-first removal's export (OF-163),
    /// in the same shape as a whole-vault archive and re-importable alike.
    /// No run's results go with it; a run names no world to scope it by.
    pub(crate) fn export_records_archive(
        &self,
        records: &BTreeSet<EntityId>,
    ) -> Result<WholeVaultExport> {
        self.export_archive_snapshot(CallerLocality::OffDevice, Some(records), |_| Ok(()))
    }

    /// The actor facade supplies an owner admission evaluated in the SAME
    /// snapshot as the rows. The host-level Vault export retains its existing
    /// direct door; transport callers must use the admitted memory facade.
    /// For a caller off this device the snapshot holds no row a device-local
    /// world keeps here (DEC-0005), so no edge, package or receipt of one
    /// follows; one whose world cannot be read stays too.
    pub(crate) fn export_whole_vault_with_admission<E: From<Error>>(
        &self,
        locality: CallerLocality,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<WholeVaultExport, E> {
        self.export_archive_snapshot(locality, None, admit)
    }

    fn export_archive_snapshot<E: From<Error>>(
        &self,
        locality: CallerLocality,
        only: Option<&BTreeSet<EntityId>>,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<WholeVaultExport, E> {
        let artifact = self.whole_vault_export_manifest_artifact(
            ExportSecretsNulledManifest::from_redacted(false),
        )?;
        let storage = ExportManifest::from_json_for_import(artifact.bytes())?;
        let rtxn = self.store.env.read_txn().map_err(Error::from)?;
        admit(&rtxn)?;
        // A run names no world, so a caller off this device gets no run's
        // results: none of a device-local world's may leave it (DEC-0005).
        let (run_results, result_bodies) = if locality == CallerLocality::OnDevice && only.is_none()
        {
            self.export_run_results_in_txn(&rtxn)?
        } else {
            (Vec::new(), BTreeMap::new())
        };
        let device_only = crate::settings::device_local_worlds_at(self, &rtxn, locality)?;
        let mut entities = Vec::new();
        let mut included = BTreeSet::new();
        let mut skill_packages = BTreeMap::new();
        let mut agent_fork_hashes = BTreeMap::new();
        let mut task_receipts = BTreeMap::new();
        let mut archived_receipts = BTreeMap::new();
        let mut diaries = ExportDiaryLedger::default();
        let mut secrets = Vec::new();
        for entry in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &rtxn)? {
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
                    && live_entity_row_in_txn(&self.store, &rtxn, &id)?.is_live()
                    && let Some(secret) =
                        archive_custody_secret(&id, &raw[ENTITY_METADATA_HEADER_LEN..], locality)?
                {
                    secrets.push(secret);
                }
                continue;
            }
            if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                &self.store,
                &rtxn,
                &id,
                header.entity_type,
            )? || !live_entity_row_in_txn(&self.store, &rtxn, &id)?.is_live()
            {
                continue;
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_ASSET
                && crate::receipt::is_receipt_archive_source(&raw[ENTITY_METADATA_HEADER_LEN..])
            {
                continue;
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_ASSET
                && crate::skill_hub::decode_source_carrier(&raw[ENTITY_METADATA_HEADER_LEN..])?
                    .is_some()
            {
                continue;
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_ASSET
                && !crate::agent_def::birth_source_exportable(
                    &self.store,
                    &rtxn,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )?
            {
                continue;
            }
            // OF-490: a diary goes out only as a read the owner's grant
            // covers and its agent has not asked to review first.
            if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                && let Some(author) =
                    note_diary_author(self, &rtxn, &id, &raw[ENTITY_METADATA_HEADER_LEN..])?
                && !diaries.admit(self, &rtxn, author)?
            {
                continue;
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_SKILL
                && let Some(package) = self.export_hub_package_in_txn(&rtxn, &id)?
            {
                let record = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                if record.content_hash != Some(package.content_hash()?) {
                    return Err(Error::CorruptedIndex("stored skill package identity drift").into());
                }
                skill_packages.insert(id, package);
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
            if !tainted
                && header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && let Ok(claim) =
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
            {
                archived_receipts.insert(
                    id,
                    crate::receipt::archived_receipt_sources_in_txn(&self.store, &rtxn, &id)?,
                );
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
            // The entity-document head owns committed text after migration or
            // stream finalization; the row then holds only a pointer. Project
            // it under this snapshot transaction before the NOTE-specific
            // document and the serializer's unconditional credential nulling.
            // In base mode there are no EntityDoc heads to resolve.
            #[cfg(feature = "sync")]
            let resolved = crate::entity_doc::resolve_record_body(
                &self.store,
                &rtxn,
                &id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
            #[cfg(feature = "sync")]
            let body = resolved.as_slice();
            #[cfg(not(feature = "sync"))]
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            // Historical/archive-only NOTE rows may intentionally carry a
            // different body. Only the NOTE codec's live rows use its editor.
            let body = if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                && crate::note::decode_note_body_using(body, crate::note::NoteKind::wire).is_ok()
            {
                crate::note::live_body_in_txn(&self.store, &rtxn, &id, header.entity_type, body)?
            } else {
                std::borrow::Cow::Borrowed(body)
            };
            entities.push(ExportSnapshotEntity {
                id,
                short_ref,
                header,
                body: body.into_owned(),
                tainted,
            });
        }
        let mut edges = Vec::new();
        for entry in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&self.store, &rtxn)? {
            let (key, value) = entry?;
            let edge = parse_strict_edge_record(&key, &value)?;
            if !included.contains(&edge.source) || !included.contains(&edge.target) {
                continue;
            }
            edges.push(ExportEdge {
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
            });
        }
        let adapters = crate::ingest::INGEST_SOURCE_REGISTRY
            .source_configs()
            .map(|config| ExportAdapterDescriptor {
                source_id: config.source_id.to_owned(),
                adapter_skill_id: config.adapter_skill.map(|a| a.skill_id.to_owned()),
                adapter_version: config.adapter_skill.map(|a| a.version.to_owned()),
            })
            .collect();
        let pack_sources = self
            .pack_sources_in_txn(&rtxn)?
            .into_iter()
            .filter(|(id, _)| included.contains(id))
            .collect();
        drop(rtxn);
        let (diary_reads, diary_holds) = diaries.finish();
        crate::serialize::serialize_vault_snapshot(ExportSnapshot {
            entities,
            edges,
            adapters,
            storage,
            exported_at: crate::unix_seconds_now(),
            skill_packages,
            agent_fork_hashes,
            pack_sources,
            task_receipts,
            archived_receipts,
            run_results,
            result_bodies,
            diary_reads,
            diary_holds,
            secrets,
        })
        .map_err(E::from)
    }

    /// The run result closure (OF-190 B++): every run's manifests, and each
    /// body they name once, through the egress door. A body no row holds
    /// any longer is withheld as absent.
    fn export_run_results_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<(
        Vec<ExportSnapshotRun>,
        BTreeMap<[u8; 32], ExportSnapshotBody>,
    )> {
        let mut runs = Vec::new();
        let mut bodies = BTreeMap::new();
        for (run_id, outputs) in self.code_run_result_manifests_in_txn(rtxn)? {
            for output in &outputs {
                if bodies.contains_key(&output.raw_blake3) {
                    continue;
                }
                let body = match super::whole_vault_export_withholds_result(self, rtxn, output)? {
                    Some(reason) => Err(reason),
                    None => self
                        .code_run_result_body_in_txn(rtxn, output)?
                        .ok_or("absent"),
                };
                bodies.insert(
                    output.raw_blake3,
                    ExportSnapshotBody {
                        bytes: output.raw_len,
                        body,
                    },
                );
            }
            runs.push(ExportSnapshotRun { run_id, outputs });
        }
        Ok((runs, bodies))
    }
}

/// The author of a NOTE row when it is a diary, read from its committed text.
fn note_diary_author(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<EntityId>> {
    #[cfg(feature = "sync")]
    let body = crate::entity_doc::resolve_record_body(&vault.store, rtxn, id, body)?;
    #[cfg(not(feature = "sync"))]
    let _ = (vault, rtxn, id);
    Ok(super::diary_author(&body))
}

/// A custody record as an archive row, when this export carries it: an
/// active record, and for a caller off this device only a portable one (a
/// device-bound value never leaves this device, DEC-0005).
fn archive_custody_secret(
    id: &EntityId,
    body: &[u8],
    locality: CallerLocality,
) -> Result<Option<ArchiveSecretCustody>> {
    use base64::Engine as _;
    use crate::secret_custody::{CustodyClass, SecretCustodyStatus};
    let record = crate::secret_custody::decode_secret_custody_body(body)?;
    if record.status != SecretCustodyStatus::Active
        || (locality != CallerLocality::OnDevice
            && (record.device_only || record.class != CustodyClass::CustodyPortable))
    {
        return Ok(None);
    }
    Ok(Some(ArchiveSecretCustody {
        id: id.to_hex(),
        name: record.name.clone(),
        body: base64::engine::general_purpose::STANDARD.encode(body),
    }))
}
