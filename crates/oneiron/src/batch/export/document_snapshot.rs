//! Snapshot enumeration for whole-vault export. No raw bytes leave this module
//! except as input to the serializer's mandatory credential-nulling transform.
use std::collections::{BTreeMap, BTreeSet};

use super::{
    ExportAdapterDescriptor, ExportEdge, ExportManifest, ExportSecretsNulledManifest,
    WholeVaultExport, whole_vault_export_excludes_entity,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_pack::PackFormat;
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
}

pub(crate) struct ExportSnapshotEntity {
    pub(crate) id: EntityId,
    pub(crate) header: EntityMetadataHeader,
    pub(crate) body: Vec<u8>,
    pub(crate) tainted: bool,
}

impl Vault {
    /// Exports all live base entities and their graph, not a retrieval selection.
    /// Live off-record overlay rows, deleted shells, archive tombstones, and
    /// credential custody rows are excluded. No caller can disable nulling.
    pub fn export_whole_vault(&self, format: PackFormat) -> Result<WholeVaultExport> {
        let artifact = self.whole_vault_export_manifest_artifact(
            ExportSecretsNulledManifest::from_redacted(false),
        )?;
        let storage = ExportManifest::from_json_for_import(artifact.bytes())?;
        let rtxn = self.store.env.read_txn()?;
        let mut entities = Vec::new();
        let mut included = BTreeSet::new();
        let mut skill_packages = BTreeMap::new();
        let mut agent_fork_hashes = BTreeMap::new();
        let mut task_receipts = BTreeMap::new();
        for entry in self.store.entities.iter(&rtxn)? {
            let (key, raw) = entry?;
            let id = crate::entity_id::parse_entity_id(&key, "whole-vault entity id")?;
            if whole_vault_export_excludes_entity(self, &id)? {
                continue;
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("whole-vault entity header"))?;
            // Check the type BEFORE reading or transforming the custody body.
            if header.entity_type == ENTITY_TYPE_SECRET_CUSTODY
                || !live_entity_row_in_txn(&self.store, &rtxn, &id)?.is_live()
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
            if header.entity_type == crate::registry::ENTITY_TYPE_SKILL
                && let Some(package) = self.export_hub_package_in_txn(&rtxn, &id)?
            {
                let record = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                if record.content_hash != Some(package.content_hash()?) {
                    return Err(Error::CorruptedIndex("stored skill package identity drift"));
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
            entities.push(ExportSnapshotEntity {
                id,
                header,
                body: raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
                tainted,
            });
        }
        let mut edges = Vec::new();
        for entry in self.store.edges_out.iter(&rtxn)? {
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
        crate::serialize::serialize_vault_snapshot(
            ExportSnapshot {
                entities,
                edges,
                adapters,
                storage,
                exported_at: crate::unix_seconds_now(),
                skill_packages,
                agent_fork_hashes,
                pack_sources,
                task_receipts,
            },
            format,
        )
    }
}
