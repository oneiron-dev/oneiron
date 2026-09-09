//! Vault CRUD for symbol manifests and the blame / definition / reference / PPR reads over them.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::decode_code_artifact_body;
use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::ppr::{
    SeedWeighting, flush_deferred_ppr_cache_writes, ppr_query_in_txn_with_vad_deferred_cache,
};
use crate::registry::{ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CODE_SYMBOL};
use crate::store::Store;
use crate::temporal::TimeRange;

use super::codec::{
    decode_code_symbol_manifest, encode_code_symbol_entity_body, encode_code_symbol_manifest,
};
use super::keys::{
    CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX, code_symbol_entity_id, code_symbol_manifest_key,
    code_symbol_revision_index_key, code_symbol_revision_index_prefix, delete_index_rows_for_id,
    id_from_index_key,
};
use super::text_diff::symbol_line_range;
use super::types::{
    CODE_SYMBOL_FINGERPRINT_LEN, CODE_SYMBOL_NAME_MAX_BYTES, CodeChunk, CodeEmbeddingVector,
    CodeSymbolBlame, CodeSymbolDefinition, CodeSymbolGraph, CodeSymbolManifest, CodeSymbolRevision,
};
use super::validate::{
    scan_code_symbol_manifest_metadata, validate_code_symbol_graph_edge,
    validate_code_symbol_manifest, validate_manifest_path, validate_text,
};

impl Vault {
    pub fn put_code_symbol_manifest(
        &self,
        code_artifact_id: &EntityId,
        manifest: &CodeSymbolManifest,
    ) -> Result<()> {
        validate_code_symbol_manifest(manifest)?;
        scan_code_symbol_manifest_metadata(manifest)?;
        let encoded = encode_code_symbol_manifest(manifest)?;
        let mut wtxn = self.store.env.write_txn()?;
        validate_code_artifact_target(&self.store, &wtxn, code_artifact_id, &manifest.repo_ref)?;

        delete_code_symbol_manifest_in_txn(&self.store, &mut wtxn, code_artifact_id)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &code_symbol_manifest_key(code_artifact_id),
            &encoded,
        )?;
        for symbol in &manifest.symbols {
            self.store.vault_meta.put(
                &mut wtxn,
                &code_symbol_revision_index_key(
                    &manifest.repo_ref,
                    &symbol.path,
                    &symbol.name,
                    &symbol.fingerprint,
                    code_artifact_id,
                ),
                &[],
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    pub fn put_code_symbol_graph(
        &self,
        code_artifact_id: &EntityId,
        graph: &CodeSymbolGraph,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        validate_code_symbol_manifest(&graph.manifest)?;
        scan_code_symbol_manifest_metadata(&graph.manifest)?;
        {
            let rtxn = self.store.env.read_txn()?;
            validate_code_artifact_target(
                &self.store,
                &rtxn,
                code_artifact_id,
                &graph.manifest.repo_ref,
            )?;
        }

        let mut batch = self.batch();
        let mut symbol_ids = BTreeSet::new();
        for symbol in &graph.manifest.symbols {
            let symbol_id = code_symbol_entity_id(&graph.manifest.repo_ref, symbol)?;
            symbol_ids.insert(symbol_id);
            let (start_line, end_line) = symbol_line_range(symbol, &graph.manifest.chunks)?;
            let body = encode_code_symbol_entity_body(
                &graph.manifest.repo_ref,
                symbol,
                start_line,
                end_line,
            )?;
            batch = batch
                .put(
                    &symbol_id,
                    ENTITY_TYPE_CODE_SYMBOL,
                    occurred,
                    learned_at,
                    &body,
                )
                .edge(&symbol_id, EdgeKind::PartOf, code_artifact_id, 1.0);
        }
        for edge in &graph.edges {
            validate_code_symbol_graph_edge(edge)?;
            if symbol_ids.contains(&edge.source) && symbol_ids.contains(&edge.target) {
                batch = batch.edge(&edge.source, edge.kind, &edge.target, edge.weight);
            }
        }
        batch.commit()?;
        self.put_code_symbol_manifest(code_artifact_id, &graph.manifest)
    }

    pub fn put_code_symbol_embedding_vectors(
        &self,
        embeddings: &[CodeEmbeddingVector],
    ) -> Result<()> {
        let mut batch = self.batch();
        for embedding in embeddings {
            batch = batch.vector(&embedding.entity_id, &embedding.vector);
        }
        batch.commit()
    }

    pub fn get_code_symbol_manifest(
        &self,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodeSymbolManifest>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &code_symbol_manifest_key(code_artifact_id))?
        else {
            return Ok(None);
        };
        let manifest = decode_code_symbol_manifest(&raw)?;
        validate_code_artifact_target(&self.store, &rtxn, code_artifact_id, &manifest.repo_ref)?;
        Ok(Some(manifest))
    }

    pub fn code_symbol_blame(
        &self,
        code_artifact_id: &EntityId,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Option<CodeSymbolBlame>> {
        validate_manifest_path(path)?;
        validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let Some(manifest) = self.get_code_symbol_manifest(code_artifact_id)? else {
            return Ok(None);
        };
        Ok(manifest
            .symbols
            .iter()
            .find(|symbol| {
                symbol.path == path && symbol.name == name && &symbol.fingerprint == fingerprint
            })
            .map(|symbol| CodeSymbolBlame {
                code_artifact_id: *code_artifact_id,
                provenance_claim_id: symbol.provenance_claim_id,
                source_session: symbol.source_session.clone(),
            }))
    }

    pub fn lookup_code_symbol_blame(
        &self,
        repo_ref: &RepoRef,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Option<CodeSymbolBlame>> {
        validate_manifest_path(path)?;
        validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let rtxn = self.store.env.read_txn()?;
        let prefix = code_symbol_revision_index_prefix(repo_ref, path, name, fingerprint);
        let mut result = None;
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = entry?;
            let id = id_from_index_key(&key, prefix.len(), "code symbol revision index key")?;
            match validate_code_artifact_entity_exists(&self.store, &rtxn, &id) {
                Ok(()) => {}
                Err(Error::EntityNotFound) => continue,
                Err(err) => return Err(err),
            }
            if let Some(raw) = self
                .store
                .vault_meta
                .get(&rtxn, &code_symbol_manifest_key(&id))?
            {
                let manifest = decode_code_symbol_manifest(&raw)?;
                if manifest.repo_ref != *repo_ref {
                    return Err(Error::InvalidCodeSymbolManifestBody(
                        "symbol revision index repo_ref does not match manifest",
                    ));
                }
                validate_code_artifact_target(&self.store, &rtxn, &id, &manifest.repo_ref)?;
                if let Some(symbol) = manifest.symbols.iter().find(|symbol| {
                    symbol.path == path && symbol.name == name && &symbol.fingerprint == fingerprint
                }) {
                    result = Some(CodeSymbolBlame {
                        code_artifact_id: id,
                        provenance_claim_id: symbol.provenance_claim_id,
                        source_session: symbol.source_session.clone(),
                    });
                }
            }
        }
        Ok(result)
    }

    pub fn code_symbol_definitions(
        &self,
        code_artifact_id: &EntityId,
        name: &str,
    ) -> Result<Vec<CodeSymbolDefinition>> {
        validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let Some(manifest) = self.get_code_symbol_manifest(code_artifact_id)? else {
            return Ok(Vec::new());
        };
        manifest
            .symbols
            .iter()
            .filter(|symbol| symbol.name == name)
            .map(|symbol| code_symbol_definition(&manifest.repo_ref, symbol, &manifest.chunks))
            .collect()
    }

    pub fn code_symbol_references(
        &self,
        code_artifact_id: &EntityId,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Vec<EntityId>> {
        let Some(definition) =
            self.code_symbol_definition_by_identity(code_artifact_id, path, name, fingerprint)?
        else {
            return Ok(Vec::new());
        };
        self.sources(&definition.entity_id, EdgeKind::Mentions, None)
    }

    pub fn code_symbol_callers(
        &self,
        code_artifact_id: &EntityId,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Vec<EntityId>> {
        let Some(definition) =
            self.code_symbol_definition_by_identity(code_artifact_id, path, name, fingerprint)?
        else {
            return Ok(Vec::new());
        };
        self.sources(
            &definition.entity_id,
            EdgeKind::Mentions,
            Some(ENTITY_TYPE_CODE_SYMBOL),
        )
    }

    pub fn code_symbol_ppr_neighbors(
        &self,
        code_artifact_id: &EntityId,
        seed_name: &str,
        depth: u32,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        crate::config::validate_ppr_vad_alpha(self.config.ppr_vad_alpha)?;
        let definitions = self.code_symbol_definitions(code_artifact_id, seed_name)?;
        if definitions.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let seeds = definitions
            .iter()
            .map(|definition| definition.entity_id)
            .collect::<Vec<_>>();
        let rtxn = self.store.env.read_txn()?;
        let (scores, deferred) = ppr_query_in_txn_with_vad_deferred_cache(
            &self.store,
            &rtxn,
            &seeds,
            depth,
            0.15,
            self.config.ppr_vad_alpha,
            SeedWeighting::Specificity,
        )?;
        let mut filtered = Vec::new();
        for score in scores {
            if entity_type_in_txn(&self.store, &rtxn, &score.id)? == Some(ENTITY_TYPE_CODE_SYMBOL) {
                filtered.push(score);
                if filtered.len() == limit {
                    break;
                }
            }
        }
        drop(rtxn);
        if let Some(write) = deferred {
            flush_deferred_ppr_cache_writes(&self.store, &[write])?;
        }
        Ok(filtered)
    }

    fn code_symbol_definition_by_identity(
        &self,
        code_artifact_id: &EntityId,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Option<CodeSymbolDefinition>> {
        validate_manifest_path(path)?;
        validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let Some(manifest) = self.get_code_symbol_manifest(code_artifact_id)? else {
            return Ok(None);
        };
        manifest
            .symbols
            .iter()
            .find(|symbol| {
                symbol.path == path && symbol.name == name && &symbol.fingerprint == fingerprint
            })
            .map(|symbol| code_symbol_definition(&manifest.repo_ref, symbol, &manifest.chunks))
            .transpose()
    }
}

fn code_symbol_definition(
    repo_ref: &RepoRef,
    symbol: &CodeSymbolRevision,
    chunks: &[CodeChunk],
) -> Result<CodeSymbolDefinition> {
    let (start_line, end_line) = symbol_line_range(symbol, chunks)?;
    Ok(CodeSymbolDefinition {
        entity_id: code_symbol_entity_id(repo_ref, symbol)?,
        path: symbol.path.clone(),
        name: symbol.name.clone(),
        kind: symbol.kind.clone(),
        fingerprint: symbol.fingerprint,
        start_line,
        end_line,
    })
}

/// Applies an EXPLICIT, already-reviewed rename/copy anchor mapping
/// (ARCH-0050 R6 L2 / ONE-1608).
///
/// Called only AFTER rename/copy detection has produced a reviewed mapping.
/// It infers nothing from paths or fingerprints, and nothing upstream of it
/// does either: `code_symbol_entity_id`, manifest decoding, fingerprint
/// generation, chunking, and symbol-graph ingestion carry no path-based
/// auto-transfer. Attachment identity moves ONLY through this door.
pub fn apply_code_symbol_anchor_transfer(
    store: &Store,
    txn: &mut RwTxn<'_>,
    transfer: &crate::code_memory::AnchorTransfer,
) -> Result<crate::code_memory::AnchorTransferReceipt> {
    crate::code_memory::transfer_code_memory_anchor(store, txn, transfer)
}

pub(super) fn delete_code_symbol_manifest_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let key = code_symbol_manifest_key(id);
    let Some(raw) = store
        .vault_meta
        .get(wtxn, &key)?
        .map(|value| value.to_vec())
    else {
        return Ok(false);
    };

    store.vault_meta.delete(wtxn, &key)?;
    match decode_code_symbol_manifest(&raw) {
        Ok(manifest) => {
            for symbol in &manifest.symbols {
                store.vault_meta.delete(
                    wtxn,
                    &code_symbol_revision_index_key(
                        &manifest.repo_ref,
                        &symbol.path,
                        &symbol.name,
                        &symbol.fingerprint,
                        id,
                    ),
                )?;
            }
        }
        Err(_) => {
            delete_index_rows_for_id(store, wtxn, CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX, id)?;
        }
    }
    Ok(true)
}

fn entity_type_in_txn(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

fn validate_code_artifact_target(
    store: &Store,
    rtxn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
    repo_ref: &RepoRef,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, code_artifact_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest target is not a CODE_ARTIFACT",
        ));
    }
    let artifact = decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let artifact_repo_ref = RepoRef::parse(&artifact.repo_ref).map_err(|_| {
        Error::InvalidCodeSymbolManifestBody("CODE artifact repo_ref must be a valid v1 repo_ref")
    })?;
    if &artifact_repo_ref != repo_ref {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest repo_ref must match CODE artifact repo_ref",
        ));
    }
    Ok(())
}

fn validate_code_artifact_entity_exists(
    store: &Store,
    rtxn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, code_artifact_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest target is not a CODE_ARTIFACT",
        ));
    }
    Ok(())
}
