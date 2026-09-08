//! Legacy buffer-oriented NapiVault binding and all its verbs.

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use oneiron::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, RepoRef, TimeRange, Vault,
    VaultConfig,
};

use super::boundary::{
    DEFAULT_NAPI_SEARCH_LIMIT, entity_ids_to_buffers, parse_created_at, parse_edge_kind,
    parse_entity_id, parse_search_limit, parse_u8, to_napi_err, ts_to_u64, validate_batch_size,
    validate_dimensions, validate_entity_payload_len, validate_query_len, validate_vector_len,
};
use super::codebase::{
    apply_codebase_context_filters, apply_codebase_filters, core_codebase_snapshot,
    napi_codebase_snapshot,
};
use super::email::{core_email_adapter, core_email_inbound};
use super::types::{
    NapiBatchEntity, NapiCodebaseSnapshot, NapiEdgeInfo, NapiEmailIdentityAdapterConfig,
    NapiEmailInboundEvent, NapiScoredEntity, NapiSubtreeEntry,
};

/// Node.js binding for the Oneiron Vault.
#[napi]
pub struct NapiVault {
    vault: Arc<Vault>,
    dimensions: usize,
}

#[napi]
impl NapiVault {
    /// Open or create a vault at the given filesystem path.
    ///
    /// `dimensions` controls the embedding vector size (default: 1024 for device preset).
    ///
    /// `dictSearchPaths` lists directories searched at open time for
    /// per-language analyzer dictionaries (e.g. `ja/system.dic`,
    /// `ko/` containing `metadata.json`, `zh/jieba.dict.utf8`). On iOS,
    /// pass the bundle path (`Bundle.main.resourcePath + "/oneiron-dicts"`).
    /// When a language's dict is absent, oneiron falls back to a Portable
    /// (ICU4X + n-gram) analyzer for that language.
    #[napi(constructor)]
    pub fn new(
        path: String,
        dimensions: Option<u32>,
        dict_search_paths: Option<Vec<String>>,
    ) -> napi::Result<Self> {
        let mut config = VaultConfig::device();
        if let Some(dims) = dimensions {
            config.dimensions = dims as usize;
        }
        if let Some(paths) = dict_search_paths {
            config.dict_search_paths = paths.into_iter().map(std::path::PathBuf::from).collect();
        }

        validate_dimensions(config.dimensions).map_err(napi::Error::from_reason)?;
        let dimensions = config.dimensions;
        let vault = Vault::open(&path, config).map_err(to_napi_err)?;
        Ok(Self {
            vault: Arc::new(vault),
            dimensions,
        })
    }

    // ─── Entity CRUD ───────────────────────────────────────────

    /// Store an entity blob.
    #[napi]
    pub fn put_entity(
        &self,
        id: Buffer,
        entity_type: u32,
        occurred_start: i64,
        occurred_end: i64,
        learned_at: i64,
        data: Buffer,
    ) -> napi::Result<()> {
        let eid = parse_entity_id(&id)?;
        let etype = parse_u8(entity_type, "entity_type")?;
        validate_entity_payload_len(data.len()).map_err(napi::Error::from_reason)?;
        self.vault
            .put_entity(
                &eid,
                etype,
                TimeRange {
                    start: ts_to_u64(occurred_start),
                    end: ts_to_u64(occurred_end),
                },
                ts_to_u64(learned_at),
                data.as_ref(),
            )
            .map_err(to_napi_err)
    }

    /// Retrieve an entity blob by ID. Returns null if not found.
    #[napi]
    pub fn get_entity(&self, id: Buffer) -> napi::Result<Option<Buffer>> {
        let eid = parse_entity_id(&id)?;
        self.vault
            .get(&eid)
            .map(|opt| opt.map(std::convert::Into::into))
            .map_err(to_napi_err)
    }

    /// Delete an entity by ID. Returns true if the entity existed.
    #[napi]
    pub fn delete_entity(&self, id: Buffer) -> napi::Result<bool> {
        let eid = parse_entity_id(&id)?;
        self.vault.delete_entity(&eid).map_err(to_napi_err)
    }

    /// Check whether an entity exists in the vault.
    #[napi]
    pub fn entity_exists(&self, id: Buffer) -> napi::Result<bool> {
        let eid = parse_entity_id(&id)?;
        self.vault.entity_exists(&eid).map_err(to_napi_err)
    }

    // ─── Edges ─────────────────────────────────────────────────

    /// Store a directed edge between two entities.
    #[napi]
    pub fn put_edge(&self, src: Buffer, kind: u32, tgt: Buffer, weight: f64) -> napi::Result<()> {
        let src_id = parse_entity_id(&src)?;
        let tgt_id = parse_entity_id(&tgt)?;
        let edge_kind = parse_edge_kind(kind)?;
        self.vault
            .put_edge(&src_id, edge_kind, &tgt_id, weight as f32)
            .map_err(to_napi_err)
    }

    /// Return outbound edges for a source entity.
    #[napi]
    pub fn edges_out(&self, src: Buffer) -> napi::Result<Vec<NapiEdgeInfo>> {
        let src_id = parse_entity_id(&src)?;
        let edges = self.vault.edges_out(&src_id).map_err(to_napi_err)?;
        let mut out = Vec::with_capacity(edges.len());
        for e in edges {
            let vad = e.vad;
            out.push(NapiEdgeInfo {
                src: Buffer::from(src_id.as_bytes().as_slice()),
                kind: e.kind as u32,
                tgt: Buffer::from(e.target.as_bytes().as_slice()),
                weight: e.weight as f64,
                created_at: parse_created_at(e.created_at).map_err(napi::Error::from_reason)?,
                valence: vad.map(|v| v.valence as f64),
                arousal: vad.map(|v| v.arousal as f64),
                dominance: vad.map(|v| v.dominance as f64),
            });
        }
        Ok(out)
    }

    /// Return inbound edges for a target entity.
    #[napi]
    pub fn edges_in(&self, tgt: Buffer) -> napi::Result<Vec<NapiEdgeInfo>> {
        let tgt_id = parse_entity_id(&tgt)?;
        let edges = self.vault.edges_in(&tgt_id).map_err(to_napi_err)?;
        let mut out = Vec::with_capacity(edges.len());
        for e in edges {
            let vad = e.vad;
            out.push(NapiEdgeInfo {
                src: Buffer::from(e.target.as_bytes().as_slice()),
                kind: e.kind as u32,
                tgt: Buffer::from(tgt_id.as_bytes().as_slice()),
                weight: e.weight as f64,
                created_at: parse_created_at(e.created_at).map_err(napi::Error::from_reason)?,
                valence: vad.map(|v| v.valence as f64),
                arousal: vad.map(|v| v.arousal as f64),
                dominance: vad.map(|v| v.dominance as f64),
            });
        }
        Ok(out)
    }

    // ─── Search ────────────────────────────────────────────────

    /// Search for entities by vector similarity (cosine distance via HNSW).
    #[napi]
    pub fn search_vector(
        &self,
        query: Vec<f64>,
        limit: u32,
    ) -> napi::Result<Vec<NapiScoredEntity>> {
        let limit = parse_search_limit(limit).map_err(napi::Error::from_reason)?;
        validate_vector_len(query.len(), self.dimensions, "query vector")
            .map_err(napi::Error::from_reason)?;
        let f32_query: Vec<f32> = query.iter().map(|&v| v as f32).collect();
        let results = self
            .vault
            .search_vector(&f32_query, limit)
            .map_err(to_napi_err)?;
        Ok(results
            .into_iter()
            .map(|s| NapiScoredEntity {
                id: Buffer::from(s.id.as_bytes().as_slice()),
                score: s.score as f64,
            })
            .collect())
    }

    /// Search for entities by BM25 text matching.
    #[napi]
    pub fn search_text(&self, query: String, limit: u32) -> napi::Result<Vec<NapiScoredEntity>> {
        validate_query_len(&query).map_err(napi::Error::from_reason)?;
        let limit = parse_search_limit(limit).map_err(napi::Error::from_reason)?;
        let results = self.vault.search_text(&query, limit).map_err(to_napi_err)?;
        Ok(results
            .into_iter()
            .map(|s| NapiScoredEntity {
                id: Buffer::from(s.id.as_bytes().as_slice()),
                score: s.score as f64,
            })
            .collect())
    }

    /// Search for entities by BM25 text matching, scoped to codebase metadata.
    #[napi]
    pub fn search_text_scoped(
        &self,
        query: String,
        limit: u32,
        repo_ref: Option<String>,
        project_id: Option<String>,
    ) -> napi::Result<Vec<NapiScoredEntity>> {
        validate_query_len(&query).map_err(napi::Error::from_reason)?;
        let limit = parse_search_limit(limit).map_err(napi::Error::from_reason)?;
        let builder = self.vault.query().search_text(&query, limit).limit(limit);
        let results = apply_codebase_filters(builder, repo_ref, project_id)?
            .run()
            .map_err(to_napi_err)?;
        Ok(results
            .into_iter()
            .map(|s| NapiScoredEntity {
                id: Buffer::from(s.id.as_bytes().as_slice()),
                score: s.score as f64,
            })
            .collect())
    }

    // ─── Vectors ───────────────────────────────────────────────

    /// Store a vector embedding for an entity.
    #[napi]
    pub fn put_vector(&self, id: Buffer, vector: Vec<f64>) -> napi::Result<()> {
        let eid = parse_entity_id(&id)?;
        validate_vector_len(vector.len(), self.dimensions, "vector")
            .map_err(napi::Error::from_reason)?;
        let f32_vec: Vec<f32> = vector.iter().map(|&v| v as f32).collect();
        self.vault.put_vector(&eid, &f32_vec).map_err(to_napi_err)
    }

    // ─── Codebase Metadata ─────────────────────────────────────

    /// Attach or replace codebase snapshot metadata for a CODE_ARTIFACT entity.
    #[napi]
    pub fn put_codebase_snapshot(
        &self,
        id: Buffer,
        snapshot: NapiCodebaseSnapshot,
    ) -> napi::Result<()> {
        let eid = parse_entity_id(&id)?;
        // Take the bodies before conversion consumes the boundary struct, so
        // custody filtering can hash-check each declared entry.
        let file_count = snapshot.files.len();
        let contents = snapshot
            .files
            .iter()
            .filter_map(|entry| {
                entry
                    .content
                    .as_ref()
                    .map(|bytes| (entry.path.clone(), bytes.to_vec()))
            })
            .collect::<std::collections::HashMap<String, Vec<u8>>>();
        let snapshot = core_codebase_snapshot(snapshot).map_err(napi::Error::from_reason)?;
        // Without any content every entry would quarantine, silently replacing a
        // prior snapshot with an empty manifest. Refuse before touching storage.
        if file_count > 0 && contents.is_empty() {
            return Err(napi::Error::from_reason(
                "codebase snapshot file contents required; refusing all-quarantine empty-manifest persist",
            ));
        }
        self.vault
            .put_codebase_snapshot(&eid, &snapshot, &move |path: &str| {
                contents.get(path).cloned()
            })
            .map_err(to_napi_err)
    }

    /// Read codebase snapshot metadata for a CODE_ARTIFACT entity.
    #[napi]
    pub fn get_codebase_snapshot(&self, id: Buffer) -> napi::Result<Option<NapiCodebaseSnapshot>> {
        let eid = parse_entity_id(&id)?;
        self.vault
            .get_codebase_snapshot(&eid)
            .map_err(to_napi_err)?
            .map(napi_codebase_snapshot)
            .transpose()
            .map_err(napi::Error::from_reason)
    }

    /// Return CODE_ARTIFACT ids whose snapshot uses the given repo_ref.
    #[napi]
    pub fn codebase_snapshots_by_repo_ref(&self, repo_ref: String) -> napi::Result<Vec<Buffer>> {
        let repo_ref = RepoRef::parse(&repo_ref).map_err(to_napi_err)?;
        let ids = self
            .vault
            .codebase_snapshots_by_repo_ref(&repo_ref)
            .map_err(to_napi_err)?;
        Ok(entity_ids_to_buffers(ids))
    }

    /// Return CODE_ARTIFACT ids whose snapshot uses the given project id.
    #[napi]
    pub fn codebase_snapshots_by_project_id(
        &self,
        project_id: String,
    ) -> napi::Result<Vec<Buffer>> {
        let ids = self
            .vault
            .codebase_snapshots_by_project_id(&project_id)
            .map_err(to_napi_err)?;
        Ok(entity_ids_to_buffers(ids))
    }

    // ─── Context Pack ──────────────────────────────────────────

    /// Run a context pack query. Returns serialized output as a string.
    ///
    /// Options:
    /// - `query_text`: Text search query
    /// - `query_vector`: Vector search query (f64 array)
    /// - `limit`: Max number of results (default: 10)
    /// - `format`: Output format — "json", "yaml", "toon", "markdown", "plaintext" (default: "json")
    #[napi]
    pub fn context_pack(
        &self,
        query_text: Option<String>,
        query_vector: Option<Vec<f64>>,
        limit: Option<u32>,
        format: Option<String>,
    ) -> napi::Result<String> {
        let limit = parse_search_limit(limit.unwrap_or(DEFAULT_NAPI_SEARCH_LIMIT))
            .map_err(napi::Error::from_reason)?;
        let pack_format = match format.as_deref() {
            Some("yaml") => oneiron::PackFormat::Yaml,
            Some("toon") => oneiron::PackFormat::Toon,
            Some("markdown") => oneiron::PackFormat::Markdown,
            Some("plaintext") => oneiron::PackFormat::Plaintext,
            // Lenient default: unrecognized or missing format falls back to JSON
            _ => oneiron::PackFormat::Json,
        };

        let mut builder = self.vault.context_pack().format(pack_format).limit(limit);

        if let Some(text) = &query_text {
            validate_query_len(text).map_err(napi::Error::from_reason)?;
            builder = builder.search_text(text, limit);
        }

        if let Some(vec) = &query_vector {
            validate_vector_len(vec.len(), self.dimensions, "query vector")
                .map_err(napi::Error::from_reason)?;
            let f32_vec: Vec<f32> = vec.iter().map(|&v| v as f32).collect();
            builder = builder.search_vector(&f32_vec, limit);
        }

        let output = builder.run_serialized().map_err(to_napi_err)?;
        String::from_utf8(output)
            .map_err(|e| napi::Error::from_reason(format!("context pack output is not utf8: {e}")))
    }

    /// Run a context pack query scoped to codebase metadata.
    #[napi]
    pub fn context_pack_scoped(
        &self,
        query_text: Option<String>,
        query_vector: Option<Vec<f64>>,
        limit: Option<u32>,
        format: Option<String>,
        repo_ref: Option<String>,
        project_id: Option<String>,
    ) -> napi::Result<String> {
        let limit = parse_search_limit(limit.unwrap_or(DEFAULT_NAPI_SEARCH_LIMIT))
            .map_err(napi::Error::from_reason)?;
        let pack_format = match format.as_deref() {
            Some("yaml") => oneiron::PackFormat::Yaml,
            Some("toon") => oneiron::PackFormat::Toon,
            Some("markdown") => oneiron::PackFormat::Markdown,
            Some("plaintext") => oneiron::PackFormat::Plaintext,
            _ => oneiron::PackFormat::Json,
        };

        let mut builder = self.vault.context_pack().format(pack_format).limit(limit);

        if let Some(text) = &query_text {
            validate_query_len(text).map_err(napi::Error::from_reason)?;
            builder = builder.search_text(text, limit);
        }

        if let Some(vec) = &query_vector {
            validate_vector_len(vec.len(), self.dimensions, "query vector")
                .map_err(napi::Error::from_reason)?;
            let f32_vec: Vec<f32> = vec.iter().map(|&v| v as f32).collect();
            builder = builder.search_vector(&f32_vec, limit);
        }

        let output = apply_codebase_context_filters(builder, repo_ref, project_id)?
            .run_serialized()
            .map_err(to_napi_err)?;
        String::from_utf8(output)
            .map_err(|e| napi::Error::from_reason(format!("context pack output is not utf8: {e}")))
    }

    /// Parse and route inbound email webhook data, returning a route receipt JSON string.
    #[napi]
    pub fn route_email_inbound_surface_event(
        &self,
        config: NapiEmailIdentityAdapterConfig,
        inbound: NapiEmailInboundEvent,
    ) -> napi::Result<String> {
        let adapter = core_email_adapter(config)?;
        let input = adapter
            .parse_inbound(ChannelIdentityProviderInbound::Email(core_email_inbound(
                inbound,
            )))
            .map_err(to_napi_err)?;
        let receipt = self
            .vault
            .route_inbound_surface_event(input)
            .map_err(to_napi_err)?;
        serde_json::to_string(&receipt)
            .map_err(|e| napi::Error::from_reason(format!("surface route receipt json: {e}")))
    }

    // ─── Batch Writes ──────────────────────────────────────────

    /// Write multiple entities in a single atomic transaction.
    #[napi]
    pub fn batch_put_entities(&self, entities: Vec<NapiBatchEntity>) -> napi::Result<()> {
        validate_batch_size(entities.len()).map_err(napi::Error::from_reason)?;
        for e in &entities {
            validate_entity_payload_len(e.data.len()).map_err(napi::Error::from_reason)?;
        }

        let mut batch = self.vault.batch();

        for e in &entities {
            let eid = parse_entity_id(&e.id)?;
            let etype = parse_u8(e.entity_type, "entity_type")?;
            batch = batch.put(
                &eid,
                etype,
                TimeRange {
                    start: ts_to_u64(e.occurred_start),
                    end: ts_to_u64(e.occurred_end),
                },
                ts_to_u64(e.learned_at),
                e.data.as_ref(),
            );
        }

        batch.commit().map_err(to_napi_err)
    }

    // ─── Tree Queries ──────────────────────────────────────────

    /// Return the stored entity type for an entity, or null if not found.
    #[napi]
    pub fn get_entity_type(&self, id: Buffer) -> napi::Result<Option<u32>> {
        let eid = parse_entity_id(&id)?;
        self.vault
            .get_entity_type(&eid)
            .map(|opt| opt.map(u32::from))
            .map_err(to_napi_err)
    }

    /// Return all entity IDs of a given type.
    #[napi]
    pub fn entities_by_type(&self, entity_type: u32) -> napi::Result<Vec<Buffer>> {
        let etype = parse_u8(entity_type, "entity_type")?;
        let ids = self.vault.entities_by_type(etype).map_err(to_napi_err)?;
        Ok(entity_ids_to_buffers(ids))
    }

    /// Return outbound edge targets filtered by kind and optional target type.
    #[napi]
    pub fn targets(
        &self,
        src: Buffer,
        kind: u32,
        target_type: Option<u32>,
    ) -> napi::Result<Vec<Buffer>> {
        let src_id = parse_entity_id(&src)?;
        let edge_kind = parse_edge_kind(kind)?;
        let tgt_type = target_type
            .map(|t| parse_u8(t, "target_type"))
            .transpose()?;
        let ids = self
            .vault
            .targets(&src_id, edge_kind, tgt_type)
            .map_err(to_napi_err)?;
        Ok(entity_ids_to_buffers(ids))
    }

    /// Return inbound edge sources filtered by kind and optional source type.
    #[napi]
    pub fn sources(
        &self,
        tgt: Buffer,
        kind: u32,
        source_type: Option<u32>,
    ) -> napi::Result<Vec<Buffer>> {
        let tgt_id = parse_entity_id(&tgt)?;
        let edge_kind = parse_edge_kind(kind)?;
        let src_type = source_type
            .map(|t| parse_u8(t, "source_type"))
            .transpose()?;
        let ids = self
            .vault
            .sources(&tgt_id, edge_kind, src_type)
            .map_err(to_napi_err)?;
        Ok(entity_ids_to_buffers(ids))
    }

    /// Return subtree descendants via ChildOf traversal, limited to `max_depth`.
    #[napi]
    pub fn subtree(&self, root: Buffer, max_depth: u32) -> napi::Result<Vec<NapiSubtreeEntry>> {
        let root_id = parse_entity_id(&root)?;
        let entries = self
            .vault
            .subtree(&root_id, max_depth)
            .map_err(to_napi_err)?;
        Ok(entries
            .into_iter()
            .map(|(id, depth)| NapiSubtreeEntry {
                id: Buffer::from(id.as_bytes().as_slice()),
                depth,
            })
            .collect())
    }

    /// Walk ancestors via ChildOf edges. Uses visited set to prevent cycles.
    #[napi]
    pub fn ancestors(&self, node: Buffer) -> napi::Result<Vec<Buffer>> {
        let node_id = parse_entity_id(&node)?;
        let ids = self.vault.ancestors(&node_id).map_err(to_napi_err)?;
        Ok(entity_ids_to_buffers(ids))
    }

    /// Check whether making `target` a parent of `node` would create a cycle.
    #[napi]
    pub fn would_create_cycle(&self, node: Buffer, target: Buffer) -> napi::Result<bool> {
        let node_id = parse_entity_id(&node)?;
        let target_id = parse_entity_id(&target)?;
        self.vault
            .would_create_cycle(&node_id, &target_id)
            .map_err(to_napi_err)
    }
}
