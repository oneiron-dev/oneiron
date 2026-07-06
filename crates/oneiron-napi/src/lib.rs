mod types;

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use oneiron::{
    CODEBASE_CONTENT_HASH_LEN, CODEBASE_FORK_HASH_LEN, CODEBASE_SCOPE_KEY_LEN,
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, CodebaseFileEntry,
    CodebaseSnapshot, DevEmailIdentityAdapter, DevEmailIdentityAdapterConfig, EdgeKind,
    EmailProviderInbound, EntityId, RepoRef, TimeRange, Vault, VaultConfig,
};

use types::{
    NapiBatchEntity, NapiCodebaseFileEntry, NapiCodebaseSnapshot, NapiEdgeInfo,
    NapiEmailIdentityAdapterConfig, NapiEmailInboundEvent, NapiScoredEntity, NapiSubtreeEntry,
};

const DEFAULT_NAPI_SEARCH_LIMIT: u32 = 10;
const MAX_NAPI_SEARCH_LIMIT: u32 = 1_000;
const MAX_NAPI_QUERY_BYTES: usize = 8 * 1024;
const MAX_NAPI_BATCH_ENTITIES: usize = 10_000;
const MAX_NAPI_CODEBASE_FILES: usize = 100_000;
const MAX_NAPI_DIMENSIONS: usize = 16_384;

type BoundaryResult<T> = std::result::Result<T, String>;

/// Convert an oneiron error to a napi error.
fn to_napi_err(e: oneiron::Error) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// Extract a 16-byte EntityId from a Buffer, returning a napi error if invalid.
fn parse_entity_id(buf: &Buffer) -> napi::Result<EntityId> {
    let bytes: [u8; 16] = buf
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("EntityId must be exactly 16 bytes"))?;
    EntityId::from_bytes(bytes).map_err(to_napi_err)
}

/// Convert a signed i64 timestamp to u64, clamping negatives to 0.
fn ts_to_u64(ts: i64) -> u64 {
    ts.max(0) as u64
}

/// Validate and narrow a u32 to u8, returning a descriptive error on overflow.
fn parse_u8(value: u32, label: &str) -> napi::Result<u8> {
    if value > u8::MAX as u32 {
        return Err(napi::Error::from_reason(format!(
            "{label} must be 0-255, got {value}"
        )));
    }
    Ok(value as u8)
}

/// Validate a u32 as an EdgeKind discriminant.
fn parse_edge_kind(kind: u32) -> napi::Result<EdgeKind> {
    let byte = parse_u8(kind, "edge kind")?;
    EdgeKind::try_from_u8(byte)
        .ok_or_else(|| napi::Error::from_reason(format!("invalid edge kind: {kind}")))
}

/// Validate and narrow a Rust timestamp before returning it to JS.
fn parse_created_at(created_at: u64) -> BoundaryResult<i64> {
    i64::try_from(created_at)
        .map_err(|_| format!("created_at must fit in signed 64-bit integer, got {created_at}"))
}

/// Validate a user-provided search limit before passing it to core search.
fn parse_search_limit(limit: u32) -> BoundaryResult<usize> {
    if limit > MAX_NAPI_SEARCH_LIMIT {
        return Err(format!(
            "limit must be <= {MAX_NAPI_SEARCH_LIMIT}, got {limit}"
        ));
    }
    Ok(limit as usize)
}

/// Validate text query size before it crosses into core search.
fn validate_query_len(query: &str) -> BoundaryResult<()> {
    let len = query.len();
    if len > MAX_NAPI_QUERY_BYTES {
        return Err(format!(
            "query must be <= {MAX_NAPI_QUERY_BYTES} bytes, got {len}"
        ));
    }
    Ok(())
}

/// Validate batch write size before opening a write transaction.
fn validate_batch_size(len: usize) -> BoundaryResult<()> {
    if len > MAX_NAPI_BATCH_ENTITIES {
        return Err(format!(
            "batch_put_entities accepts at most {MAX_NAPI_BATCH_ENTITIES} entities, got {len}"
        ));
    }
    Ok(())
}

/// Validate codebase manifest size before allocating core snapshot entries.
fn validate_codebase_file_count(len: usize) -> BoundaryResult<()> {
    if len > MAX_NAPI_CODEBASE_FILES {
        return Err(format!(
            "codebase snapshot accepts at most {MAX_NAPI_CODEBASE_FILES} files, got {len}"
        ));
    }
    Ok(())
}

/// Validate and copy a 32-byte content hash from JS.
fn parse_content_hash(buf: &Buffer) -> BoundaryResult<[u8; CODEBASE_CONTENT_HASH_LEN]> {
    buf.as_ref().try_into().map_err(|_| {
        format!(
            "content_hash must be exactly {CODEBASE_CONTENT_HASH_LEN} bytes, got {}",
            buf.len()
        )
    })
}

fn parse_fixed_hash<const N: usize>(buf: &Buffer, label: &str) -> BoundaryResult<[u8; N]> {
    buf.as_ref()
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes, got {}", buf.len()))
}

/// Validate a JS file size before narrowing to u64.
fn parse_file_size(size: i64) -> BoundaryResult<u64> {
    u64::try_from(size).map_err(|_| format!("size_bytes must be >= 0, got {size}"))
}

/// Validate configured vector dimensions before opening a vault.
fn validate_dimensions(dimensions: usize) -> BoundaryResult<()> {
    if dimensions > MAX_NAPI_DIMENSIONS {
        return Err(format!(
            "dimensions must be <= {MAX_NAPI_DIMENSIONS}, got {dimensions}"
        ));
    }
    Ok(())
}

/// Validate vector length before allocating the narrowed f32 copy.
fn validate_vector_len(len: usize, expected: usize, label: &str) -> BoundaryResult<()> {
    if len != expected {
        return Err(format!(
            "{label} length must equal vault dimensions ({expected}), got {len}"
        ));
    }
    Ok(())
}

/// Convert a slice of EntityIds to Buffers.
fn entity_ids_to_buffers(ids: Vec<EntityId>) -> Vec<Buffer> {
    ids.into_iter()
        .map(|id| Buffer::from(id.as_bytes().as_slice()))
        .collect()
}

fn core_codebase_snapshot(input: NapiCodebaseSnapshot) -> BoundaryResult<CodebaseSnapshot> {
    validate_codebase_file_count(input.files.len())?;
    let repo_ref = RepoRef::parse(&input.repo_ref).map_err(|e| e.to_string())?;
    let files = input
        .files
        .into_iter()
        .map(|entry| {
            Ok(CodebaseFileEntry::new(
                entry.path,
                parse_content_hash(&entry.content_hash)?,
                parse_file_size(entry.size_bytes)?,
            ))
        })
        .collect::<BoundaryResult<Vec<_>>>()?;
    let fork_hash = input
        .fork_hash
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_FORK_HASH_LEN>(buf, "fork_hash"))
        .transpose()?;
    let scope_key = input
        .scope_key
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_SCOPE_KEY_LEN>(buf, "scope_key"))
        .transpose()?;
    let snapshot = CodebaseSnapshot::new(input.project_id, repo_ref, input.commit_hash, files)
        .map_err(|e| e.to_string())?;
    if let Some(fork_hash) = fork_hash
        && snapshot.fork_hash != fork_hash
    {
        return Err("fork_hash must match the file manifest".to_owned());
    }
    if let Some(scope_key) = scope_key
        && snapshot.scope_key != scope_key
    {
        return Err("scope_key must match project_id and repo_ref".to_owned());
    }
    Ok(snapshot)
}

fn napi_codebase_snapshot(snapshot: CodebaseSnapshot) -> BoundaryResult<NapiCodebaseSnapshot> {
    let files = snapshot
        .files
        .into_iter()
        .map(|entry| {
            let size_bytes = i64::try_from(entry.size_bytes).map_err(|_| {
                format!(
                    "size_bytes must fit in signed 64-bit integer, got {}",
                    entry.size_bytes
                )
            })?;
            Ok(NapiCodebaseFileEntry {
                path: entry.path,
                content_hash: Buffer::from(entry.content_hash.as_slice()),
                size_bytes,
            })
        })
        .collect::<BoundaryResult<Vec<_>>>()?;
    Ok(NapiCodebaseSnapshot {
        project_id: snapshot.project_id,
        repo_ref: snapshot.repo_ref.canonical(),
        commit_hash: snapshot.commit_hash,
        fork_hash: Some(Buffer::from(snapshot.fork_hash.as_slice())),
        scope_key: Some(Buffer::from(snapshot.scope_key.as_slice())),
        files,
    })
}

fn core_email_adapter(
    input: NapiEmailIdentityAdapterConfig,
) -> napi::Result<DevEmailIdentityAdapter> {
    let config = match input.local_part_prefix {
        Some(prefix) => {
            DevEmailIdentityAdapterConfig::with_prefix(input.domain, prefix, input.signing_secret)
        }
        None => DevEmailIdentityAdapterConfig::new(input.domain, input.signing_secret),
    }
    .map_err(to_napi_err)?;
    Ok(DevEmailIdentityAdapter::new(config))
}

fn core_email_inbound(input: NapiEmailInboundEvent) -> EmailProviderInbound {
    let inbound = EmailProviderInbound::new(
        input.provider_event_id,
        input.envelope_to,
        input.envelope_from,
        ts_to_u64(input.received_at),
    );
    if let Some(payload_ref) = input.payload_ref {
        inbound.with_payload_ref(payload_ref)
    } else {
        inbound
    }
}

/// Derive the deterministic per-identity email address for a ChannelIdentity.
#[napi]
pub fn channel_identity_email_address(
    identity_id: Buffer,
    agent_ref: Buffer,
    config: NapiEmailIdentityAdapterConfig,
    requested_at: Option<i64>,
) -> napi::Result<String> {
    let identity_id = parse_entity_id(&identity_id)?;
    let agent_ref = parse_entity_id(&agent_ref)?;
    let adapter = core_email_adapter(config)?;
    let requested_at = requested_at.map_or(0, ts_to_u64);
    Ok(adapter
        .requested_identity(identity_id, agent_ref, requested_at)
        .address_or_handle)
}

/// Parse inbound email webhook data into a SurfaceEvent input JSON string.
#[napi]
pub fn parse_email_inbound_surface_event(
    config: NapiEmailIdentityAdapterConfig,
    inbound: NapiEmailInboundEvent,
) -> napi::Result<String> {
    let adapter = core_email_adapter(config)?;
    let input = adapter
        .parse_inbound(ChannelIdentityProviderInbound::Email(core_email_inbound(
            inbound,
        )))
        .map_err(to_napi_err)?;
    serde_json::to_string(&input)
        .map_err(|e| napi::Error::from_reason(format!("surface event input json: {e}")))
}

fn apply_codebase_filters<'a>(
    mut builder: oneiron::PipelineBuilder<'a>,
    repo_ref: Option<String>,
    project_id: Option<String>,
) -> napi::Result<oneiron::PipelineBuilder<'a>> {
    if let Some(repo_ref) = repo_ref {
        builder = builder.filter_repo_ref(RepoRef::parse(&repo_ref).map_err(to_napi_err)?);
    }
    if let Some(project_id) = project_id {
        builder = builder.filter_project_id(project_id);
    }
    Ok(builder)
}

fn apply_codebase_context_filters<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    repo_ref: Option<String>,
    project_id: Option<String>,
) -> napi::Result<oneiron::ContextPackBuilder<'a>> {
    if let Some(repo_ref) = repo_ref {
        builder = builder.filter_repo_ref(RepoRef::parse(&repo_ref).map_err(to_napi_err)?);
    }
    if let Some(project_id) = project_id {
        builder = builder.filter_project_id(project_id);
    }
    Ok(builder)
}

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
            .map(|opt| opt.map(|v| v.into()))
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
        let snapshot = core_codebase_snapshot(snapshot).map_err(napi::Error::from_reason)?;
        self.vault
            .put_codebase_snapshot(&eid, &snapshot)
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

    // ─── Sync (stubs — wired up in Phase 1D) ──────────────────

    /// Start sync to a remote server. Currently a stub.
    #[napi]
    pub fn start_sync(&self, _ws_url: String, _auth_token: String) -> napi::Result<()> {
        Err(napi::Error::from_reason(
            "N-API sync bindings not yet wired up",
        ))
    }

    /// Stop an active sync connection. Currently a stub.
    #[napi]
    pub fn stop_sync(&self) -> napi::Result<()> {
        Err(napi::Error::from_reason(
            "N-API sync bindings not yet wired up",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason<T: std::fmt::Debug>(result: std::result::Result<T, String>) -> String {
        result.expect_err("expected N-API boundary error")
    }

    #[test]
    fn napi_boundary_rejects_created_at_overflow() {
        assert_eq!(parse_created_at(i64::MAX as u64).unwrap(), i64::MAX);

        let overflow = i64::MAX as u64 + 1;
        assert_eq!(
            reason(parse_created_at(overflow)),
            format!("created_at must fit in signed 64-bit integer, got {overflow}")
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_limit() {
        assert_eq!(
            parse_search_limit(MAX_NAPI_SEARCH_LIMIT).unwrap(),
            MAX_NAPI_SEARCH_LIMIT as usize
        );

        let limit = MAX_NAPI_SEARCH_LIMIT + 1;
        assert_eq!(
            reason(parse_search_limit(limit)),
            format!("limit must be <= {MAX_NAPI_SEARCH_LIMIT}, got {limit}")
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_query() {
        let ok = "x".repeat(MAX_NAPI_QUERY_BYTES);
        assert!(validate_query_len(&ok).is_ok());

        let too_long = "x".repeat(MAX_NAPI_QUERY_BYTES + 1);
        assert_eq!(
            reason(validate_query_len(&too_long)),
            format!(
                "query must be <= {MAX_NAPI_QUERY_BYTES} bytes, got {}",
                MAX_NAPI_QUERY_BYTES + 1
            )
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_batch() {
        assert!(validate_batch_size(MAX_NAPI_BATCH_ENTITIES).is_ok());

        let len = MAX_NAPI_BATCH_ENTITIES + 1;
        assert_eq!(
            reason(validate_batch_size(len)),
            format!(
                "batch_put_entities accepts at most {MAX_NAPI_BATCH_ENTITIES} entities, got {len}"
            )
        );
    }

    #[test]
    fn napi_boundary_rejects_wrong_vector_len() {
        assert!(validate_vector_len(4, 4, "query vector").is_ok());

        assert_eq!(
            reason(validate_vector_len(5, 4, "query vector")),
            "query vector length must equal vault dimensions (4), got 5"
        );
    }

    #[test]
    fn napi_boundary_rejects_oversized_dimensions() {
        assert!(validate_dimensions(MAX_NAPI_DIMENSIONS).is_ok());

        let dimensions = MAX_NAPI_DIMENSIONS + 1;
        assert_eq!(
            reason(validate_dimensions(dimensions)),
            format!("dimensions must be <= {MAX_NAPI_DIMENSIONS}, got {dimensions}")
        );
    }
}
