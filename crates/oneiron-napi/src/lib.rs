mod types;

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};

use types::{NapiBatchEntity, NapiEdgeInfo, NapiScoredEntity, NapiSubtreeEntry};

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
    Ok(EntityId::from_bytes(bytes))
}

/// Convert a signed i64 timestamp to u64, clamping negatives to 0.
fn ts_to_u64(ts: i64) -> u64 {
    ts.max(0) as u64
}

/// Node.js binding for the Oneiron Vault.
#[napi]
pub struct NapiVault {
    vault: Arc<Vault>,
}

#[napi]
impl NapiVault {
    /// Open or create a vault at the given filesystem path.
    ///
    /// `dimensions` controls the embedding vector size (default: 1024 for device preset).
    #[napi(constructor)]
    pub fn new(path: String, dimensions: Option<u32>) -> napi::Result<Self> {
        let config = if let Some(dims) = dimensions {
            VaultConfig {
                dimensions: dims as usize,
                ..VaultConfig::device()
            }
        } else {
            VaultConfig::device()
        };

        let vault = Vault::open(&path, config).map_err(to_napi_err)?;
        Ok(Self {
            vault: Arc::new(vault),
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
        if entity_type > u8::MAX as u32 {
            return Err(napi::Error::from_reason(format!(
                "entity_type must be 0-255, got {entity_type}"
            )));
        }
        self.vault
            .put_entity(
                &eid,
                entity_type as u8,
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
        if kind > u8::MAX as u32 {
            return Err(napi::Error::from_reason(format!(
                "edge kind must be 0-255, got {kind}"
            )));
        }
        let edge_kind = EdgeKind::try_from_u8(kind as u8)
            .ok_or_else(|| napi::Error::from_reason(format!("invalid edge kind: {kind}")))?;
        self.vault
            .put_edge(&src_id, edge_kind, &tgt_id, weight as f32)
            .map_err(to_napi_err)
    }

    /// Return outbound edges for a source entity.
    #[napi]
    pub fn edges_out(&self, src: Buffer) -> napi::Result<Vec<NapiEdgeInfo>> {
        let src_id = parse_entity_id(&src)?;
        let edges = self.vault.edges_out(&src_id).map_err(to_napi_err)?;
        Ok(edges
            .into_iter()
            .map(|e| NapiEdgeInfo {
                src: Buffer::from(src_id.as_bytes().as_slice()),
                kind: e.kind as u32,
                tgt: Buffer::from(e.target.as_bytes().as_slice()),
                weight: e.weight as f64,
                created_at: e.created_at as i64,
                valence: e.vad.valence as f64,
                arousal: e.vad.arousal as f64,
                dominance: e.vad.dominance as f64,
            })
            .collect())
    }

    /// Return inbound edges for a target entity.
    #[napi]
    pub fn edges_in(&self, tgt: Buffer) -> napi::Result<Vec<NapiEdgeInfo>> {
        let tgt_id = parse_entity_id(&tgt)?;
        let edges = self.vault.edges_in(&tgt_id).map_err(to_napi_err)?;
        Ok(edges
            .into_iter()
            .map(|e| NapiEdgeInfo {
                src: Buffer::from(e.target.as_bytes().as_slice()),
                kind: e.kind as u32,
                tgt: Buffer::from(tgt_id.as_bytes().as_slice()),
                weight: e.weight as f64,
                created_at: e.created_at as i64,
                valence: e.vad.valence as f64,
                arousal: e.vad.arousal as f64,
                dominance: e.vad.dominance as f64,
            })
            .collect())
    }

    // ─── Search ────────────────────────────────────────────────

    /// Search for entities by vector similarity (cosine distance via HNSW).
    #[napi]
    pub fn search_vector(
        &self,
        query: Vec<f64>,
        limit: u32,
    ) -> napi::Result<Vec<NapiScoredEntity>> {
        let f32_query: Vec<f32> = query.iter().map(|&v| v as f32).collect();
        let results = self
            .vault
            .search_vector(&f32_query, limit as usize)
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
        let results = self
            .vault
            .search_text(&query, limit as usize)
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
        let f32_vec: Vec<f32> = vector.iter().map(|&v| v as f32).collect();
        self.vault.put_vector(&eid, &f32_vec).map_err(to_napi_err)
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
        let limit = limit.unwrap_or(10) as usize;
        let pack_format = match format.as_deref() {
            Some("yaml") => oneiron::PackFormat::Yaml,
            Some("toon") => oneiron::PackFormat::Toon,
            Some("markdown") => oneiron::PackFormat::Markdown,
            Some("plaintext") => oneiron::PackFormat::Plaintext,
            // Lenient default: unrecognized or missing format falls back to JSON
            _ => oneiron::PackFormat::Json,
        };

        let mut builder = self.vault.context_pack().format(pack_format);

        if let Some(text) = &query_text {
            builder = builder.search_text(text, limit);
        }

        if let Some(vec) = &query_vector {
            let f32_vec: Vec<f32> = vec.iter().map(|&v| v as f32).collect();
            builder = builder.search_vector(&f32_vec, limit);
        }

        let output = builder.run_serialized().map_err(to_napi_err)?;
        String::from_utf8(output)
            .map_err(|e| napi::Error::from_reason(format!("context pack output is not utf8: {e}")))
    }

    // ─── Batch Writes ──────────────────────────────────────────

    /// Write multiple entities in a single atomic transaction.
    #[napi]
    pub fn batch_put_entities(&self, entities: Vec<NapiBatchEntity>) -> napi::Result<()> {
        let mut batch = self.vault.batch();

        for e in &entities {
            let eid = parse_entity_id(&e.id)?;
            if e.entity_type > u8::MAX as u32 {
                return Err(napi::Error::from_reason(format!(
                    "entity_type must be 0-255, got {}",
                    e.entity_type
                )));
            }
            batch = batch.put(
                &eid,
                e.entity_type as u8,
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
        if entity_type > u8::MAX as u32 {
            return Err(napi::Error::from_reason(format!(
                "entity_type must be 0-255, got {entity_type}"
            )));
        }
        let ids = self
            .vault
            .entities_by_type(entity_type as u8)
            .map_err(to_napi_err)?;
        Ok(ids
            .into_iter()
            .map(|id| Buffer::from(id.as_bytes().as_slice()))
            .collect())
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
        if kind > u8::MAX as u32 {
            return Err(napi::Error::from_reason(format!(
                "edge kind must be 0-255, got {kind}"
            )));
        }
        let edge_kind = EdgeKind::try_from_u8(kind as u8)
            .ok_or_else(|| napi::Error::from_reason(format!("invalid edge kind: {kind}")))?;
        let tgt_type = match target_type {
            Some(t) if t > u8::MAX as u32 => {
                return Err(napi::Error::from_reason(format!(
                    "target_type must be 0-255, got {t}"
                )));
            }
            Some(t) => Some(t as u8),
            None => None,
        };
        let ids = self
            .vault
            .targets(&src_id, edge_kind, tgt_type)
            .map_err(to_napi_err)?;
        Ok(ids
            .into_iter()
            .map(|id| Buffer::from(id.as_bytes().as_slice()))
            .collect())
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
        if kind > u8::MAX as u32 {
            return Err(napi::Error::from_reason(format!(
                "edge kind must be 0-255, got {kind}"
            )));
        }
        let edge_kind = EdgeKind::try_from_u8(kind as u8)
            .ok_or_else(|| napi::Error::from_reason(format!("invalid edge kind: {kind}")))?;
        let src_type = match source_type {
            Some(t) if t > u8::MAX as u32 => {
                return Err(napi::Error::from_reason(format!(
                    "source_type must be 0-255, got {t}"
                )));
            }
            Some(t) => Some(t as u8),
            None => None,
        };
        let ids = self
            .vault
            .sources(&tgt_id, edge_kind, src_type)
            .map_err(to_napi_err)?;
        Ok(ids
            .into_iter()
            .map(|id| Buffer::from(id.as_bytes().as_slice()))
            .collect())
    }

    /// Return full subtree via recursive ChildOf traversal.
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

    /// Walk ancestors via ChildOf edges. Capped at 100.
    #[napi]
    pub fn ancestors(&self, node: Buffer) -> napi::Result<Vec<Buffer>> {
        let node_id = parse_entity_id(&node)?;
        let ids = self.vault.ancestors(&node_id).map_err(to_napi_err)?;
        Ok(ids
            .into_iter()
            .map(|id| Buffer::from(id.as_bytes().as_slice()))
            .collect())
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
