//! Legacy buffer-oriented NapiVault binding and all its verbs.

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use oneiron::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, EdgeActorClass, EntityId,
    Memory, RawEntityPut, RepoRef, TimeRange, Vault, VaultConfig, parse_actor_key,
};

pub(crate) use super::boundary::host_device_class;
use super::boundary::{
    DEFAULT_NAPI_SEARCH_LIMIT, entity_ids_to_buffers, parse_created_at, parse_edge_kind,
    parse_entity_id, parse_search_limit, parse_u8, read_bounded_array, read_codebase_snapshot,
    NAPI_BATCH_FRAME_ENTITIES, read_query, read_vector, to_napi_err, ts_to_u64,
    validate_dimensions, validate_entity_payload_len,
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
use crate::facade::{NapiRecallMedia, boundary_error, facade_error, recall_media_to_engine};
use crate::host_root::HostRootOpenOptions;

mod reads;

/// What this embedded vault says to a context pack naming `media` (OF-370):
/// it serves no `ai.embed` rung, so it cannot embed the bytes into their
/// space, and it never packs the rest of the request without them.
const CONTEXT_PACK_MEDIA_UNSERVED: &str = "context pack: this embedded vault serves no ai.embed rung, so it cannot search media; retry without media or pack on a server";

/// A context pack's `media` on this embedded vault (OF-370). It is lowered
/// onto the served route's shape as `vault.recall`'s is (an unknown kind is
/// the caller's `BAD_REQUEST`), then refused with the typed
/// `MODEL_UNAVAILABLE` an embedded `vault.recall` answers, as the JSON
/// `{code, message, suggestions}` the facade's errors carry. No pack is
/// read: media is never dropped silently.
fn refuse_unserved_media(media: Option<NapiRecallMedia>) -> napi::Result<()> {
    let Some(media) = media else {
        return Ok(());
    };
    recall_media_to_engine(media).map_err(facade_error)?;
    Err(facade_error(oneiron::MemoryError::new(
        oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
        CONTEXT_PACK_MEDIA_UNSERVED,
        &["Pack media through a server that serves the space's rung under [models.media.embed]."],
    )))
}

/// What a bound vault says to a write it has no caller-bound door for
/// (OF-063): it never writes as the host in its caller's place.
const BOUND_WRITE_UNSERVED: &str =
    "this write has no caller-bound door, so a bound vault does not make it as the host";

/// Node.js binding for the Oneiron Vault.
///
/// A vault from `new` writes as the host. One from [`NapiVault::bound`]
/// writes as the caller its app host named (OF-063): its puts, batch puts,
/// edges, vectors and deletes run as that caller, inside its session, whose
/// room its content reads compose over base (FIX 8119; `reads`).
#[napi]
pub struct NapiVault {
    vault: Arc<Vault>,
    dimensions: usize,
    /// The caller a bound vault writes as; `None` writes as the host.
    binding: Option<RawBinding>,
    /// `openWithHostRoot`'s wrong-root fact (FIX 4730); `false` otherwise.
    wrong_host_root: bool,
}

/// The principal a bound vault's app host named, and its off-record
/// session, if any: this handle's alone, never process state.
struct RawBinding {
    actor: EntityId,
    actor_class: EdgeActorClass,
    session: Option<String>,
}

impl NapiVault {
    /// The bound caller's memory surface, its session bound; `None` for a
    /// vault that writes as the host.
    fn bound_memory(&self) -> Option<Memory<'_>> {
        self.binding.as_ref().map(|binding| {
            let memory = self.vault.memory(binding.actor, binding.actor_class);
            match binding.session.as_deref() {
                Some(session) => memory.in_off_record_session(session),
                None => memory,
            }
        })
    }

    /// Refuses a write a bound vault has no caller-bound door for.
    fn refuse_bound_host_write(&self) -> napi::Result<()> {
        if self.binding.is_none() {
            return Ok(());
        }
        Err(facade_error(oneiron::MemoryError::new(
            oneiron::memory::MEMORY_CODE_FORBIDDEN,
            BOUND_WRITE_UNSERVED,
            &["Make this write on the unbound vault, which writes as the host."],
        )))
    }

    /// One frame of [`Self::batch_put_entities`], in one transaction.
    fn put_entity_frame(&self, puts: &[RawEntityPut<'_>]) -> napi::Result<()> {
        if let Some(memory) = self.bound_memory() {
            return memory.raw_put_entities(puts).map_err(facade_error);
        }

        let mut batch = self.vault.batch();
        for put in puts {
            batch = batch.put(
                &put.id,
                put.entity_type,
                put.occurred,
                put.learned_at,
                put.data,
            );
        }

        batch.commit().map_err(to_napi_err)
    }
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
    ///
    /// `deviceClass` is what kind of machine this install is, as the host
    /// declares it (FIX 3833): `"computer"`, the default, or `"phone"`. It is
    /// set before the vault opens, so the install enrols as it.
    #[napi(constructor)]
    pub fn new(
        path: String,
        dimensions: Option<u32>,
        dict_search_paths: Option<Vec<String>>,
        device_class: Option<String>,
    ) -> napi::Result<Self> {
        crate::facade::before_vault_open();
        let mut config = VaultConfig::device();
        config.machine_device_class =
            host_device_class(device_class.as_deref()).map_err(napi::Error::from_reason)?;
        if let Some(dims) = dimensions {
            config.dimensions = dims as usize;
        }
        if let Some(paths) = dict_search_paths {
            config.dict_search_paths = paths.into_iter().map(std::path::PathBuf::from).collect();
        }

        validate_dimensions(config.dimensions).map_err(napi::Error::from_reason)?;
        let dimensions = config.dimensions;
        let vault = Vault::open(&path, config).map_err(to_napi_err)?;
        // Signing doors (delete receipts) need this install's keys from the keystore.
        vault.install_default_keystore(std::path::Path::new(&path));
        Ok(Self {
            vault: Arc::new(vault),
            dimensions,
            binding: None,
            wrong_host_root: false,
        })
    }

    /// `new`, then this install's own machine profile from the vault's host
    /// root secret (FIX 4730), so the owner's acts carry from it. With
    /// `initializeRoot`, a store this open creates is rooted under the
    /// secret first, as a new local-origin vault. A secret that cannot
    /// profile the install refuses the open with the engine's reason; a
    /// secret that is not the vault's settled root, over a profile that
    /// already stands, opens and says so in `wrongHostRoot`. `deviceClass`
    /// is `new`'s (FIX 3833).
    #[napi(factory)]
    pub fn open_with_host_root(
        path: String,
        dimensions: Option<u32>,
        dict_search_paths: Option<Vec<String>>,
        options: HostRootOpenOptions,
        device_class: Option<String>,
    ) -> napi::Result<Self> {
        let request = options
            .before_open(&path)
            .map_err(napi::Error::from_reason)?;
        let mut opened = Self::new(path, dimensions, dict_search_paths, device_class)?;
        opened.wrong_host_root = request.profile(&opened.vault).map_err(to_napi_err)?;
        Ok(opened)
    }

    /// Whether the root `openWithHostRoot` was given is not this vault's
    /// settled root, so it went unused: this install already carried its
    /// profile, and the vault stands under the settled root as before
    /// (FIX 4730). Reported, never refused, so the host can show it or
    /// re-key. `false` on every other open and on a bound vault.
    #[napi]
    pub fn wrong_host_root(&self) -> bool {
        self.wrong_host_root
    }

    /// A NEW vault over this same open vault whose writes run as one caller
    /// (OF-063): the principal `actorKey` names (`human:<ref>`,
    /// `agent:<ref>` or `system:<ref>`), or the embedded owner when it is
    /// omitted, inside the off-record session `sessionRef` names, or outside
    /// any when it is omitted. This vault is unchanged.
    ///
    /// Its puts, batch puts, edges and vectors commit as that caller, below
    /// owner grade, once their transaction proves the actor; its delete runs
    /// the `vault.delete` door (owner-only; an id naming no record is refused
    /// `INVENTED_REFERENCE`). A codebase snapshot or inbound route, which has
    /// no caller-bound door, is refused there. Inside a session that is off
    /// record, its puts, edges and vectors stage in the room, and its entity,
    /// type and edge reads read the room over base (FIX 8119).
    #[napi]
    pub fn bound(
        &self,
        actor_key: Option<String>,
        session_ref: Option<String>,
    ) -> napi::Result<NapiVault> {
        let session = session_ref.map(|session| session.trim().to_owned());
        if session.as_deref().is_some_and(str::is_empty) {
            return Err(boundary_error(
                "invalid off-record session reference".to_owned(),
            ));
        }
        let (actor, actor_class) = match actor_key.as_deref() {
            Some(key) => parse_actor_key(&self.vault, key).map_err(facade_error)?,
            None => (
                self.vault
                    .ensure_embedded_owner_actor()
                    .map_err(facade_error)?,
                EdgeActorClass::Human,
            ),
        };
        Ok(NapiVault {
            vault: Arc::clone(&self.vault),
            dimensions: self.dimensions,
            binding: Some(RawBinding {
                actor,
                actor_class,
                session,
            }),
            wrong_host_root: false,
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
        let occurred = TimeRange {
            start: ts_to_u64(occurred_start),
            end: ts_to_u64(occurred_end),
        };
        let learned_at = ts_to_u64(learned_at);
        match self.bound_memory() {
            Some(memory) => memory
                .raw_put_entity(RawEntityPut {
                    id: eid,
                    entity_type: etype,
                    occurred,
                    learned_at,
                    data: data.as_ref(),
                })
                .map_err(facade_error),
            None => self
                .vault
                .put_entity(&eid, etype, occurred, learned_at, data.as_ref())
                .map_err(to_napi_err),
        }
    }

    /// Retrieve an entity blob by ID. Returns null if not found.
    #[napi]
    pub fn get_entity(&self, id: Buffer) -> napi::Result<Option<Buffer>> {
        let eid = parse_entity_id(&id)?;
        Ok(self.entity_body(&eid)?.map(std::convert::Into::into))
    }

    /// Delete an entity by ID. Returns true if the entity existed.
    #[napi]
    pub fn delete_entity(&self, id: Buffer) -> napi::Result<bool> {
        let eid = parse_entity_id(&id)?;
        match self.bound_memory() {
            Some(memory) => memory.raw_delete_entity(&eid).map_err(facade_error),
            None => self.vault.delete_entity(&eid).map_err(to_napi_err),
        }
    }

    /// Check whether an entity exists in the vault.
    #[napi]
    pub fn entity_exists(&self, id: Buffer) -> napi::Result<bool> {
        let eid = parse_entity_id(&id)?;
        self.entity_stored(&eid)
    }

    // ─── Edges ─────────────────────────────────────────────────

    /// Store a directed edge between two entities.
    #[napi]
    pub fn put_edge(&self, src: Buffer, kind: u32, tgt: Buffer, weight: f64) -> napi::Result<()> {
        let src_id = parse_entity_id(&src)?;
        let tgt_id = parse_entity_id(&tgt)?;
        let edge_kind = parse_edge_kind(kind)?;
        match self.bound_memory() {
            Some(memory) => memory
                .raw_put_edge(&src_id, edge_kind, &tgt_id, weight as f32)
                .map_err(facade_error),
            None => self
                .vault
                .put_edge(&src_id, edge_kind, &tgt_id, weight as f32)
                .map_err(to_napi_err),
        }
    }

    /// Return outbound edges for a source entity.
    #[napi]
    pub fn edges_out(&self, src: Buffer) -> napi::Result<Vec<NapiEdgeInfo>> {
        let src_id = parse_entity_id(&src)?;
        let edges = self.edges_of(&src_id, true)?;
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
        let edges = self.edges_of(&tgt_id, false)?;
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
        query: Array<'_>,
        limit: u32,
    ) -> napi::Result<Vec<NapiScoredEntity>> {
        let limit = parse_search_limit(limit).map_err(napi::Error::from_reason)?;
        let f32_query = read_vector(&query, self.dimensions, "query vector")?;
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
    pub fn search_text(
        &self,
        query: napi::JsString<'_>,
        limit: u32,
    ) -> napi::Result<Vec<NapiScoredEntity>> {
        let query = read_query(query)?;
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
        query: napi::JsString<'_>,
        limit: u32,
        repo_ref: Option<String>,
        project_id: Option<String>,
    ) -> napi::Result<Vec<NapiScoredEntity>> {
        let query = read_query(query)?;
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
    pub fn put_vector(&self, id: Buffer, vector: Array<'_>) -> napi::Result<()> {
        let eid = parse_entity_id(&id)?;
        let f32_vec = read_vector(&vector, self.dimensions, "vector")?;
        match self.bound_memory() {
            Some(memory) => memory.raw_put_vector(&eid, &f32_vec).map_err(facade_error),
            None => self.vault.put_vector(&eid, &f32_vec).map_err(to_napi_err),
        }
    }

    // ─── Codebase Metadata ─────────────────────────────────────

    /// Attach or replace codebase snapshot metadata for a CODE_ARTIFACT entity.
    #[napi]
    pub fn put_codebase_snapshot(&self, id: Buffer, snapshot: Object<'_>) -> napi::Result<()> {
        self.refuse_bound_host_write()?;
        let eid = parse_entity_id(&id)?;
        let snapshot = read_codebase_snapshot(snapshot)?;
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
    /// - `media`: A media query (`{space, mime, bytesB64, kinds}`), the served
    ///   context pack's and `vault.recall`'s shape (OF-370). This embedded
    ///   vault serves no `ai.embed` rung, so a pack naming it is refused with
    ///   the typed `MODEL_UNAVAILABLE`, never packed without it.
    #[napi]
    pub fn context_pack(
        &self,
        query_text: Option<napi::JsString<'_>>,
        query_vector: Option<Array<'_>>,
        limit: Option<u32>,
        format: Option<String>,
        media: Option<NapiRecallMedia>,
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

        let query_text = query_text.map(read_query).transpose()?;
        let query_vector = query_vector
            .map(|vec| read_vector(&vec, self.dimensions, "query vector"))
            .transpose()?;
        refuse_unserved_media(media)?;
        let mut builder = self.vault.context_pack().format(pack_format).limit(limit);

        if let Some(text) = &query_text {
            builder = builder.search_text(text, limit);
        }

        if let Some(vec) = &query_vector {
            builder = builder.search_vector(vec, limit);
        }

        let output = builder.run_serialized().map_err(to_napi_err)?;
        String::from_utf8(output)
            .map_err(|e| napi::Error::from_reason(format!("context pack output is not utf8: {e}")))
    }

    /// Run a context pack query scoped to codebase metadata. `media` is
    /// refused as on `context_pack`.
    #[allow(
        clippy::too_many_arguments,
        reason = "one positional JS argument per option, media appended last"
    )]
    #[napi]
    pub fn context_pack_scoped(
        &self,
        query_text: Option<napi::JsString<'_>>,
        query_vector: Option<Array<'_>>,
        limit: Option<u32>,
        format: Option<String>,
        repo_ref: Option<String>,
        project_id: Option<String>,
        media: Option<NapiRecallMedia>,
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

        let query_text = query_text.map(read_query).transpose()?;
        let query_vector = query_vector
            .map(|vec| read_vector(&vec, self.dimensions, "query vector"))
            .transpose()?;
        refuse_unserved_media(media)?;
        let mut builder = self.vault.context_pack().format(pack_format).limit(limit);

        if let Some(text) = &query_text {
            builder = builder.search_text(text, limit);
        }

        if let Some(vec) = &query_vector {
            builder = builder.search_vector(vec, limit);
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
        self.refuse_bound_host_write()?;
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

    /// Write multiple entities, in frames of `NAPI_BATCH_FRAME_ENTITIES`
    /// (FIX 11125): every entity is checked first, then each frame is written
    /// in order in one atomic transaction, so a batch within one frame is
    /// one transaction, as before, and a larger one is written whole rather
    /// than refused. A frame that fails stops the call with its own error;
    /// the frames before it stay written.
    #[napi]
    pub fn batch_put_entities(&self, entities: Array<'_>) -> napi::Result<()> {
        let entities: Vec<NapiBatchEntity> = read_bounded_array(&entities, |_| Ok(()))?;
        for e in &entities {
            validate_entity_payload_len(e.data.len()).map_err(napi::Error::from_reason)?;
        }

        let mut puts = Vec::with_capacity(entities.len());
        for e in &entities {
            puts.push(RawEntityPut {
                id: parse_entity_id(&e.id)?,
                entity_type: parse_u8(e.entity_type, "entity_type")?,
                occurred: TimeRange {
                    start: ts_to_u64(e.occurred_start),
                    end: ts_to_u64(e.occurred_end),
                },
                learned_at: ts_to_u64(e.learned_at),
                data: e.data.as_ref(),
            });
        }
        puts.chunks(NAPI_BATCH_FRAME_ENTITIES)
            .try_for_each(|frame| self.put_entity_frame(frame))
    }

    // ─── Tree Queries ──────────────────────────────────────────

    /// Return the stored entity type for an entity, or null if not found.
    #[napi]
    pub fn get_entity_type(&self, id: Buffer) -> napi::Result<Option<u32>> {
        let eid = parse_entity_id(&id)?;
        Ok(self.entity_type_of(&eid)?.map(u32::from))
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
        let ids = self.peers_of(&src_id, edge_kind, tgt_type, true)?;
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
        let ids = self.peers_of(&tgt_id, edge_kind, src_type, false)?;
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
