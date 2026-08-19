//! Recall and `MemoryPack` assembly (S6): recall/recall_in_session and the
//! scope-honesty + provenance plumbing.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::structural::*;
use super::*;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::claim::claim_surfaceable;
use crate::companion::companion_value_to_json;
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, FieldProfile, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::llm::BudgetLease;
use crate::pipeline::{DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, WorldScope};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE};
use crate::serialize::{SerializeConfig, serialize_pack};

/// The S6 `MemoryPack` schema version.
pub const MEMORY_PACK_VERSION: u32 = 1;

const PPR_SEED_LIMIT: usize = 8;

/// Bounded claim scan behind scope-honesty world enumeration.
const SCOPE_HONESTY_SCAN_CAP: usize = 512;

const RECALL_TOKEN_BUDGET: usize = 4000;

/// Retrieval effort dial (S6). Deliberately distinct from `llm.rs`
/// `ReasoningEffort` (the LLM dial) and `context_pack.rs` `FieldProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Pure lexical retrieval: text search only, no graph expansion, no
    /// hydration, minimal fields. No LLM, no lease.
    Minimal,
    /// Text + PPR graph expansion, 1-hop edges, hydration, standard
    /// fields, recency/salience/confidence boosts. No LLM, no lease.
    Standard,
    /// Lease-gated deep retrieval. No lease-issuer exists yet (OF-131
    /// IN_BUILD): without a lease this is a typed `LEASE_REQUIRED` error;
    /// with one it executes as `Standard` plus `deep_pending: true` until
    /// the LLMB chain wires execution.
    Deep,
}

impl Effort {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "minimal" => Some(Self::Minimal),
            "standard" => Some(Self::Standard),
            "deep" => Some(Self::Deep),
            _ => None,
        }
    }
}

/// Recall scoping (S5): world/facet narrowing only — unset means the vault
/// floor; the scope never widens beyond it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallScope {
    /// WORLD entity ref; scopes to that world plus base reality.
    pub world_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
}

/// Item provenance (S6, default-on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProvenance {
    /// Claim source string, or `record` for structural source records.
    pub source: String,
    /// This revision plus superseded ancestors (32-hex ids).
    pub source_revision_ids: Vec<String>,
    /// Evidence TURN ids. Populated structurally for MESSAGE items; claim
    /// evidence stamping is the extraction pipeline's later responsibility.
    pub evidence_turn_ids: Vec<String>,
}

/// One memory pack item (S6 schema).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryItem {
    /// Short ref, hydratable via [`MemoryFacade::hydrate`].
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Predicate (claims only).
    pub predicate: Option<String>,
    /// Text rendering of the item value/content (capped).
    pub value_text: String,
    /// Calibrated-absolute confidence in [0, 1] — NEVER set-relative:
    /// read from the claim body, independent of the candidate set.
    pub confidence: f32,
    /// Hedge vocabulary bucket derived from `confidence`.
    pub hedge_bucket: String,
    /// Provenance (default-on).
    pub provenance: MemoryProvenance,
    /// World hex, when world-scoped.
    pub world: Option<String>,
    /// Facet hex, when faceted.
    pub facet: Option<String>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
}

/// Scope honesty (S6): what the scope excluded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeHonesty {
    /// Worlds holding surfaceable claims outside the requested scope.
    pub out_of_scope_worlds: Vec<String>,
}

/// Retrieval accounting (S6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalMeta {
    /// True when only sparse (lexical/graph) signals ran — no dense
    /// vector signal is available until the embedder lane lands.
    pub sparse: Option<bool>,
    /// Candidates considered by the retrieval pipeline.
    pub total_candidates: u64,
    /// CLAIM items in the returned pack.
    pub claims_returned: u64,
    /// Set when a leased `Deep` call executed as `Standard` (LLMB chain
    /// not yet wired).
    pub deep_pending: Option<bool>,
}

/// The facade projection of a `ContextPack` (S6, `pack_version: 1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryPack {
    /// Ranked items.
    pub items: Vec<MemoryItem>,
    /// What the scope excluded.
    pub scope_honesty: ScopeHonesty,
    /// Retrieval accounting.
    pub retrieval_meta: RetrievalMeta,
    /// Schema version (always [`MEMORY_PACK_VERSION`]).
    pub pack_version: u32,
    /// Text rendering in the requested OF-096 format; `None` = typed only.
    pub rendered: Option<String>,
}

impl MemoryFacade<'_> {
    /// Effort-dialed retrieval into an S6 `MemoryPack`.
    ///
    /// `Deep` requires a [`BudgetLease`] (W4/C4). No lease-issuer exists at
    /// base (OF-131), so `Deep` without a lease is a typed
    /// `LEASE_REQUIRED` error, and a leased `Deep` executes as `Standard`
    /// with `retrieval_meta.deep_pending = true`.
    ///
    /// Retrieval is sparse-only today (`retrieval_meta.sparse = true`): the
    /// engine takes caller-supplied query vectors and no embedder lane has
    /// landed, so the vector signal joins later without a contract change.
    pub fn recall(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> FacadeResult<MemoryPack> {
        self.recall_routed(None, query, effort, scope, limit, format, lease)
    }

    /// Recalls FROM INSIDE a session (ONE-1570 Arm B), the retrieval sibling
    /// of [`Self::witness_into_session`].
    ///
    /// Identical retrieval to [`Self::recall`] — same scoring, same scope,
    /// same pack. What the session changes is where the run's TELEMETRY
    /// lands. A retrieval-run row carries `result_ids` and a score breakdown,
    /// so it betrays what the room was asking about even though the retrieval
    /// itself reads base. While the room is off record every run this call
    /// registers — the context pack's, the facet pipeline's, and the PPR seed
    /// search's — rides the session's own overlay and evaporates with the
    /// transcript at close, counted there as a deleted context receipt.
    ///
    /// After a flip back on record the room's retrievals are ORDINARY ones and
    /// their runs land in the base ledger exactly as [`Self::recall`]'s do.
    /// The session is an explicit ARGUMENT for the same reason witness takes
    /// one: an ordinary commissioned recall issued while some room happens to
    /// be live elsewhere is not a room retrieval and never enters its receipt
    /// set. Ambient live-session state is never consulted.
    #[expect(
        clippy::too_many_arguments,
        reason = "recall's public parameter list plus the session it runs inside; the two \
                  doors must stay call-compatible, so neither may regroup its parameters"
    )]

    pub fn recall_in_session(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> FacadeResult<MemoryPack> {
        self.recall_routed(Some(session), query, effort, scope, limit, format, lease)
    }

    /// The one recall body. `session` is `None` for every canonical caller,
    /// which therefore takes byte-identical base paths.
    #[expect(
        clippy::too_many_arguments,
        reason = "carries recall's public parameter list plus the session route; splitting it \
                  would fork the body the two public doors exist to share"
    )]

    fn recall_routed(
        &self,
        session: Option<&crate::off_record::OffRecordSession<'_>>,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> FacadeResult<MemoryPack> {
        if limit == 0 {
            return Err(FacadeError::bad_request("recall limit must be at least 1"));
        }
        if let Some(session) = session {
            // A session handle names a room in ONE store, and this facade's
            // vault is an independent borrow — nothing in the lifetimes ties
            // them, so safe public code can pair a facade on vault A with a
            // room on vault B. That pairing reads A while staging A's run row
            // and its `result_ids` into B's overlay, and derives B's PPR seeds
            // for A's pack: private telemetry cross-associated and results
            // contaminated, in both directions. The executor binding refuses
            // the same mismatch by the same identity.
            if !std::ptr::eq(
                session.store_identity(),
                std::ptr::from_ref(&self.vault.store),
            ) {
                return Err(FacadeError::bad_request(
                    "off-record session belongs to a different vault than this memory facade",
                ));
            }
        }
        // ONE route and ONE registration door for the whole assembly. The
        // context pack registers a PROVISIONAL run and finalizes it in a
        // second write, so a target re-derived between them could stage into
        // the room and then publish into base — see
        // `OffRecordSession::retrieval_telemetry`.
        let route = session
            .map(crate::off_record::OffRecordSession::write_route)
            .transpose()?;
        let session_telemetry = match (session, route.as_ref()) {
            (Some(session), Some(route)) => Some(session.retrieval_telemetry(route)?),
            _ => None,
        };
        let mut deep_pending = None;
        let effective = match effort {
            Effort::Deep => {
                if lease.is_none() {
                    return Err(FacadeError::new(
                        FACADE_CODE_LEASE_REQUIRED,
                        "deep recall requires a budget lease and no lease was presented",
                        &[
                            "Use standard effort or present a budget lease.",
                            "The lease issuer lands with the LLMB chain (OF-131).",
                        ],
                    ));
                }
                deep_pending = Some(true);
                Effort::Standard
            }
            other => other,
        };
        let world_scope = match &scope.world_ref {
            Some(world_ref) => WorldScope::World(self.resolve_ref(world_ref)?),
            None => WorldScope::All,
        };
        let pack_format = format.map(parse_pack_format).transpose()?;

        let (items, total_candidates, rendered) = match &scope.facet {
            Some(facet_ref) => {
                // Facet-strict narrowing rides the raw retrieval pipeline:
                // ContextPackBuilder exposes no facet passthrough and
                // pipeline.rs/context_pack.rs are consume-only for this
                // chain. No pack rendering on this path.
                let facet_id = self.resolve_ref(facet_ref)?;
                let mut pipeline = self
                    .vault
                    .query()
                    .search_text(query, limit)
                    .facet(&facet_id, FacetMode::Strict)
                    .world(world_scope);
                if let Some(telemetry) = session_telemetry.as_ref() {
                    pipeline = pipeline.in_session(telemetry);
                }
                if effective == Effort::Standard {
                    pipeline = pipeline
                        .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                        .boost_salience()
                        .boost_confidence();
                }
                let hits = pipeline.run()?;
                let total = hits.len() as u64;
                let mut items = Vec::new();
                for hit in hits.into_iter().take(limit) {
                    if let Some(item) = self.memory_item_for(&hit.id, Some(facet_id))? {
                        items.push(item);
                    }
                }
                (items, total, None)
            }
            None => {
                let mut builder = self
                    .vault
                    .context_pack()
                    .search_text(query, limit)
                    .limit(limit)
                    .world(world_scope);
                if let Some(telemetry) = session_telemetry.as_ref() {
                    builder = builder.in_session(telemetry);
                }
                match effective {
                    Effort::Minimal => {
                        builder = builder
                            .hydrate(false)
                            .include_edges(false)
                            .field_profile(FieldProfile::Minimal);
                    }
                    Effort::Standard | Effort::Deep => {
                        // The seed search is a SECOND retrieval and registers
                        // its own run. Left on the base door it would publish
                        // a durable row naming what the room searched for, so
                        // in a room it takes the session's routed sibling.
                        let seed_hits = match (session, route.as_ref()) {
                            (Some(session), Some(route)) => {
                                session.search_text_routed(route, query, PPR_SEED_LIMIT)?
                            }
                            _ => self.vault.search_text(query, PPR_SEED_LIMIT)?,
                        };
                        let seeds: Vec<EntityId> =
                            seed_hits.into_iter().map(|hit| hit.id).collect();
                        if !seeds.is_empty() {
                            builder = builder.expand_ppr(&seeds, 1);
                        }
                        builder = builder
                            .include_edges(true)
                            .edge_hop(1)
                            .hydrate(true)
                            .field_profile(FieldProfile::Standard)
                            .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                            .boost_salience()
                            .boost_confidence();
                    }
                }
                let pack = builder.run()?;
                let total = pack.stats.candidates_considered as u64;
                let rendered = pack_format.map(|fmt| {
                    let config = SerializeConfig {
                        format: fmt,
                        profile: match effective {
                            Effort::Minimal => FieldProfile::Minimal,
                            Effort::Standard | Effort::Deep => FieldProfile::Standard,
                        },
                        budget: RECALL_TOKEN_BUDGET,
                        allocation: crate::context_pack::TokenAllocation::default(),
                        include_stats: false,
                        merge_neighbors: true,
                        max_field_chars: DEFAULT_MAX_FIELD_CHARS,
                        max_item_tokens: 0,
                    };
                    String::from_utf8_lossy(&serialize_pack(&pack, &config)).into_owned()
                });
                let mut items = Vec::new();
                for entity in pack.results.iter().take(limit) {
                    if let Some(item) = self.memory_item_for(&entity.id, None)? {
                        items.push(item);
                    }
                }
                (items, total, rendered)
            }
        };

        let claims_returned = items.iter().filter(|item| item.kind == "CLAIM").count() as u64;
        Ok(MemoryPack {
            scope_honesty: ScopeHonesty {
                out_of_scope_worlds: self.out_of_scope_worlds(scope.world_ref.as_deref())?,
            },
            retrieval_meta: RetrievalMeta {
                sparse: Some(true),
                total_candidates,
                claims_returned,
                deep_pending,
            },
            items,
            pack_version: MEMORY_PACK_VERSION,
            rendered,
        })
    }

    /// Builds one S6 memory item from an entity id. Returns `Ok(None)` for
    /// missing entities and non-surfaceable claims (D19 admission).
    fn memory_item_for(
        &self,
        id: &EntityId,
        facet_hint: Option<EntityId>,
    ) -> FacadeResult<Option<MemoryItem>> {
        let Some(entity_type) = self.vault.get_entity_type(id)? else {
            return Ok(None);
        };
        let edges = self.vault.edges_out(id)?;
        let mut source_revision_ids = vec![id.to_hex()];
        source_revision_ids.extend(
            edges
                .iter()
                .filter(|edge| edge.kind == EdgeKind::Supersedes)
                .map(|edge| edge.target.to_hex()),
        );
        let facet = facet_hint.map(|facet| facet.to_hex()).or_else(|| {
            edges
                .iter()
                .find(|edge| edge.kind == EdgeKind::HasFacet)
                .map(|edge| edge.target.to_hex())
        });
        let short_id = self.short_ref_or_hex(id)?;
        let kind = kind_string_for_type(entity_type);

        if entity_type == ENTITY_TYPE_CLAIM {
            let Some(body) = self.vault.get_claim(id)? else {
                return Ok(None);
            };
            if !claim_surfaceable(&body) {
                return Ok(None);
            }
            let value_json = companion_value_to_json(&body.value);
            Ok(Some(MemoryItem {
                short_id,
                kind,
                predicate: Some(body.predicate.clone()),
                value_text: truncate_text(&value_text_of(&value_json), DEFAULT_MAX_FIELD_CHARS),
                confidence: body.confidence,
                hedge_bucket: hedge_bucket_for(body.confidence).to_owned(),
                provenance: MemoryProvenance {
                    source: body
                        .source
                        .map_or_else(|| "unattributed".to_owned(), |s| s.as_str().to_owned()),
                    source_revision_ids,
                    evidence_turn_ids: Vec::new(),
                },
                world: body.world.map(|world| world.to_hex()),
                facet,
                salience: body.salience,
            }))
        } else {
            let Some(view) = self.entity_view(id)? else {
                return Ok(None);
            };
            let value_text = view
                .body
                .as_ref()
                .and_then(|body| body.get("content"))
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || {
                        view.body
                            .as_ref()
                            .map(|body| serde_json::to_string(body).unwrap_or_default())
                            .unwrap_or_default()
                    },
                    str::to_owned,
                );
            let evidence_turn_ids = if entity_type == ENTITY_TYPE_MESSAGE {
                edges
                    .iter()
                    .filter(|edge| edge.kind == EdgeKind::PartOf)
                    .map(|edge| edge.target.to_hex())
                    .collect()
            } else {
                Vec::new()
            };
            Ok(Some(MemoryItem {
                short_id,
                kind,
                predicate: None,
                value_text: truncate_text(&value_text, DEFAULT_MAX_FIELD_CHARS),
                confidence: 1.0,
                hedge_bucket: hedge_bucket_for(1.0).to_owned(),
                provenance: MemoryProvenance {
                    source: "record".to_owned(),
                    source_revision_ids,
                    evidence_turn_ids,
                },
                world: None,
                facet,
                salience: None,
            }))
        }
    }

    /// Scope honesty: worlds holding surfaceable claims outside the
    /// requested world scope. Bounded scan (first
    /// [`SCOPE_HONESTY_SCAN_CAP`] claims); unset scope excludes nothing.
    pub(super) fn out_of_scope_worlds(
        &self,
        scope_world_ref: Option<&str>,
    ) -> FacadeResult<Vec<String>> {
        let Some(world_ref) = scope_world_ref else {
            return Ok(Vec::new());
        };
        let scope_world = self.resolve_ref(world_ref)?;
        // Bounded page primitive, not `entities_by_type().take(cap)`: the
        // latter materializes the whole CLAIM index and errors with
        // IndexOverflow past MAX_TYPE_QUERY_RESULTS before `take` can run, so
        // a large vault would hard-fail world-scoped recall.
        let ids =
            self.vault
                .entities_by_type_page(ENTITY_TYPE_CLAIM, None, SCOPE_HONESTY_SCAN_CAP)?;
        let mut worlds = BTreeSet::new();
        for id in ids {
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if !claim_surfaceable(&body) {
                continue;
            }
            if let Some(world) = body.world
                && world != scope_world
            {
                worlds.insert(world.to_hex());
            }
        }
        Ok(worlds.into_iter().collect())
    }
}

/// Hedge vocabulary over calibrated-absolute confidence (scour:A176 —
/// never rank-relative).
fn hedge_bucket_for(confidence: f32) -> &'static str {
    if confidence >= 0.9 {
        "confident"
    } else if confidence >= 0.7 {
        "likely"
    } else if confidence >= 0.4 {
        "tentative"
    } else {
        "uncertain"
    }
}

/// Maps the OF-096 format strings (`toon|md|json|yaml|txt`) to the pack
/// serializer formats.
fn parse_pack_format(format: &str) -> FacadeResult<PackFormat> {
    match format {
        "json" => Ok(PackFormat::Json),
        "yaml" => Ok(PackFormat::Yaml),
        "toon" => Ok(PackFormat::Toon),
        "md" => Ok(PackFormat::Markdown),
        "txt" => Ok(PackFormat::Plaintext),
        other => Err(FacadeError::bad_request_with(
            format!("unknown pack format {other:?}"),
            &["Use one of: toon, md, json, yaml, txt."],
        )),
    }
}

fn value_text_of(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub(super) fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_owned()
    } else {
        let mut out: String = text.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}
