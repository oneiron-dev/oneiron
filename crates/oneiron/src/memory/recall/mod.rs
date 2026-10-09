//! Recall and `MemoryPack` assembly (S6): recall/recall_in_session and the
//! scope-honesty + provenance plumbing.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::structural::*;
use super::*;
use crate::ports::EntityStoreRead;

mod items;
mod presentation;
mod scope_honesty;

use self::presentation::{hedge_bucket_for, value_text_of};
pub(super) use self::presentation::{parse_pack_format, truncate_text};

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, claim_surfaceable};
fn companion_value_to_json(value: &rmpv::Value) -> serde_json::Value {
    let mut value = crate::companion::companion_value_to_json(value);
    crate::batch::export::redact_credentials(&mut value);
    value
}
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, FieldProfile, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::llm::BudgetLease;
use crate::pipeline::{DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, WorldScope};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::rerank::RerankOptions;
use crate::retrieval_depth::RecallExecution;
use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use crate::serialize::{SerializeConfig, serialize_pack};

/// The S6 `MemoryPack` schema version.
pub const MEMORY_PACK_VERSION: u32 = 1;

const PPR_SEED_LIMIT: usize = 8;

/// Bounded claim scan behind scope-honesty world enumeration.
const SCOPE_HONESTY_SCAN_CAP: usize = 512;

pub(super) const RECALL_TOKEN_BUDGET: usize = 4000;

/// Retrieval effort dial (S6). Deliberately distinct from `llm.rs`
/// `ReasoningEffort` (the LLM dial) and `context_pack.rs` `FieldProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Available vector, text, phonetic and temporal signals, then blend.
    Light,
    /// Light plus seed-specific search PPR.
    Medium,
    /// Medium plus two-hop expansion and top-30 reranking.
    High,
    /// Four-hop expansion and top-50 reranking.
    Xhigh,
    /// Ten-hop expansion, top-50 reranking and bitemporal search.
    Max,
}

impl Effort {
    /// Stable five-level wire vocabulary. Retired names are not aliases.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "light" => Some(Self::Light),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::Xhigh),
            "max" => Some(Self::Max),
            _ => None,
        }
    }
    /// Paid tiers require an explicit lease and reranker; never silent fallback.
    #[must_use]
    pub const fn requires_rerank(self) -> bool {
        matches!(self, Self::High | Self::Xhigh | Self::Max)
    }
    #[must_use]
    pub const fn graph_depth(self) -> u32 {
        match self {
            Self::Light => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Xhigh => 4,
            Self::Max => 10,
        }
    }
    #[must_use]
    pub const fn rerank_top_n(self) -> usize {
        match self {
            Self::Xhigh | Self::Max => 50,
            _ => 30,
        }
    }
}

/// Recall scoping (S5): world/facet narrowing and the kinds returned — unset
/// means the vault floor; the scope never widens beyond it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallScope {
    /// WORLD entity ref; scopes to that world plus base reality. Unset reads
    /// base plus the actor's active world (ARCH-0022), never every world.
    pub world_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
    /// Registry kinds to return (`MESSAGE`, `CLAIM`, `PERSON`, ...). Unset
    /// returns every kind but the ones with no text of their own
    /// ([`CONTAINER_KINDS`]), so `limit` slots go to rows that say something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

/// Kinds that hold no text of their own: conversations and sessions, and the
/// worlds and facets that scope memories. Recall returns them only when
/// [`RecallScope::kinds`] names them.
///
/// TURN is here only until turns are embedded: ARCH-0004 makes the turn the
/// embedding unit, but today a turn's text repeats its messages, so a turn hit
/// would take the slot of the message it copies.
pub const CONTAINER_KINDS: [u8; 5] = [
    crate::registry::ENTITY_TYPE_TURN,
    crate::registry::ENTITY_TYPE_CONVERSATION,
    crate::registry::ENTITY_TYPE_SESSION,
    crate::registry::ENTITY_TYPE_FACET,
    crate::registry::ENTITY_TYPE_WORLD,
];

/// The kinds a recall admits, resolved once from its scope. `None` is the
/// default: every kind but [`CONTAINER_KINDS`].
fn recall_kinds(scope: &RecallScope) -> MemoryResult<Option<Vec<u8>>> {
    let Some(kinds) = &scope.kinds else {
        return Ok(None);
    };
    if kinds.is_empty() || kinds.len() > crate::registry::ENTITY_TYPE_REGISTRY.len() {
        return Err(MemoryError::bad_request_with(
            format!(
                "scope.kinds must name between 1 and {} registry kinds",
                crate::registry::ENTITY_TYPE_REGISTRY.len()
            ),
            &["Name each kind once, or omit kinds for the default kinds."],
        ));
    }
    let mut types = kinds
        .iter()
        .map(|kind| type_byte_for_kind(kind))
        .collect::<MemoryResult<Vec<u8>>>()?;
    types.sort_unstable();
    types.dedup();
    Ok(Some(types))
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
    /// Short ref, hydratable via [`Memory::hydrate`]: the same `name:hash`
    /// a witness receipt returns, never revision-qualified.
    pub short_id: String,
    /// The retained revision (32 hex) retrieval read this item at, when it
    /// pinned one. [`Self::reference`] joins it to `short_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision_ref: Option<String>,
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
    /// A conversation record's current reactions, one grouped line per
    /// glyph (`👍×8 (Anna, Ben, +6)`); empty for every other item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reactions: Vec<String>,
}

impl MemoryItem {
    /// The ref that hydrates exactly the revision this item was read at:
    /// `short_id@source_revision_ref`, or `short_id` when nothing was pinned.
    #[must_use]
    pub fn reference(&self) -> String {
        match &self.source_revision_ref {
            Some(revision) => format!("{}@{revision}", self.short_id),
            None => self.short_id.clone(),
        }
    }
}

/// Scope honesty (S6): what the scope excluded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeHonesty {
    /// Worlds holding surfaceable claims outside the requested scope.
    pub out_of_scope_worlds: Vec<String>,
    /// The census stopped at its scan cap, so a world past it may be missing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub census_capped: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Retrieval accounting (S6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalMeta {
    #[serde(default)]
    pub quality: RetrievalQuality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradation: Vec<RetrievalDegradation>,
    #[serde(default)]
    pub confidence_adjustment: ConfidenceAdjustment,
    /// True when only sparse (lexical/graph) signals ran — no dense
    /// vector signal is available until the embedder lane lands.
    pub sparse: Option<bool>,
    /// Candidates considered by the retrieval pipeline.
    pub total_candidates: u64,
    /// CLAIM items in the returned pack.
    pub claims_returned: u64,
    /// Retained wire field. Always `None`: paid work never pretends to complete.
    pub deep_pending: Option<bool>,
    /// Requested stages skipped at the explicit deadline.
    #[serde(default)]
    pub partial: bool,
    /// Time phrases read from the query, in order. `used` ones narrowed the
    /// occurred-time window; `unresolved` and `future` ones were skipped and
    /// recall ran on its other signals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporal_hints: Vec<crate::temporal::TemporalHintReport>,
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
    /// The bound actor's requested/ceiling/intersection receipt for every read in this pack.
    pub narrowing: Box<ScopedReadReceipt>,
}

impl Memory<'_> {
    /// Minimal recall for an exact-world view, with kind/predicate narrowing
    /// BEFORE lexical top-k. Uses the same recall assembly and ranking as
    /// [`Self::recall`]; no authority is inferred from these relevance filters.
    pub fn recall_view(
        &self,
        query: &str,
        scope: &RecallScope,
        kind: Option<&str>,
        predicate: Option<&str>,
        limit: usize,
    ) -> MemoryResult<MemoryPack> {
        if limit == 0 || limit > 1000 {
            return Err(MemoryError::bad_request(
                "view limit must be between 1 and 1000",
            ));
        }
        let world = scope
            .world_ref
            .as_deref()
            .map(|reference| self.resolve_ref(reference))
            .transpose()?;
        let filter = |store: &crate::store::Store,
                      txn: &heed::RoTxn<'_>,
                      id: &EntityId|
         -> crate::Result<bool> {
            let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
                return Ok(false);
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                return Ok(false);
            };
            match kind {
                Some(kind) if kind_string_for_type(header.entity_type) != kind => return Ok(false),
                // A view that names no kind takes the scope's kinds, which
                // recall applies, or else the default kinds.
                None if scope.kinds.is_none() && CONTAINER_KINDS.contains(&header.entity_type) => {
                    return Ok(false);
                }
                _ => {}
            }
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Ok(world.is_none() && predicate.is_none());
            }
            let Some(body) = raw
                .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
            else {
                return Ok(false);
            };
            Ok(claim_surfaceable(&body)
                && crate::claim::has_live_support_in_txn(store, txn, &body)?
                && body.world == world
                && predicate.is_none_or(|predicate| body.predicate == predicate))
        };
        let mut pack = self.recall_routed(
            None,
            query,
            Effort::Light,
            scope,
            limit,
            None,
            None,
            Some(&filter),
            &RecallExecution::default(),
        )?;
        let world_hex = world.map(|id| id.to_hex());
        pack.items.retain(|item| {
            item.world == world_hex
                && kind.is_none_or(|kind| item.kind == kind)
                && predicate.is_none_or(|predicate| item.predicate.as_deref() == Some(predicate))
        });
        Ok(pack)
    }

    /// Effort-dialed retrieval into an S6 `MemoryPack`.
    ///
    /// High, xhigh and max require a lease and a prepared reranker; use
    /// [`Self::recall_with_execution`] to supply execution inputs. The ordinary
    /// door refuses unsupported paid work instead of returning a fake success.
    /// Dense and phonetic inputs are optional, explicit host inputs.
    pub fn recall(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            None,
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            &RecallExecution::default(),
        )
    }

    /// Runs the same recall body with dense input, prepared scoring and/or a deadline.
    #[expect(
        clippy::too_many_arguments,
        reason = "adds per-request execution inputs to recall"
    )]
    pub fn recall_with_execution(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
        execution: &RecallExecution<'_>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            None, query, effort, scope, limit, format, lease, None, execution,
        )
    }

    /// Recalls inside a session. Retrieval and scope are unchanged; every
    /// telemetry write (including the seed search and pack finalization) rides
    /// the one session route captured for this call. Off-record rows therefore
    /// evaporate with the room, never leaking into the base retrieval ledger.
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
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            Some(session),
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            &RecallExecution::default(),
        )
    }

    /// Recall with explicit execution inputs, keeping all telemetry on the room route.
    #[expect(
        clippy::too_many_arguments,
        reason = "session sibling of recall_with_execution"
    )]
    pub fn recall_in_session_with_execution(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
        execution: &RecallExecution<'_>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            Some(session),
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            execution,
        )
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
        candidate_filter: Option<&crate::pipeline::CandidateFilter<'_>>,
        execution: &RecallExecution<'_>,
    ) -> MemoryResult<MemoryPack> {
        if limit == 0 {
            return Err(MemoryError::bad_request("recall limit must be at least 1"));
        }
        crate::memory::caps::check_as_of(execution.as_of)?;
        if let Some(session) = session {
            // A session handle names a room in ONE store, and this facade's
            // vault is an independent borrow — nothing in the lifetimes ties
            // them, so safe public code can pair a facade on vault A with a
            // room on vault B. That pairing reads A while staging A's run row
            // and its `result_ids` into B's overlay, and derives B's PPR seeds
            // for A's pack: private telemetry cross-associated and results
            // contaminated, in both directions. The executor binding refuses
            // the same mismatch by the same vault identity.
            if session.vault_id() != self.vault.vault_id() {
                return Err(MemoryError::bad_request(
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
        if effort.requires_rerank() {
            if lease.is_none() {
                return Err(MemoryError::new(
                    MEMORY_CODE_LEASE_REQUIRED,
                    "high, xhigh and max recall require a budget lease",
                    &["Use light or medium, or present a lease."],
                ));
            }
            if execution.reranker.is_none() {
                return Err(MemoryError::bad_request(
                    "paid recall requires a prepared reranker",
                ));
            }
        }
        let worlds = self.recall_worlds(scope)?;
        let canonical_lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let session_view = session
            .map(crate::off_record::OffRecordSession::read_view)
            .transpose()?;
        // The census reads past the asked worlds only to name the ones left
        // out. Every row retrieval reads, ranked or reached through the graph
        // as a neighbour, an edge, a seed or evidence, lies in `worlds`.
        let census = match session_view.as_ref() {
            Some(view) => self
                .vault
                .scoped_read_in_session(canonical_lane.actor_key().clone(), view),
            None => self.vault.scoped_read(canonical_lane.actor_key().clone()),
        };
        let lane = match session_view.as_ref() {
            Some(view) => self
                .vault
                .scoped_read_in_session(canonical_lane.actor_key().clone(), view),
            None => canonical_lane,
        }
        .within_worlds(worlds.clone());
        let mut receipt = lane.read_receipt(None, 0)?;
        let (plan_filter, plan_policy) = lane.recall_plan()?;
        let effective = effort;
        let deep_pending = None;
        let world_scope = if worlds.include_base() && worlds.worlds().is_empty() {
            WorldScope::Base
        } else {
            WorldScope::WorldSet(worlds.clone())
        };
        let pack_format = format.map(parse_pack_format).transpose()?;
        if receipt.applied.deny_all {
            return Ok(MemoryPack {
                items: Vec::new(),
                scope_honesty: ScopeHonesty::default(),
                retrieval_meta: RetrievalMeta {
                    sparse: Some(true),
                    deep_pending,
                    ..RetrievalMeta::default()
                },
                pack_version: MEMORY_PACK_VERSION,
                rendered: None,
                narrowing: Box::new(receipt),
            });
        }
        let kinds = recall_kinds(scope)?;
        // Admission runs in each candidate's retrieval transaction before ranking.
        let admitted = |store: &crate::store::Store, txn: &heed::RoTxn<'_>, id: &EntityId| {
            // Reject irrelevant kind/predicate rows before the actor gate.
            if !candidate_filter.map_or(Ok(true), |filter| filter(store, txn, id))? {
                return Ok(false);
            }
            // A caller's own filter already chose its kinds; otherwise the
            // scope's kinds, or the default kinds, decide.
            if kinds.is_some() || candidate_filter.is_none() {
                let Some(kind) = store
                    .port_entity_record(txn, id)?
                    .map(|row| row.entity_type)
                else {
                    return Ok(false);
                };
                let wanted = match &kinds {
                    Some(kinds) => kinds.contains(&kind),
                    None => !CONTAINER_KINDS.contains(&kind),
                };
                if !wanted {
                    return Ok(false);
                }
            }
            lane.recall_candidate_in(txn, &plan_policy, &plan_filter, id)
        };

        let seeds = if effective != Effort::Light
            && !execution
                .deadline
                .is_some_and(crate::retrieval_depth::RetrievalDeadline::stop_before_stage)
        {
            let hits = match (session, route.as_ref()) {
                (Some(session), Some(route)) => {
                    let limit = lane.search_candidate_limit(PPR_SEED_LIMIT, true, false)?;
                    let raw = session.search_text_routed(route, query, limit)?;
                    let scored = lane.filter_scored_entities(raw)?;
                    receipt.restrict_with(&scored.receipt);
                    scored.value
                }
                _ => {
                    // A deadline's text-stage hook belongs to the principal
                    // retrieval, not its preparatory seed lookup. Still
                    // admit every seed through the actor's read lane, and
                    // read the query's time words on the recall's clock.
                    let scored = if execution.deadline.is_some() {
                        let limit = lane.search_candidate_limit(PPR_SEED_LIMIT, true, false)?;
                        lane.filter_scored_entities(self.vault.search_text(query, limit)?)?
                    } else {
                        lane.search_text_as_of(query, PPR_SEED_LIMIT, None, execution.as_of)?
                    };
                    receipt.restrict_with(&scored.receipt);
                    scored.value
                }
            };
            hits.into_iter()
                .take(PPR_SEED_LIMIT)
                .map(|hit| hit.id)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let (
            items,
            total_candidates,
            rendered,
            retrieval_quality,
            vector_completed,
            temporal_hints,
        ) = match &scope.facet {
            Some(facet_ref) => {
                // Facet-strict narrowing rides the raw retrieval pipeline:
                // ContextPackBuilder exposes no facet passthrough and
                // pipeline.rs/context_pack.rs are consume-only for this
                // chain. No pack rendering on this path.
                let facet_id = self.resolve_ref(facet_ref)?;
                let mut pipeline = self.vault.query().search_text(query, limit);
                if let Some(as_of) = execution.as_of {
                    pipeline = pipeline.with_temporal_now(as_of);
                }
                pipeline = pipeline
                    .facet(&facet_id, FacetMode::Strict)
                    .world(world_scope)
                    .retrieval_effort(effective, &seeds)
                    .authority_filter(plan_filter.clone());
                pipeline = pipeline.filter_candidates(&admitted);
                if let Some(telemetry) = session_telemetry.as_ref() {
                    pipeline = pipeline.in_session(telemetry);
                }

                if let Some(deadline) = execution.deadline {
                    pipeline = pipeline.deadline(deadline);
                }
                if let Some(vector) = execution.embedding {
                    pipeline = pipeline.search_vector(vector, limit);
                }
                if !execution.phonetic_codes.is_empty() {
                    pipeline = pipeline.search_phonetic(execution.phonetic_codes);
                }
                if effective.requires_rerank() {
                    pipeline = pipeline.rerank(
                        execution.reranker.expect("validated reranker"),
                        RerankOptions {
                            top_n: effective.rerank_top_n(),
                            query: Some(query.to_owned()),
                        },
                    );
                }
                pipeline = pipeline
                    .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                    .boost_salience()
                    .boost_confidence();
                let retrieval = pipeline.run_for_pack()?;
                lane.end_recall_plan()?;
                let scoped = lane.filter_scored_entities(retrieval.scores)?;
                receipt.restrict_with(&scoped.receipt);
                let mut items = Vec::new();
                for hit in scoped.value.into_iter().take(limit) {
                    let Some(revision) = retrieval.revisions.get(&hit.id) else {
                        continue;
                    };
                    let mode = crate::vault::ReadMode::Pinned(*revision);
                    if let Some(item) =
                        self.memory_item_for(&lane, &hit.id, Some(facet_id), mode, &mut receipt)?
                    {
                        items.push(item);
                    }
                }
                let total = items.len() as u64;

                (
                    items,
                    total,
                    None,
                    retrieval.retrieval_quality,
                    retrieval.vector_completed,
                    retrieval.temporal_hints,
                )
            }
            None => {
                let mut builder = self.vault.context_pack().search_text(query, limit);
                if let Some(as_of) = execution.as_of {
                    builder = builder.with_temporal_now(as_of);
                }
                builder = builder
                    .limit(limit)
                    .world(world_scope)
                    .retrieval_effort(effective, &seeds)
                    .authority_filter(plan_filter.clone());
                builder = builder.filter_candidates(&admitted);

                if let Some(telemetry) = session_telemetry.as_ref() {
                    builder = builder.in_session(telemetry);
                }
                if let Some(deadline) = execution.deadline {
                    builder = builder.deadline(deadline);
                }
                if let Some(vector) = execution.embedding {
                    builder = builder.search_vector(vector, limit);
                }
                if !execution.phonetic_codes.is_empty() {
                    builder = builder.search_phonetic(execution.phonetic_codes);
                }
                if effective.requires_rerank() {
                    builder = builder.rerank(
                        execution.reranker.expect("validated reranker"),
                        RerankOptions {
                            top_n: effective.rerank_top_n(),
                            query: Some(query.to_owned()),
                        },
                    );
                }
                match effective {
                    Effort::Light => {
                        builder = builder
                            .hydrate(false)
                            .include_edges(false)
                            .field_profile(FieldProfile::Minimal)
                            .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                            .boost_salience()
                            .boost_confidence();
                    }
                    Effort::Medium | Effort::High | Effort::Xhigh | Effort::Max => {
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
                let (scoped, vector_completed, temporal_hints) =
                    builder.run_scoped_with_run_status(&lane)?;
                receipt.restrict_with(&scoped.receipt);
                let mut pack = scoped.value;
                lane.attach_reactions(&mut pack)?;

                let rendered = pack_format.map(|fmt| {
                    let config = SerializeConfig {
                        format: fmt,
                        profile: match effective {
                            Effort::Light => FieldProfile::Minimal,
                            Effort::Medium | Effort::High | Effort::Xhigh | Effort::Max => {
                                FieldProfile::Standard
                            }
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
                    let mode = entity.source_revision_ref.map_or(
                        crate::vault::ReadMode::Indexed,
                        |revision| {
                            crate::vault::ReadMode::Pinned(crate::vault::RevisionRef(revision))
                        },
                    );
                    if let Some(item) =
                        self.memory_item_for(&lane, &entity.id, None, mode, &mut receipt)?
                    {
                        items.push(item);
                    }
                }
                let total = items.len() as u64;

                (
                    items,
                    total,
                    rendered,
                    pack.retrieval_quality,
                    vector_completed,
                    temporal_hints,
                )
            }
        };

        let claims_returned = items.iter().filter(|item| item.kind == "CLAIM").count() as u64;
        Ok(MemoryPack {
            scope_honesty: self.out_of_scope_worlds(&census, &mut receipt, &worlds)?,
            retrieval_meta: RetrievalMeta {
                quality: retrieval_quality.quality,
                degradation: retrieval_quality.degradation,
                confidence_adjustment: retrieval_quality.confidence_adjustment,
                sparse: Some(!vector_completed),
                partial: execution
                    .deadline
                    .is_some_and(crate::retrieval_depth::RetrievalDeadline::was_cut_short),
                total_candidates,
                claims_returned,
                deep_pending,
                temporal_hints,
            },
            items,
            pack_version: MEMORY_PACK_VERSION,
            rendered,
            narrowing: Box::new(receipt),
        })
    }
}

impl Memory<'_> {
    /// The worlds one recall reads (ARCH-0022). A named world reads with base
    /// reality; no name reads the actor's default, base plus its active world.
    /// A handle bound to a room turn meets either with the room's Scope.
    fn recall_worlds(
        &self,
        scope: &RecallScope,
    ) -> MemoryResult<crate::pipeline::WorldAuthoritySet> {
        let requested = match &scope.world_ref {
            Some(world_ref) => {
                crate::pipeline::WorldAuthoritySet::new(true, [self.resolve_ref(world_ref)?])?
            }
            None => self
                .reading_defaults(&[self.actor])?
                .pop()
                .expect("one default per actor"),
        };
        let room = match self.room_turn_now()? {
            Some(turn) => crate::context_board::scope_worlds(&turn.scope)?,
            None => None,
        };
        Ok(match room {
            Some(room) => crate::pipeline::WorldAuthoritySet::new(
                requested.include_base() && room.include_base(),
                requested.worlds().intersection(room.worlds()).copied(),
            )?,
            None => requested,
        })
    }
}
