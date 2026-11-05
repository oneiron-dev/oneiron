use super::super::structural::*;
use super::super::*;
use super::*;
use super::conversation;
use super::home;
use super::presentation::{hedge_bucket_for, hedge_bucket_for_band, parse_pack_format, truncate_text, value_text_of};
use super::render_budget;
use super::render_budget::execution_render_budget;
use super::selection::RecallPin;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, claim_surfaceable};
use crate::claim::retrieval_scope::FacetMode;
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, FieldProfile, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::memory::retrieval_defaults::DEFAULT_RECENCY_HALF_LIFE_DAYS;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::rerank::RerankOptions;
use crate::retrieval_depth::RecallExecution;
use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use crate::serialize::{SerializeConfig, serialize_pack};
use oneiron_model::llm::BudgetLease;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

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
        let filter = |store: &crate::store::StoreRead<'_>,
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
            None,
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
            None,
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
            None, query, effort, scope, limit, format, lease, None, execution, None,
        )
    }

    /// Recalls inside a session. Retrieval reads the room's overlay ∪ base
    /// under the same scope and gates (ARCH-0052 §2); every telemetry write
    /// (including the seed search and pack finalization) rides the one
    /// session route captured for this call. Off-record rows therefore
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
            None,
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
            None,
        )
    }

    /// [`Self::recall_routed`] once its session handle, if any, is bound and
    /// admitted.
    #[expect(
        clippy::too_many_arguments,
        reason = "recall_routed's parameter list, its checked lease aside"
    )]
    fn recall_admitted(
        &self,
        session: Option<&crate::off_record::OffRecordSession<'_>>,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        candidate_filter: Option<&crate::store::retrieval_values::CandidateFilter<'_>>,
        execution: &RecallExecution<'_>,
        pin: Option<&RecallPin>,
    ) -> MemoryResult<MemoryPack> {
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
        // Worlds, projects, facet and kinds, resolved once: an opened
        // device's home narrows by these same values (FIX 2905), and each
        // pass of a paid recall by its first pass's (FIX 5006).
        let unfaceted = self.recall_selection(scope, pin)?;
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
        };
        let lane = match unfaceted.worlds() {
            Some(worlds) => lane.within_worlds(worlds.clone()),
            None => lane,
        };
        // An as_of recall judges each claim's decay and staleness at its
        // as_of, never at the wall clock (FIX 12226).
        let census = census.with_judged_at(execution.as_of);
        let lane = lane.with_judged_at(execution.as_of);
        let mut receipt = lane.read_receipt(None, 0)?;
        let (plan_filter, plan_policy) = lane.recall_plan()?;
        let effective = effort;
        let deep_pending = None;
        let pack_format = format.map(parse_pack_format).transpose()?;
        if receipt.applied.deny_all {
            let mut pack = MemoryPack {
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
                retrieval_run_id: None,
                residence: None,
            };
            pack.stamp_residence(home::local_residence(self.vault, None));
            return Ok(pack);
        }
        // Only a reader past that check has its facet ref looked up: one
        // denied everything answers empty whatever the ref names (FIX 5008).
        let store = lane.store_read();
        let selection = self.recall_faceted(unfaceted, scope, pin, &store)?;
        let worlds = &selection.worlds;
        let projects = &selection.projects;
        let world_scope = selection.world_scope();
        let kinds = &selection.kinds;
        // A scope that names TURN but not MESSAGE still finds a turn by its
        // messages' words: each message comes back as its turn or not at all.
        let turn_fold = kinds.turn_fold();
        // Admission runs in each candidate's retrieval transaction before ranking:
        // the kinds here, then the actor gate under one authority per snapshot
        // (FIX 11648).
        let gate = lane.recall_candidate_gate(&plan_policy, &plan_filter);
        let conversation_gate =
            conversation::ConversationGate::new(&gate, self.vault, &selection.conversations);
        let admitted =
            |store: &crate::store::StoreRead<'_>, txn: &heed::RoTxn<'_>, id: &EntityId| {
                // Reject irrelevant kind/predicate rows before the actor gate.
                if !candidate_filter.map_or(Ok(true), |filter| filter(store, txn, id))? {
                    return Ok(false);
                }
                // A caller's own filter already chose its kinds; otherwise the
                // scope's kinds, or the default kinds, decide.
                if kinds.listed().is_some() || candidate_filter.is_none() {
                    let Some(kind) = store
                        .port_entity_record(txn, id)?
                        .map(|row| row.entity_type)
                    else {
                        return Ok(false);
                    };
                    if !kinds.admits(kind) {
                        return Ok(false);
                    }
                }
                Ok(true)
            };

        // A door that stops waiting at the deadline answers then with the
        // last pack this recall published and drops what the recall returns
        // after it. So past the deadline the recall stops and returns the
        // pack that door published before retrieval, instead of reading and
        // hydrating items no one will read.
        let door_answered = || {
            execution.door_fallback.filter(|_| {
                execution
                    .deadline
                    .is_some_and(crate::retrieval_depth::RetrievalDeadline::answer_due)
            })
        };

        let seeds = if effective != Effort::Light
            && !execution
                .deadline
                .is_some_and(crate::retrieval_depth::RetrievalDeadline::stop_before_stage)
        {
            let hits = match (session, route.as_ref()) {
                (Some(session), Some(route)) => {
                    let limit = lane.search_candidate_limit(PPR_SEED_LIMIT)?;
                    // Seeds come from what the lane reads: a reader that
                    // reads base alone in the room seeds from base alone.
                    let raw = if lane.reads_room() {
                        session.search_text_routed(route, query, limit)?
                    } else {
                        session.search_base_text_routed(route, query, limit)?
                    };
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
                        let limit = lane.search_candidate_limit(PPR_SEED_LIMIT)?;
                        lane.filter_scored_entities(self.vault.search_text(query, limit)?)?
                    } else {
                        lane.search_text_as_of(query, PPR_SEED_LIMIT, None, execution.as_of)?
                    };
                    receipt.restrict_with(&scored.receipt);
                    scored.value
                }
            };
            // Admitted seeds rank by claim source, as the pack does, before
            // the cut. The body read only orders them; it admits nothing.
            let reads: Vec<_> = hits.iter().map(|hit| PointRead::id(hit.id)).collect();
            let mut seeds = Vec::with_capacity(hits.len());
            for (hit, row) in hits.into_iter().zip(lane.read(&reads, None)?.value) {
                let body = match row {
                    Some(crate::claim::ReadRow {
                        entity_type: ENTITY_TYPE_CLAIM,
                        body: Some(body),
                        ..
                    }) => Some(crate::claim::decode_claim_body(&body, true)?),
                    _ => None,
                };
                seeds.push((hit, body));
            }
            crate::context_pack::source_ranking::rank(
                &mut seeds,
                &Default::default(),
                |(hit, body)| (hit.score, body.as_ref()),
            )?;
            seeds
                .into_iter()
                .take(PPR_SEED_LIMIT)
                .map(|(hit, _)| hit.id)
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
            retrieval_run_id,
        ) = {
            let mut builder = self
                .vault
                .context_pack()
                .memory_results_only()
                .search_text(query, limit)
                .fold_messages_into_turns(turn_fold);
            if let Some(telemetry) = execution.telemetry {
                builder = builder.capture_retrieval_trace(telemetry.capture_trace);
                if let Some(turn) = telemetry.turn {
                    builder = builder.retrieval_turn(turn);
                }
            }
            if let Some(as_of) = execution.as_of {
                builder = builder.with_temporal_now(as_of);
            }
            if let Some(vad) = execution.query_affect {
                builder = builder.query_affect(vad);
            }
            // The rendering budget the door resolved sizes the pack it
            // assembles and the text it renders alike (FIX 9962).
            let budget = render_budget::execution_render_budget(execution);
            builder = builder
                .limit(limit)
                .world(world_scope)
                .corpus(projects.clone())
                .retrieval_effort(effective, &seeds)
                .authority_filter(plan_filter.clone())
                .token_budget(budget);
            builder = builder
                .filter_candidates(&admitted)
                .gate_candidates(&conversation_gate);
            // A facet narrows strictly inside this same builder (FIX 9961):
            // the pack it admits and pins is the one its items and its
            // rendering are read from, and it walks no edges, so nothing
            // outside the facet enters either. It selects as the facet route
            // always did: the limit alone, with no per-kind ceiling and no
            // share for non-base worlds.
            if let Some(facet_id) = selection.facet {
                builder = builder
                    .facet(&facet_id, FacetMode::Strict)
                    .retrieval_budget(crate::context_pack::ContextPackRetrievalBudget {
                        claims: limit,
                        turns: limit,
                        summaries: limit,
                        facets: limit,
                        other: limit,
                        selected_edges: 0,
                    })
                    .non_base_world_claim_fraction(1.0);
            }

            if let Some(telemetry) = session_telemetry.as_ref() {
                builder = builder.in_session(telemetry);
            }
            if session_view.is_some() {
                builder = builder.reading(lane.store_read());
            }
            if let Some(deadline) = execution.deadline {
                builder = builder.deadline(deadline);
            }
            if let Some(vector) = execution.embedding {
                builder = builder.search_vector(vector, limit);
            }
            if effective.requires_rerank()
                && let Some((expander, grounding, options)) = execution.hyde
            {
                builder = builder.hyde(expander, grounding.clone(), options);
            }
            for seed in execution.media {
                builder =
                    builder.search_media(seed.space, seed.kind, seed.vector, seed.kinds, limit);
            }
            if !execution.phonetic_codes.is_empty() {
                builder = builder.search_phonetic(execution.phonetic_codes);
            }
            if effective.requires_rerank()
                && let Some(reranker) = execution.reranker
            {
                builder = builder.rerank(
                    reranker,
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
                        .include_edges(selection.facet.is_none())
                        .edge_hop(1)
                        .hydrate(true)
                        .field_profile(FieldProfile::Standard)
                        .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                        .boost_salience()
                        .boost_confidence();
                }
            }
            let (scoped, status) = builder.run_scoped_with_run_status(&lane)?;
            receipt.restrict_with(&scoped.receipt);
            if let Some(fallback) = door_answered() {
                return Ok(fallback.clone());
            }
            let mut pack = scoped.value;
            let mut counted = Vec::new();
            lane.attach_reactions_quoting(&mut pack, &status.cited_messages, None, &mut counted)?;
            // Each reaction claim a line counts is a producer of the pack.
            self.produced_from(counted);

            let rendered = pack_format.map(|fmt| {
                let config = SerializeConfig {
                    format: fmt,
                    profile: match effective {
                        Effort::Light => FieldProfile::Minimal,
                        Effort::Medium | Effort::High | Effort::Xhigh | Effort::Max => {
                            FieldProfile::Standard
                        }
                    },
                    budget,
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
                if let Some(fallback) = door_answered() {
                    return Ok(fallback.clone());
                }
                let mode = entity
                    .source_revision_ref
                    .map_or(crate::vault::ReadMode::Indexed, |revision| {
                        crate::vault::ReadMode::Pinned(crate::vault::RevisionRef(revision))
                    });
                let cited = status
                    .cited_messages
                    .get(&entity.id)
                    .map_or(&[][..], Vec::as_slice);
                if let Some(mut item) = self.memory_item_for(
                    &lane,
                    &entity.id,
                    selection.facet,
                    mode,
                    cited,
                    &mut receipt,
                )? {
                    item.embedding_matches = status
                        .embedding_matches
                        .get(&entity.id)
                        .cloned()
                        .unwrap_or_default();
                    items.push(item);
                }
            }
            let total = items.len() as u64;

            (
                items,
                total,
                rendered,
                pack.retrieval_quality,
                status.vector_completed,
                status.temporal_hints,
                status.run_id,
            )
        };

        let claims_returned = items.iter().filter(|item| item.kind == "CLAIM").count() as u64;
        let mut pack = MemoryPack {
            scope_honesty: ScopeHonesty::default(),
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
                rerank: None,
                limit_clamped: false,
            },
            items,
            pack_version: MEMORY_PACK_VERSION,
            rendered,
            narrowing: Box::new(receipt),
            retrieval_run_id,
            residence: None,
        };
        // An opened device's answer is its own items alone (FIX 2905); the
        // stamp keeps what this recall narrowed by, for its home.
        pack.stamp_residence(home::local_residence(self.vault, Some(&selection)));
        if let Some(on_cut) = execution.on_cut {
            // The items are ready. A door that stops waiting during the
            // census answers with them, the census marked unfinished.
            let mut ready = pack.clone();
            ready.scope_honesty.census_capped = true;
            ready.mark_cut();
            on_cut(ready);
        }
        if let Some(worlds) = &worlds {
            pack.scope_honesty =
                self.out_of_scope_worlds(&census, &mut pack.narrowing, worlds, execution.deadline)?;
        }
        Ok(pack)
    }
}
