//! Entity/claim read surface plus BM25 and neighbor queries.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::recall::*;
use super::structural::*;
use super::support::*;
use super::*;

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::companion::companion_value_to_json;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::registry::ENTITY_TYPE_CLAIM;

const SNIPPET_MAX_CHARS: usize = 160;

/// Typed read-back view of one claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimView {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Short-id ref, when assigned.
    pub short_ref: Option<String>,
    /// Predicate.
    pub predicate: String,
    /// Subject: entity hex, or `edge:<src>:<kind>:<tgt>` for edge subjects.
    pub subject_ref: String,
    /// Claim value as JSON.
    pub value: serde_json::Value,
    /// Confidence.
    pub confidence: f32,
    /// Approval string.
    pub approval: String,
    /// Lifecycle string.
    pub lifecycle: String,
    /// Source string, when stamped.
    pub source: Option<String>,
    /// World hex, when world-scoped.
    pub world_ref: Option<String>,
    /// Scope as JSON, when present.
    pub scope: Option<serde_json::Value>,
    /// Validity window start.
    pub valid_from: Option<u64>,
    /// Validity window end.
    pub valid_to: Option<u64>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
    /// Stale marker.
    pub stale: bool,
}

/// Filter for [`Memory::claim_list`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimListFilter {
    /// Restrict to claims on this subject (short-id ref or hex).
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    pub predicate: Option<String>,
    /// Restrict to this lifecycle (`active`/`superseded`/`retracted`).
    pub lifecycle: Option<String>,
    /// Maximum results (required; no unbounded scans).
    pub limit: usize,
}

/// One BM25 hit (engine index scores, never re-ranked app-side).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LexicalHit {
    /// Short ref (hex fallback).
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Engine BM25F score.
    pub score: f32,
    /// Content preview, when the body carries a `content` field.
    pub snippet: Option<String>,
}

/// Options for [`Memory::neighbors`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NeighborOpts {
    /// Restrict to this snake_case `EdgeKind` name.
    pub edge_kind: Option<String>,
    /// Drop edges below this weight (engine-side filter).
    pub min_weight: Option<f32>,
    /// Maximum hits (required; no unbounded scans).
    pub limit: usize,
}

/// One graph neighbor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborHit {
    /// Short ref of the neighboring entity (hex fallback).
    pub short_id: String,
    /// Registry kind string of the neighbor.
    pub kind: String,
    /// snake_case `EdgeKind` name.
    pub edge_kind: String,
    /// Stored edge weight.
    pub weight: f32,
    /// `out` (edge from the anchor) or `in` (edge into the anchor).
    pub direction: String,
}

impl Memory<'_> {
    // ── read verbs ──────────────────────────────────────────────────────

    /// Reads one entity as a typed view. `Ok(None)` when absent.
    pub fn get_entity(&self, entity_ref: &str) -> MemoryResult<Option<EntityView>> {
        let id = match self.resolve_ref(entity_ref) {
            Ok(id) => id,
            Err(err) if err.code == MEMORY_CODE_NOT_FOUND => return Ok(None),
            Err(err) => return Err(err),
        };
        self.entity_view(&id)
    }

    /// Hydrates short refs (or hex ids) to full entity views. Unresolvable
    /// refs are typed errors — hydrate is the OF-096 round-trip contract.
    pub fn hydrate(&self, refs: &[String]) -> MemoryResult<Vec<EntityView>> {
        let mut views = Vec::with_capacity(refs.len());
        for reference in refs {
            let id = self.resolve_ref(reference)?;
            let Some(view) = self.entity_view(&id)? else {
                return Err(MemoryError::not_found(format!(
                    "entity {reference:?} does not resolve"
                )));
            };
            views.push(view);
        }
        Ok(views)
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by
    /// `filter.limit`.
    pub fn claim_list(&self, filter: &ClaimListFilter) -> MemoryResult<Vec<ClaimView>> {
        if filter.limit == 0 {
            return Err(MemoryError::bad_request(
                "claim_list limit must be at least 1",
            ));
        }
        let lifecycle = match filter.lifecycle.as_deref() {
            Some(value) => Some(ClaimLifecycleStatus::parse(value).ok_or_else(|| {
                MemoryError::bad_request_with(
                    format!("unknown lifecycle {value:?}"),
                    &["Use one of: active, superseded, retracted."],
                )
            })?),
            None => None,
        };
        let ids = match &filter.subject_ref {
            Some(subject_ref) => {
                let subject = self.resolve_ref(subject_ref)?;
                self.vault.claims_for_subject(&subject)?
            }
            None => self.vault.entities_by_type(ENTITY_TYPE_CLAIM)?,
        };
        let mut views = Vec::new();
        for id in ids {
            if views.len() >= filter.limit {
                break;
            }
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if let Some(predicate) = &filter.predicate
                && body.predicate != *predicate
            {
                continue;
            }
            if let Some(lifecycle) = lifecycle
                && body.lifecycle != lifecycle
            {
                continue;
            }
            views.push(self.claim_view(&id, &body)?);
        }
        Ok(views)
    }

    /// Returns the supersession timeline for one claim, oldest first.
    pub fn claim_history(&self, claim_ref: &str) -> MemoryResult<Vec<ClaimView>> {
        let id = self.resolve_ref(claim_ref)?;
        let timeline = self.vault.memory_timeline(&id)?;
        let mut records: Vec<_> = timeline
            .records
            .into_iter()
            .filter(|record| record.entity_type == Some(ENTITY_TYPE_CLAIM))
            .collect();
        records.sort_by_key(|record| (record.learned_at.unwrap_or(0), record.id.to_hex()));
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            if let Some(body) = self.vault.get_claim(&record.id)? {
                views.push(self.claim_view(&record.id, &body)?);
            }
        }
        Ok(views)
    }

    /// Lists gated writes parked for consent, newest lane state first.
    pub fn pending_writes(&self, limit: usize) -> MemoryResult<Vec<PendingWrite>> {
        let records = self.vault.pending_gate_consents(limit)?;
        Ok(records
            .into_iter()
            .map(|record| PendingWrite {
                claim_ref: hex_string(&record.claim_id),
                decision_ref: format!("gate:{}", record.decision_id.to_hex()),
                created_at: record.created_at,
                reason_codes: record.reason_codes,
                dreamer_run_id: record.dreamer_run_id,
            })
            .collect())
    }

    /// Lists gate decision receipts.
    pub fn receipts(&self, limit: usize) -> MemoryResult<Vec<MemoryReceipt>> {
        let records = self.vault.gate_decisions(limit)?;
        Ok(records
            .into_iter()
            .map(|record| MemoryReceipt {
                receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
                outcome: record.outcome,
                created_at: record.created_at,
                reason_codes: record.reason_codes,
                actor_class: record.actor_class,
                actor_ref: record.actor_ref,
                content_kind: record.content_kind,
                claim_ref: record.claim_id.map(|id| hex_string(&id)),
            })
            .collect())
    }

    // ── query verbs (BRIDGE-02) ─────────────────────────────────────────

    /// BM25 text query over the engine index (engine scores, never a
    /// re-implementation).
    pub fn query_bm25(&self, query: &str, limit: usize) -> MemoryResult<Vec<LexicalHit>> {
        if limit == 0 {
            return Err(MemoryError::bad_request(
                "query_bm25 limit must be at least 1",
            ));
        }
        let hits = self.vault.search_text(query, limit)?;
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
            let Some(entity_type) = self.vault.get_entity_type(&hit.id)? else {
                continue;
            };
            let snippet = self
                .entity_view(&hit.id)?
                .and_then(|view| view.body)
                .and_then(|body| {
                    body.get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(|content| truncate_text(content, SNIPPET_MAX_CHARS))
                });
            out.push(LexicalHit {
                short_id: self.short_ref_or_hex(&hit.id)?,
                kind: kind_string_for_type(entity_type),
                score: hit.score,
                snippet,
            });
        }
        Ok(out)
    }

    /// Weighted-edge neighborhood of one entity, filtered engine-side by
    /// edge kind and minimum weight.
    pub fn neighbors(
        &self,
        entity_ref: &str,
        opts: &NeighborOpts,
    ) -> MemoryResult<Vec<NeighborHit>> {
        if opts.limit == 0 {
            return Err(MemoryError::bad_request(
                "neighbors limit must be at least 1",
            ));
        }
        let kind_filter = match opts.edge_kind.as_deref() {
            Some(name) => Some(edge_kind_from_str(name).ok_or_else(|| {
                MemoryError::bad_request_with(
                    format!("unknown edge kind {name:?}"),
                    &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                )
            })?),
            None => None,
        };
        let id = self.resolve_ref(entity_ref)?;
        let mut hits = Vec::new();
        // Push kind/min_weight/limit into the LMDB prefix walk per direction
        // so a high-degree node stops after `limit` matches instead of
        // materializing its full edge set (which errors with IndexOverflow
        // past MAX_EDGE_QUERY_RESULTS).
        for (direction, outbound) in [("out", true), ("in", false)] {
            let remaining = opts.limit - hits.len();
            if remaining == 0 {
                break;
            }
            let edges = self.vault.neighbor_edges_bounded(
                &id,
                outbound,
                kind_filter,
                opts.min_weight,
                remaining,
            )?;
            for edge in edges {
                let kind = self
                    .vault
                    .get_entity_type(&edge.target)?
                    .map_or_else(|| "UNKNOWN".to_owned(), kind_string_for_type);
                hits.push(NeighborHit {
                    short_id: self.short_ref_or_hex(&edge.target)?,
                    kind,
                    edge_kind: edge_kind_name(edge.kind).to_owned(),
                    weight: edge.weight,
                    direction: direction.to_owned(),
                });
            }
        }
        Ok(hits)
    }

    pub(super) fn entity_view(&self, id: &EntityId) -> MemoryResult<Option<EntityView>> {
        let Some(raw) = self.vault.get_raw(id)? else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or_else(|| MemoryError::from(Error::CorruptedIndex("entity header")))?;
        let body = decode_body_json(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
        Ok(Some(EntityView {
            id_hex: id.to_hex(),
            short_ref: self.short_ref_of(id)?,
            kind: kind_string_for_type(header.entity_type),
            occurred_start: header.occurred_start,
            occurred_end: header.occurred_end,
            learned_at: header.learned_at,
            body,
        }))
    }

    fn claim_view(&self, id: &EntityId, body: &ClaimBody) -> MemoryResult<ClaimView> {
        Ok(ClaimView {
            claim_ref: id.to_hex(),
            short_ref: self.short_ref_of(id)?,
            predicate: body.predicate.clone(),
            subject_ref: subject_ref_string(&body.subject),
            value: companion_value_to_json(&body.value),
            confidence: body.confidence,
            approval: body.approval.as_str().to_owned(),
            lifecycle: body.lifecycle.as_str().to_owned(),
            source: body.source.map(|source| source.as_str().to_owned()),
            world_ref: body.world.map(|world| world.to_hex()),
            scope: body.scope.as_ref().map(companion_value_to_json),
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            salience: body.salience,
            stale: body.stale,
        })
    }

    pub(super) fn entity_ref_receipt(&self, id: &EntityId) -> MemoryResult<EntityRefReceipt> {
        Ok(EntityRefReceipt {
            entity_ref: self.short_ref_or_hex(id)?,
            id_hex: id.to_hex(),
            receipt_ref: format!("put:{}", id.to_hex()),
        })
    }
}

/// snake_case name of an `EdgeKind` (inverse of `edge_kind_from_str`).
pub(super) const fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::AuthoredBy => "authored_by",
        EdgeKind::ScopedTo => "scoped_to",
        EdgeKind::PartOf => "part_of",
        EdgeKind::Supersedes => "supersedes",
        EdgeKind::BelongsTo => "belongs_to",
        EdgeKind::ClaimOf => "claim_of",
        EdgeKind::ChildOf => "child_of",
        EdgeKind::AssignedTo => "assigned_to",
        EdgeKind::DerivedFrom => "derived_from",
        EdgeKind::Mentions => "mentions",
        EdgeKind::About => "about",
        EdgeKind::Supports => "supports",
        EdgeKind::Opposes => "opposes",
        EdgeKind::ParticipatesIn => "participates_in",
        EdgeKind::Attached => "attached",
        EdgeKind::EmployedBy => "employed_by",
        EdgeKind::HasFacet => "has_facet",
        EdgeKind::FacetOf => "facet_of",
        EdgeKind::InWorld => "in_world",
        EdgeKind::SetIn => "set_in",
        EdgeKind::MergedInto => "merged_into",
        EdgeKind::SplitInto => "split_into",
        EdgeKind::BlockedBy => "blocked_by",
        EdgeKind::Blocks => "blocks",
        EdgeKind::Fulfills => "fulfills",
        EdgeKind::DischargedBy => "discharged_by",
        EdgeKind::SameAs => "same_as",
    }
}
