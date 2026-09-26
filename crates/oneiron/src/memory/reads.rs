//! Entity/claim read surface plus BM25 and neighbor queries.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::read_lane::{ReadTargetSlot, fold_receipt};
use super::recall::*;
use super::structural::*;
use super::support::*;
use super::*;

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimReadStatus, PointRead, ScopedReadResult};
fn companion_value_to_json(value: &rmpv::Value) -> serde_json::Value {
    let mut value = crate::companion::companion_value_to_json(value);
    crate::batch::export::redact_credentials(&mut value);
    value
}
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_CLAIM;

const SNIPPET_MAX_CHARS: usize = 160;

/// Claim ids read per lane read while listing: a bounded list stops early.
const CLAIM_LIST_READ_CHUNK: usize = 256;

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
    //
    // Every read verb opens the bound actor's `read_lane` and returns the
    // lane's receipt with its result. Record verbs (get, hydrate, claim list
    // and history, neighbors) serve every claim status; the BM25 channel
    // serves surfaceable claims only.

    /// Reads one entity as a typed view. `None` when absent or withheld; the
    /// receipt says which.
    pub fn get_entity(
        &self,
        entity_ref: &str,
    ) -> MemoryResult<ScopedReadResult<Option<EntityView>>> {
        if let Some((reference, revision)) = entity_ref.rsplit_once('@') {
            let revision = crate::vault::RevisionRef::from_hex(revision)?;
            return self.get_entity_with_mode(reference, crate::vault::ReadMode::Pinned(revision));
        }
        self.get_entity_with_mode(entity_ref, crate::vault::ReadMode::Live)
    }

    /// Reads LIVE, the last indexed revision, or an exact retained pin.
    pub fn get_entity_with_mode(
        &self,
        entity_ref: &str,
        mode: crate::vault::ReadMode,
    ) -> MemoryResult<ScopedReadResult<Option<EntityView>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let target = self.read_target(entity_ref, mode)?;
        Ok(self.read_views(&lane, &[target])?.single())
    }

    /// Hydrates every ref through the same explicit read frontier.
    pub fn hydrate_with_mode(
        &self,
        refs: &[String],
        mode: crate::vault::ReadMode,
    ) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let targets = refs
            .iter()
            .map(|reference| self.read_target(reference, mode))
            .collect::<MemoryResult<Vec<_>>>()?;
        self.hydrated(
            &lane,
            refs,
            &targets,
            "does not resolve at requested revision",
        )
    }

    /// Hydrates short refs (or hex ids, each optionally `@<revision>`) to full
    /// entity views. Unresolvable refs are typed errors — hydrate is the
    /// OF-096 round-trip contract — and that `NOT_FOUND` carries the receipt.
    pub fn hydrate(&self, refs: &[String]) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let targets = refs
            .iter()
            .map(|reference| match reference.rsplit_once('@') {
                Some((reference, revision)) => self.read_target(
                    reference,
                    crate::vault::ReadMode::Pinned(crate::vault::RevisionRef::from_hex(revision)?),
                ),
                None => self.read_target(reference, crate::vault::ReadMode::Live),
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        self.hydrated(&lane, refs, &targets, "does not resolve")
    }

    /// One hydrate read: every view, or `NOT_FOUND` naming the first ref that
    /// is absent or withheld, under the read's receipt either way.
    fn hydrated(
        &self,
        lane: &crate::claim::ScopedRead<'_>,
        refs: &[String],
        targets: &[ReadTargetSlot],
        unresolved: &str,
    ) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        let ScopedReadResult { value, receipt } = self.read_views(lane, targets)?;
        let mut views = Vec::with_capacity(value.len());
        for (reference, view) in refs.iter().zip(value) {
            let Some(view) = view else {
                return Err(
                    MemoryError::not_found(format!("entity {reference:?} {unresolved}"))
                        .with_read_receipt(receipt),
                );
            };
            views.push(view);
        }
        Ok(ScopedReadResult {
            value: views,
            receipt,
        })
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by
    /// `filter.limit`. History and proposed claims are part of this verb.
    pub fn claim_list(
        &self,
        filter: &ClaimListFilter,
    ) -> MemoryResult<ScopedReadResult<Vec<ClaimView>>> {
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
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ids = match &filter.subject_ref {
            Some(subject_ref) => {
                let subject = self.resolve_ref_in_lane(&lane, subject_ref)?;
                self.vault.claims_for_subject(&subject)?
            }
            None => self.vault.entities_by_type(ENTITY_TYPE_CLAIM)?,
        };
        let mut receipt = None;
        let mut views = Vec::new();
        for chunk in ids.chunks(CLAIM_LIST_READ_CHUNK) {
            if views.len() >= filter.limit {
                break;
            }
            let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
            let ScopedReadResult {
                value,
                receipt: read,
            } = lane.read(&reads, None)?;
            fold_receipt(&mut receipt, read);
            for row in value.into_iter().flatten() {
                if views.len() >= filter.limit {
                    break;
                }
                let Some(bytes) = row.body.as_deref() else {
                    continue;
                };
                let body = crate::claim::decode_claim_body(bytes, true)?;
                if filter
                    .predicate
                    .as_ref()
                    .is_some_and(|predicate| body.predicate != *predicate)
                    || lifecycle.is_some_and(|lifecycle| body.lifecycle != lifecycle)
                {
                    continue;
                }
                views.push(self.claim_view(&row.id, &body)?);
            }
        }
        let receipt = match receipt {
            Some(receipt) => receipt,
            None => lane.read_receipt(None, 0)?,
        };
        Ok(ScopedReadResult {
            value: views,
            receipt,
        })
    }

    /// Returns the supersession timeline for one claim, oldest first.
    pub fn claim_history(&self, claim_ref: &str) -> MemoryResult<ScopedReadResult<Vec<ClaimView>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref_in_lane(&lane, claim_ref)?;
        let ScopedReadResult {
            value: timeline,
            mut receipt,
        } = lane.memory_timeline(&id)?;
        let mut records: Vec<_> = timeline
            .records
            .into_iter()
            .filter(|record| record.entity_type == Some(ENTITY_TYPE_CLAIM))
            .collect();
        records.sort_by_key(|record| (record.learned_at.unwrap_or(0), record.id.to_hex()));
        let reads: Vec<_> = records
            .iter()
            .map(|record| PointRead::id(record.id))
            .collect();
        let rows = lane.read(&reads, None)?;
        receipt.restrict_with(&rows.receipt);
        let mut views = Vec::with_capacity(records.len());
        for row in rows.value.into_iter().flatten() {
            let Some(bytes) = row.body.as_deref() else {
                continue;
            };
            let body = crate::claim::decode_claim_body(bytes, true)?;
            views.push(self.claim_view(&row.id, &body)?);
        }
        Ok(ScopedReadResult {
            value: views,
            receipt,
        })
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
    /// re-implementation). A retrieval channel: surfaceable claims only.
    pub fn query_bm25(
        &self,
        query: &str,
        limit: usize,
    ) -> MemoryResult<ScopedReadResult<Vec<LexicalHit>>> {
        if limit == 0 {
            return Err(MemoryError::bad_request(
                "query_bm25 limit must be at least 1",
            ));
        }
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let ScopedReadResult {
            value: hits,
            mut receipt,
        } = lane.filter_scored_entities(self.vault.search_text(query, limit)?)?;
        let reads: Vec<_> = hits.iter().map(|hit| PointRead::id(hit.id)).collect();
        let rows = lane.read(&reads, None)?;
        receipt.restrict_with(&rows.receipt);
        let mut out = Vec::with_capacity(hits.len());
        for (hit, row) in hits.iter().zip(rows.value) {
            let Some(row) = row else {
                continue;
            };
            let snippet = row
                .body
                .as_deref()
                .and_then(decode_body_json)
                .and_then(|body| {
                    body.get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(|content| truncate_text(content, SNIPPET_MAX_CHARS))
                });
            out.push(LexicalHit {
                short_id: self.short_ref_or_hex(&hit.id)?,
                kind: kind_string_for_type(row.entity_type),
                score: hit.score,
                snippet,
            });
        }
        Ok(ScopedReadResult {
            value: out,
            receipt,
        })
    }

    /// Weighted-edge neighborhood of one entity, filtered engine-side by
    /// edge kind and minimum weight. The anchor and every neighbor are read
    /// through the lane; an unreadable anchor has no neighborhood.
    pub fn neighbors(
        &self,
        entity_ref: &str,
        opts: &NeighborOpts,
    ) -> MemoryResult<ScopedReadResult<Vec<NeighborHit>>> {
        if opts.limit == 0 {
            return Err(MemoryError::bad_request(
                "neighbors limit must be at least 1",
            ));
        }
        let kind_filter = match opts.edge_kind.as_deref() {
            Some(name) => Some(EdgeKind::from_name(name).ok_or_else(|| {
                MemoryError::bad_request_with(
                    format!("unknown edge kind {name:?}"),
                    &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                )
            })?),
            None => None,
        };
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref_in_lane(&lane, entity_ref)?;
        let anchor = lane.read(&[PointRead::id(id)], None)?.single();
        let mut receipt = anchor.receipt;
        let mut hits = Vec::new();
        if anchor.value.is_none() {
            return Ok(ScopedReadResult {
                value: hits,
                receipt,
            });
        }
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
            let reads: Vec<_> = edges
                .iter()
                .map(|edge| PointRead::id(edge.target))
                .collect();
            let rows = lane.read(&reads, None)?;
            receipt.restrict_with(&rows.receipt);
            for (edge, row) in edges.iter().zip(rows.value) {
                let Some(row) = row else {
                    continue;
                };
                hits.push(NeighborHit {
                    short_id: self.short_ref_or_hex(&edge.target)?,
                    kind: kind_string_for_type(row.entity_type),
                    edge_kind: edge.kind.name().to_owned(),
                    weight: edge.weight,
                    direction: direction.to_owned(),
                });
            }
        }
        Ok(ScopedReadResult {
            value: hits,
            receipt,
        })
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

    pub(crate) fn entity_ref_receipt(&self, id: &EntityId) -> MemoryResult<EntityRefReceipt> {
        Ok(EntityRefReceipt {
            entity_ref: self.short_ref_or_hex(id)?,
            id_hex: id.to_hex(),
            receipt_ref: format!("put:{}", id.to_hex()),
        })
    }
}
