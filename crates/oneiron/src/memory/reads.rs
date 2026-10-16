//! Entity/claim read surface plus BM25 and neighbor queries.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::read_lane::{ReadTargetSlot, fold_receipt};
use super::recall::*;
use super::structural::*;
use super::support::*;
use super::*;

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimReadStatus, PointRead, ScopedReadResult};
fn served_value_json(value: &rmpv::Value) -> serde_json::Value {
    crate::batch::export::served_messagepack_json(value.clone())
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
            false,
        )
    }

    /// Hydrates short refs (or hex ids, each optionally `@<revision>`) to full
    /// entity views. Unresolvable refs are typed errors — hydrate is the
    /// OF-096 round-trip contract — and that `NOT_FOUND` carries the receipt.
    pub fn hydrate(&self, refs: &[String]) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        self.hydrate_reading(refs, false)
    }

    /// [`Self::hydrate`] for a door that renders the views through a pack
    /// writer: a body the write door refuses is withheld whole
    /// ([`Self::read_views_whole_body`]).
    pub(super) fn hydrate_whole_body(
        &self,
        refs: &[String],
    ) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        self.hydrate_reading(refs, true)
    }

    fn hydrate_reading(
        &self,
        refs: &[String],
        whole_body: bool,
    ) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
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
        self.hydrated(&lane, refs, &targets, "does not resolve", whole_body)
    }

    /// One hydrate read: every view, or `NOT_FOUND` naming the first ref that
    /// is absent or withheld, under the read's receipt either way. An image
    /// ASSET is served in its resolved form (OF-329), and every text form
    /// served is recorded as a served-form receipt before the views return.
    fn hydrated(
        &self,
        lane: &crate::claim::ScopedRead<'_>,
        refs: &[String],
        targets: &[ReadTargetSlot],
        unresolved: &str,
        whole_body: bool,
    ) -> MemoryResult<ScopedReadResult<Vec<EntityView>>> {
        let ScopedReadResult { value, mut receipt } = if whole_body {
            self.read_views_whole_body(lane, targets)?
        } else {
            self.read_views(lane, targets)?
        };
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
        self.serve_hydrated_assets(lane, targets, &mut views, &mut receipt)?;
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

    /// Lists gated writes parked for consent, newest lane state first. A
    /// caller off this device sees none about a device-local claim, and none
    /// takes a place in its page.
    pub fn pending_writes(&self, limit: usize) -> MemoryResult<Vec<PendingWrite>> {
        let off_device = self.locality == crate::claim::CallerLocality::OffDevice;
        let mut records =
            self.vault
                .pending_gate_consents(if off_device { usize::MAX } else { limit })?;
        if off_device {
            let mut admitted = Vec::new();
            for record in records {
                if admitted.len() == limit {
                    break;
                }
                if !self
                    .vault
                    .device_local_keeps(&EntityId::from_bytes(record.claim_id)?)?
                {
                    admitted.push(record);
                }
            }
            records = admitted;
        }
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

    /// Lists gate decision receipts. A caller off this device sees none about
    /// a device-local claim, and none takes a place in its page.
    pub fn receipts(&self, limit: usize) -> MemoryResult<Vec<MemoryReceipt>> {
        let mut records = Vec::new();
        let mut before = None;
        while records.len() < limit {
            let page = self.vault.store.gate_decisions_page(before, limit)?;
            let exhausted = page.len() < limit;
            before = page.last().map(|record| record.decision_id);
            for record in page {
                if records.len() == limit {
                    break;
                }
                let kept = self.locality == crate::claim::CallerLocality::OffDevice
                    && match record.claim_id {
                        Some(id) => self.vault.device_local_keeps(&EntityId::from_bytes(id)?)?,
                        None => false,
                    };
                if !kept {
                    records.push(record);
                }
            }
            if exhausted || before.is_none() {
                break;
            }
        }
        Ok(records
            .into_iter()
            .map(|record| MemoryReceipt {
                receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
                kind: crate::receipt::ReceiptKind::Gate.as_str().to_owned(),
                outcome: record.outcome,
                created_at: record.created_at,
                reason_codes: record.reason_codes,
                actor_class: record.actor_class,
                actor_ref: record.actor_ref,
                content_kind: record.content_kind,
                claim_ref: record.claim_id.map(|id| hex_string(&id)),
                fields: std::collections::BTreeMap::new(),
            })
            .collect())
    }

    /// `vault.receipts`: with no `kinds`, [`Self::receipts`], the gate
    /// decision ledger. With kinds (`ReceiptKind` names: `gate`, `hook`,
    /// `outbound`, ...), the unified receipt family's receipts of those
    /// kinds, newest first, each in the same shape with its own fields. A
    /// caller off this device sees none whose trigger is a device-local row.
    /// An unknown kind is refused.
    pub fn receipts_of_kinds(
        &self,
        limit: usize,
        kinds: &[String],
    ) -> MemoryResult<Vec<MemoryReceipt>> {
        if kinds.is_empty() {
            return self.receipts(limit);
        }
        let mut query = crate::receipt::ReceiptQuery::new(limit);
        for name in kinds {
            let kind = crate::receipt::ReceiptKind::parse(name.trim()).ok_or_else(|| {
                MemoryError::bad_request_with(
                    format!("unknown receipt kind {name:?}"),
                    &[
                        "Use one of: outbound, gate, identity_lifecycle, scoped_read, share, artifact_settle, proposal_outcome, commitment_lifecycle, extraction, served_form, hook.",
                    ],
                )
            })?;
            query = query.with_kind(kind);
        }
        let mut receipts = Vec::new();
        for record in self.vault.receipts(query)? {
            let trigger = record.trigger_ref.as_deref().and_then(|reference| {
                EntityId::from_hex(reference.strip_prefix("claim:").unwrap_or(reference)).ok()
            });
            let withheld = match trigger {
                Some(id) if self.locality == crate::claim::CallerLocality::OffDevice => {
                    self.vault.device_local_keeps(&id)?
                }
                _ => false,
            };
            if !withheld {
                receipts.push(family_receipt(record));
            }
        }
        Ok(receipts)
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
        // Admitted hits rank by claim source, as the pack does.
        let mut ranked = Vec::with_capacity(hits.len());
        for (hit, row) in hits.into_iter().zip(rows.value) {
            let Some(row) = row else {
                continue;
            };
            let body = match row.body.as_deref() {
                Some(body) if row.entity_type == ENTITY_TYPE_CLAIM => {
                    Some(crate::claim::decode_claim_body(body, true)?)
                }
                _ => None,
            };
            ranked.push((hit, row, body));
        }
        let scores = crate::context_pack::source_ranking::rank(
            &mut ranked,
            &Default::default(),
            |(hit, _, body)| (hit.score, body.as_ref()),
        )?;
        let mut out = Vec::with_capacity(ranked.len());
        for ((hit, row, _), score) in ranked.into_iter().zip(scores) {
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
                score,
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
        // Scan inside the ONE read snapshot. Hidden edges are not results:
        // count only edges admitted by both endpoint and exact-pair gates.
        // The walk stops at `limit` admitted edges, so a high-degree node
        // never materializes its full edge set.
        lane.neighborhood_projected(
            &id,
            kind_filter,
            opts.min_weight,
            opts.limit,
            |txn, neighbors| {
                neighbors
                    .unwrap_or_default()
                    .into_iter()
                    .map(|neighbor| {
                        let edge = neighbor.edge;
                        Ok(NeighborHit {
                            short_id: self
                                .short_ref_of_in_txn(txn, &edge.target)?
                                .unwrap_or_else(|| edge.target.to_hex()),
                            kind: neighbor
                                .peer_type
                                .map_or_else(|| "UNKNOWN".to_owned(), kind_string_for_type),
                            edge_kind: edge.kind.name().to_owned(),
                            weight: edge.weight,
                            direction: if neighbor.outbound { "out" } else { "in" }.to_owned(),
                        })
                    })
                    .collect::<MemoryResult<Vec<_>>>()
            },
        )
    }

    /// [`Self::claim_view`] for a lens that serves claims it admitted
    /// itself: the weave report (OF-499).
    pub(crate) fn served_claim_view(
        &self,
        id: &EntityId,
        body: &ClaimBody,
    ) -> MemoryResult<ClaimView> {
        self.claim_view(id, body)
    }

    fn claim_view(&self, id: &EntityId, body: &ClaimBody) -> MemoryResult<ClaimView> {
        // A claim whose parts read as a secret together serves none of them.
        let secret = crate::batch::export::claim_reads_as_secret(body);
        let served = |value: &rmpv::Value| {
            if secret {
                serde_json::Value::String("[redacted]".to_owned())
            } else {
                served_value_json(value)
            }
        };
        Ok(ClaimView {
            claim_ref: id.to_hex(),
            short_ref: self.short_ref_of(id)?,
            predicate: if secret {
                "[redacted]".to_owned()
            } else {
                body.predicate.clone()
            },
            subject_ref: subject_ref_string(&body.subject),
            value: served(&body.value),
            confidence: body.confidence,
            approval: body.approval.as_str().to_owned(),
            lifecycle: body.lifecycle.as_str().to_owned(),
            source: body.source.map(|source| source.as_str().to_owned()),
            world_ref: body.world.map(|world| world.to_hex()),
            scope: body.scope.as_ref().map(served),
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

/// One unified-family receipt in the `vault.receipts` shape: the gate
/// fields it carries, its policy trace as reason codes, and every field it
/// carries with its trigger, job and principal refs.
fn family_receipt(record: crate::receipt::ReceiptRecord) -> MemoryReceipt {
    let crate::receipt::ReceiptRecord {
        receipt_id,
        receipt_kind,
        occurred_at,
        actor,
        on_behalf_of,
        outcome,
        job_ref,
        trigger_ref,
        policy_trace,
        mut fields,
    } = record;
    let claim_ref = trigger_ref
        .as_deref()
        .and_then(|reference| reference.strip_prefix("claim:"))
        .map(str::to_owned);
    for (key, value) in [
        ("trigger_ref", trigger_ref),
        ("job_ref", job_ref),
        ("on_behalf_of", on_behalf_of),
    ] {
        if let Some(value) = value {
            fields.entry(key.to_owned()).or_insert(value);
        }
    }
    MemoryReceipt {
        receipt_ref: receipt_id,
        kind: receipt_kind.as_str().to_owned(),
        outcome,
        created_at: occurred_at,
        reason_codes: policy_trace,
        actor_class: fields.get("actor_class").cloned().unwrap_or_default(),
        actor_ref: actor,
        content_kind: fields.get("content_kind").cloned().unwrap_or_default(),
        claim_ref,
        fields,
    }
}
