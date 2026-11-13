//! Turning vault-side records into the contract's response shapes.

use serde_json::Value;

use crate::context_pack::{
    ContextEntity, ContextPack, EmptyContext, EmptyReason, PackItemAccounting,
    PackItemAccountingReason, PackStats, PackTokenStats,
};
use crate::deletion::{MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState};
use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;
use crate::pipeline::Signal;
use crate::vault::Vault;

use super::context_pack::{
    CoreContextPackAccounting, CoreContextPackAccountingReason, CoreContextPackEdgeProvenance,
    CoreContextPackEdgeRecord, CoreContextPackEmpty, CoreContextPackEmptyReason,
    CoreContextPackEntityRecord, CoreContextPackItemTokenStats, CoreContextPackProjection,
    CoreContextPackSectionTokenStats, CoreContextPackSignal, CoreContextPackStats,
    CoreContextPackTokenStats, CoreContextPackVad,
};
use super::error::{NOT_FOUND_ENGINE_CODE, VaultReadError, VaultReadResult};
use super::types::{
    CoreBatchShortIdHydrateItem, CoreBodyOmitted, CoreEntityRecord, CoreHydrateResponse,
    CoreHydrateStatus, CoreMemoryTimelineRecord, CoreMemoryTimelineResponse,
    CoreShortIdHydrateOutcome, PROJECTION_BYTES_EXCEEDED_CODE, View,
};

/// Decodes already-clamped entity bytes into the public JSON projection.
/// Opaque bodies use the accepted server's lossless `bodyBytes` representation.
fn decode_scoped_body(body: &[u8]) -> Value {
    crate::batch::export::redacted_memory_body(body)
}

pub(super) fn entity_record_from_parts(
    id: &EntityId,
    entity_type: u8,
    learned_at: u64,
    score: Option<f32>,
    body: &[u8],
    view: View,
) -> CoreEntityRecord {
    let body = match view {
        View::Standard => None,
        View::Summary | View::Full => Some(decode_scoped_body(body)),
    };
    CoreEntityRecord {
        id: id.to_hex(),
        entity_type,
        learned_at,
        score,
        body,
        body_omitted: None,
    }
}

/// The stored body bytes one multi-row read may still decode, its host's
/// `[limits].projection_body_bytes` (H27), as the `/v1` doors bound theirs.
/// Each body is charged at its stored length before it decodes. A body the
/// rest of the budget cannot hold is not decoded, and the budget keeps its
/// credit.
#[derive(Debug)]
pub(super) struct ProjectionBodyBudget {
    bound: usize,
    remaining: usize,
}

impl ProjectionBodyBudget {
    pub(super) const fn new(bound: usize) -> Self {
        Self {
            bound,
            remaining: bound,
        }
    }

    /// Charges a body of `bytes` when the rest of the budget holds it.
    pub(super) fn admits(&mut self, bytes: usize) -> bool {
        match self.remaining.checked_sub(bytes) {
            Some(remaining) => {
                self.remaining = remaining;
                true
            }
            None => false,
        }
    }

    /// The bytes the rest of the budget holds: the bound an image's
    /// nothing-fits ask reports (FIX 680).
    pub(super) fn remaining(&self) -> u64 {
        u64::try_from(self.remaining).unwrap_or(u64::MAX)
    }

    /// The record of `row`, whose admitted body the budget left out: its id,
    /// kind, time and score, and the marker in place of the body, which was
    /// never decoded. The marker's ref is the row's short id with its stored
    /// revision's content hash, or its hex id when it has no short id.
    pub(super) fn omitted(&self, vault: &Vault, row: OmittedRow) -> CoreEntityRecord {
        let OmittedRow {
            id,
            entity_type,
            learned_at,
            score,
            body_bytes,
            content_hash,
        } = row;
        let short =
            crate::retrieval_depth::short_ref_or_hex(vault, &id).unwrap_or_else(|_| id.to_hex());
        let reference = match short.split_once(':') {
            Some((name, _)) => format!("{name}:{content_hash:02x}"),
            None => short,
        };
        CoreEntityRecord {
            id: id.to_hex(),
            entity_type,
            learned_at,
            score,
            body: None,
            body_omitted: Some(CoreBodyOmitted {
                code: PROJECTION_BYTES_EXCEEDED_CODE.to_owned(),
                max_bytes: u64::try_from(self.bound).unwrap_or(u64::MAX),
                body_bytes: u64::try_from(body_bytes).unwrap_or(u64::MAX),
                reference,
            }),
        }
    }
}

/// The facts of an admitted row that [`ProjectionBodyBudget::omitted`]
/// projects without its body.
pub(super) struct OmittedRow {
    pub(super) id: EntityId,
    pub(super) entity_type: u8,
    pub(super) learned_at: u64,
    pub(super) score: Option<f32>,
    /// The stored length of the body left out.
    pub(super) body_bytes: usize,
    /// The content-hash byte of the stored revision the row was read from.
    pub(super) content_hash: u8,
}

fn project_signal(signal: Signal) -> CoreContextPackSignal {
    match signal {
        Signal::Vector => CoreContextPackSignal::Vector,
        Signal::Text => CoreContextPackSignal::Text,
        Signal::Phonetic => CoreContextPackSignal::Phonetic,
        Signal::Temporal => CoreContextPackSignal::Temporal,
        Signal::Ppr => CoreContextPackSignal::Ppr,
        Signal::Hyde => CoreContextPackSignal::Hyde,
    }
}

fn project_accounting(accounting: PackItemAccounting) -> CoreContextPackAccounting {
    CoreContextPackAccounting {
        count: accounting.count,
        reason: match accounting.reason {
            PackItemAccountingReason::ItemBudget => CoreContextPackAccountingReason::ItemBudget,
            PackItemAccountingReason::TokenBudget => CoreContextPackAccountingReason::TokenBudget,
        },
    }
}

fn project_token_stats(tokens: &PackTokenStats) -> CoreContextPackTokenStats {
    CoreContextPackTokenStats {
        tokenizer_id: tokens.tokenizer_id.clone(),
        total_tokens: tokens.total_tokens,
        sections: tokens
            .sections
            .iter()
            .map(|section| CoreContextPackSectionTokenStats {
                section: section.section.clone(),
                tokens: section.tokens,
            })
            .collect(),
        items: tokens
            .items
            .iter()
            .map(|item| CoreContextPackItemTokenStats {
                section: item.section.clone(),
                id: item.id.clone(),
                entity_type: item.entity_type,
                tokens: item.tokens,
            })
            .collect(),
    }
}

fn project_pack_stats(stats: &PackStats) -> CoreContextPackStats {
    CoreContextPackStats {
        candidates_considered: stats.candidates_considered,
        signals_used: stats
            .signals_used
            .iter()
            .copied()
            .map(project_signal)
            .collect(),
        query_time_us: stats.query_time_us,
        entities_hydrated: stats.entities_hydrated,
        neighbors_hydrated: stats.neighbors_hydrated,
        cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
        claims_suppressed: stats.claims_suppressed,
        deadline_exceeded: stats.deadline_exceeded,
        tokens: project_token_stats(&stats.tokens),
        items_truncated: project_accounting(stats.items_truncated),
        items_dropped: project_accounting(stats.items_dropped),
    }
}

fn project_context_edge(edge: &EdgeInfo) -> CoreContextPackEdgeRecord {
    CoreContextPackEdgeRecord {
        kind: edge.kind as u8,
        target: edge.target.to_hex(),
        target_short_id: edge.target_short_id.clone(),
        weight: edge.weight,
        created_at: edge.created_at,
        vad: edge.vad.map(|vad| CoreContextPackVad {
            valence: vad.valence,
            arousal: vad.arousal,
            dominance: vad.dominance,
        }),
        provenance: edge.provenance.map(|flags| CoreContextPackEdgeProvenance {
            confirmation_status: flags.confirmation_status as u8,
            actor_class: flags.actor_class as u8,
        }),
    }
}

fn project_context_entity(entity: &ContextEntity) -> CoreContextPackEntityRecord {
    CoreContextPackEntityRecord {
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        content_hash: entity.content_hash,
        entity_type: entity.entity_type,
        score: entity.score,
        fields: entity.fields.as_ref().map(|fields| {
            let mut value = Value::Object(fields.clone().into_iter().collect());
            crate::batch::export::redact_credentials(&mut value);
            value
                .as_object()
                .expect("redactor preserves object")
                .clone()
                .into_iter()
                .collect()
        }),
        edges: entity
            .edges
            .as_ref()
            .map(|edges| edges.iter().map(project_context_edge).collect()),
        vector: entity.vector.clone(),
    }
}

fn project_empty_context(empty: &EmptyContext) -> CoreContextPackEmpty {
    CoreContextPackEmpty {
        reason: match empty.reason {
            EmptyReason::FilterMatchedNone => CoreContextPackEmptyReason::FilterMatchedNone,
            EmptyReason::NoData => CoreContextPackEmptyReason::NoData,
            EmptyReason::AllActivated => CoreContextPackEmptyReason::AllActivated,
            EmptyReason::BelowThreshold => CoreContextPackEmptyReason::BelowThreshold,
            EmptyReason::SkippedByProfile => CoreContextPackEmptyReason::SkippedByProfile,
        },
        total_in_scope: empty.total_in_scope,
        hint: empty.hint.clone(),
    }
}

/// Consumes the already-filtered pack and copies every public field into the
/// local serializable projection. No facade helper is involved.
pub(super) fn project_context_pack(
    pack: &ContextPack,
    narrowing: crate::claim::ScopedReadReceipt,
) -> CoreContextPackProjection {
    CoreContextPackProjection {
        capabilities: pack.capabilities.clone(),
        access: crate::access_grant::GrantedData::new(
            pack.results
                .iter()
                .chain(&pack.neighbors)
                .map(|row| row.id.to_hex())
                .collect(),
            narrowing.suppressed_count,
        ),
        narrowing,
        results: pack.results.iter().map(project_context_entity).collect(),
        neighbors: pack.neighbors.iter().map(project_context_entity).collect(),
        instruction_files: pack.instruction_files.clone(),
        stats: project_pack_stats(&pack.stats),
        empty: pack.empty.as_ref().map(project_empty_context),
        limit_clamped: false,
    }
}

fn project_timeline_record(record: &MemoryTimelineRecord) -> CoreMemoryTimelineRecord {
    CoreMemoryTimelineRecord {
        id: record.id.to_hex(),
        state: record.state,
        entity_type: record.entity_type,
        occurred_start: record.occurred_start,
        occurred_end: record.occurred_end,
        learned_at: record.learned_at,
        body_bytes: record.body_bytes,
        deletion: record.deletion.clone(),
        supersedes: record.supersedes.iter().map(EntityId::to_hex).collect(),
        superseded_by: record.superseded_by.iter().map(EntityId::to_hex).collect(),
    }
}

pub(super) fn project_memory_timeline(
    timeline: &crate::claim::ScopedReadResult<MemoryTimeline>,
) -> CoreMemoryTimelineResponse {
    CoreMemoryTimelineResponse {
        narrowing: timeline.receipt.clone(),
        anchor_id: timeline.anchor.to_hex(),
        records: timeline
            .records
            .iter()
            .map(project_timeline_record)
            .collect(),
    }
}

/// Accepted timeline absence predicate: no records at all, or exactly one
/// `Missing` record.
pub(super) fn timeline_is_absent(timeline: &MemoryTimeline) -> bool {
    timeline.records.is_empty()
        || matches!(
            timeline.records.as_slice(),
            [record] if record.state == MemoryTimelineRecordState::Missing
        )
}

/// Narrow batch absence conversion: only accepted-route absence becomes a
/// per-item `NotFound`. Every other failure aborts the whole batch call.
pub(super) fn batch_item_from_result(
    reference: String,
    result: VaultReadResult<CoreHydrateResponse>,
) -> VaultReadResult<CoreBatchShortIdHydrateItem> {
    match result {
        Ok(response) => {
            let outcome = match response.status {
                CoreHydrateStatus::Live => CoreShortIdHydrateOutcome::Live,
                CoreHydrateStatus::Deleted => CoreShortIdHydrateOutcome::Deleted,
            };
            Ok(CoreBatchShortIdHydrateItem {
                reference,
                outcome,
                result: Some(response),
            })
        }
        Err(VaultReadError::Engine { engine_code, .. }) if engine_code == NOT_FOUND_ENGINE_CODE => {
            Ok(CoreBatchShortIdHydrateItem {
                reference,
                outcome: CoreShortIdHydrateOutcome::NotFound,
                result: None,
            })
        }
        Err(other) => Err(other),
    }
}
