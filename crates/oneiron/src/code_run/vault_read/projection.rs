//! Turning vault-side records into the contract's response shapes.

use std::io::Cursor;

use serde_json::Value;

use crate::companion::companion_value_to_json;
use crate::context_pack::{
    ContextEntity, ContextPack, EmptyContext, EmptyReason, PackItemAccounting,
    PackItemAccountingReason, PackStats, PackTokenStats,
};
use crate::deletion::{MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState};
use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;
use crate::pipeline::Signal;

use super::context_pack::{
    CoreContextPackAccounting, CoreContextPackAccountingReason, CoreContextPackEdgeProvenance,
    CoreContextPackEdgeRecord, CoreContextPackEmpty, CoreContextPackEmptyReason,
    CoreContextPackEntityRecord, CoreContextPackItemTokenStats, CoreContextPackProjection,
    CoreContextPackSectionTokenStats, CoreContextPackSignal, CoreContextPackStats,
    CoreContextPackTokenStats, CoreContextPackVad,
};
use super::error::{NOT_FOUND_ENGINE_CODE, VaultReadError, VaultReadResult};
use super::types::{
    CoreBatchShortIdHydrateItem, CoreEntityRecord, CoreHydrateResponse, CoreHydrateStatus,
    CoreMemoryTimelineRecord, CoreMemoryTimelineResponse, CoreShortIdHydrateOutcome, View,
};

/// Decodes already-clamped entity bytes into the public JSON projection.
/// Opaque bodies use the accepted server's lossless `bodyBytes` representation.
fn decode_scoped_body(body: &[u8]) -> Value {
    let mut cursor = Cursor::new(body);
    if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == body.len() as u64
    {
        return companion_value_to_json(&value);
    }
    serde_json::json!({ "bodyBytes": body })
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
    }
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
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
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
        },
        total_in_scope: empty.total_in_scope,
        hint: empty.hint.clone(),
    }
}

/// Consumes the already-filtered pack and copies every public field into the
/// local serializable projection. No facade helper is involved.
pub(super) fn project_context_pack(pack: &ContextPack) -> CoreContextPackProjection {
    CoreContextPackProjection {
        results: pack.results.iter().map(project_context_entity).collect(),
        neighbors: pack.neighbors.iter().map(project_context_entity).collect(),
        stats: project_pack_stats(&pack.stats),
        empty: pack.empty.as_ref().map(project_empty_context),
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

pub(super) fn project_memory_timeline(timeline: &MemoryTimeline) -> CoreMemoryTimelineResponse {
    CoreMemoryTimelineResponse {
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
