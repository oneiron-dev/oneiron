//! Why a context pack came back empty, at each serialization stage.

use std::collections::HashSet;

use crate::pipeline::Signal;
use crate::serialize::SerializedPackTelemetry;
use crate::store::RetrievalSignal;

use super::types::{ContextPack, PackStats};

/// Machine-readable reason an otherwise successful context-pack query surfaced
/// no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Structured context for an empty context-pack response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyContext {
    pub reason: EmptyReason,
    pub total_in_scope: usize,
    pub hint: String,
}

pub(super) fn context_pack_empty_reason(
    pack: &ContextPack,
    surfaced_result_ids: &[[u8; 16]],
) -> Option<String> {
    if !surfaced_result_ids.is_empty() {
        return None;
    }
    let reason = pack
        .empty
        .as_ref()
        .map_or(EmptyReason::FilterMatchedNone, |empty| empty.reason);
    Some(format!("{reason:?}"))
}

pub(super) fn serialized_context_pack_empty_reason(
    pack: &ContextPack,
    telemetry: &SerializedPackTelemetry,
) -> Option<String> {
    if !telemetry.result_ids.is_empty() {
        return None;
    }
    if !pack.results.is_empty()
        && telemetry.stats.items_dropped.count > pack.stats.items_dropped.count
    {
        return Some(format!("{:?}", telemetry.stats.items_dropped.reason));
    }
    context_pack_empty_reason(pack, &telemetry.result_ids)
}

pub(super) fn projected_context_pack_empty_reason(
    pack: &ContextPack,
    pre_projection_stats: &PackStats,
    pre_projection_had_results: bool,
    surfaced_result_ids: &[[u8; 16]],
) -> Option<String> {
    if !surfaced_result_ids.is_empty() {
        return None;
    }
    if pre_projection_had_results
        && pack.stats.items_dropped.count > pre_projection_stats.items_dropped.count
    {
        return Some(format!("{:?}", pack.stats.items_dropped.reason));
    }
    context_pack_empty_reason(pack, surfaced_result_ids)
}

/// Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
/// 2026-08-19 — needs wiring/design completion.
pub fn refresh_projected_empty_context(pack: &mut ContextPack) {
    if !pack.results.is_empty() || !pack.neighbors.is_empty() {
        pack.empty = None;
        return;
    }
    if pack.empty.is_some() {
        return;
    }

    let reason = if pack.stats.candidates_considered == 0 {
        EmptyReason::NoData
    } else {
        EmptyReason::FilterMatchedNone
    };
    let hint = if pack.stats.items_dropped.count > 0 {
        match pack.stats.items_dropped.reason {
            crate::context_pack::PackItemAccountingReason::TokenBudget => {
                "Raise budget.token_budget or request a less restrictive view to return context-pack results"
            }
            crate::context_pack::PackItemAccountingReason::ItemBudget => {
                "Raise budget.max_item_tokens or request a less restrictive view to return context-pack results"
            }
        }
    } else {
        empty_hint(reason)
    };
    pack.empty = Some(EmptyContext {
        reason,
        total_in_scope: pack.stats.candidates_considered,
        hint: hint.to_owned(),
    });
}

pub(super) fn pack_signal_from_retrieval(signal: RetrievalSignal) -> Signal {
    match signal {
        RetrievalSignal::Vector => Signal::Vector,
        RetrievalSignal::Text => Signal::Text,
        RetrievalSignal::Phonetic => Signal::Phonetic,
        RetrievalSignal::Temporal => Signal::Temporal,
        RetrievalSignal::Ppr => Signal::Ppr,
        RetrievalSignal::Hyde => Signal::Hyde,
        RetrievalSignal::HydeRetry => {
            unreachable!("HyDE retry trace markers are not context-pack retrieval channels")
        }
        RetrievalSignal::Recency
        | RetrievalSignal::Salience
        | RetrievalSignal::Confidence
        | RetrievalSignal::Gravity
        | RetrievalSignal::Rerank => {
            unreachable!("blend/rerank score components are not context-pack retrieval channels")
        }
    }
}

pub(super) fn dedupe_signals(signals: Vec<Signal>) -> Vec<Signal> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(signals.len());
    for signal in signals {
        if seen.insert(signal) {
            deduped.push(signal);
        }
    }
    deduped
}

pub(super) fn empty_context(
    pack_is_empty: bool,
    stats: &PackStats,
    pipeline_reason: Option<EmptyReason>,
) -> Option<EmptyContext> {
    if !pack_is_empty {
        return None;
    }

    let reason = match pipeline_reason {
        Some(reason) => reason,
        None if stats.candidates_considered == 0 => EmptyReason::NoData,
        None => EmptyReason::FilterMatchedNone,
    };

    Some(EmptyContext {
        reason,
        total_in_scope: stats.candidates_considered,
        hint: empty_hint(reason).to_owned(),
    })
}

fn empty_hint(reason: EmptyReason) -> &'static str {
    match reason {
        EmptyReason::FilterMatchedNone => {
            "Try removing filters or widening the world, type, or time scope"
        }
        EmptyReason::NoData => "Add data to the vault or broaden the query scope",
        EmptyReason::AllActivated => {
            "All matching items are already activated; allow activated results to revisit them"
        }
        EmptyReason::BelowThreshold => "Try broadening the query or lowering the result threshold",
    }
}
