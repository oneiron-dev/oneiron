//! The follower's reply and receipts (FIX 7510): a suffix's batch readings
//! read back through its call's labels, each asked span exactly once, and
//! what each physical call reported of its cache, as the backend gave it.

use serde::Deserialize;

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::step_charge::reply_text;
use crate::EntityId;
use crate::dreamer_wake::SpanKind;
use crate::dreamer_wake::follower::{CacheResidency, CallEvidence};
use crate::dreamer_wake::sieve::follower::SpanReading;
use crate::llm::{DurableStepError, FatalLlmError, LlmError, LlmResponse};

const CACHE_DOMAIN: &[u8] = b"oneiron:dreamer-follower:cache-identity:v1";

/// A suffix's reply as the model writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReadings {
    readings: Vec<WireReading>,
}

/// One reading: the span's ordinal in the suffix, and its entity as one of
/// that span's candidate labels, never an id.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReading {
    span: usize,
    kind: SpanKind,
    novel: bool,
    confidence: u8,
    entity: Option<String>,
}

/// `response`'s readings, one per asked span in order. A reply that omits
/// or repeats a span, names a span it was not asked, or names an entity
/// outside that span's candidates is outside the contract.
pub(super) fn decode(
    response: &LlmResponse,
    labels: &CallLabelMap,
    candidates: &[Vec<EntityId>],
) -> std::result::Result<Vec<SpanReading>, String> {
    let outside = || "follower reading outside contract".to_owned();
    let wire: WireReadings = serde_json::from_str(reply_text(response).trim())
        .map_err(|_| "invalid follower readings JSON".to_owned())?;
    let mut readings: Vec<Option<SpanReading>> = vec![None; candidates.len()];
    for reading in wire.readings {
        let index = reading
            .span
            .checked_sub(1)
            .filter(|index| *index < candidates.len())
            .ok_or_else(outside)?;
        let entity = reading
            .entity
            .as_deref()
            .map(|label| {
                labels
                    .resolve_as(LabelKind::Entity, label)
                    .ok_or_else(outside)
            })
            .transpose()?;
        if reading.confidence > 100
            || entity.is_some_and(|id| !candidates[index].contains(&id))
            || readings[index].is_some()
        {
            return Err(outside());
        }
        readings[index] = Some(SpanReading {
            kind: reading.kind,
            entity,
            novel: reading.novel,
            confidence: reading.confidence,
        });
    }
    readings
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "follower readings omit a span".to_owned())
}

/// What one finished step's physical call reported. A memo replay made no
/// call: it carries no cache record, so nothing counts twice.
pub(super) fn evidence(
    response: &LlmResponse,
    step_hash: [u8; 32],
    memoized: bool,
) -> CallEvidence {
    CallEvidence {
        step_hash,
        memoized,
        input_tokens: response.usage.input.total,
        output_tokens: response.usage.output.total,
        cache_calls: if memoized {
            Vec::new()
        } else {
            response.usage.cache_calls()
        },
        residency: CacheResidency::Unknown,
    }
}

/// The last cache identity the backend named on this call, hashed; none
/// when it named none, or when a memo replayed.
pub(super) fn reported_cache(response: &LlmResponse, memoized: bool) -> Option<[u8; 32]> {
    if memoized {
        return None;
    }
    let identity = response
        .usage
        .cache_calls()
        .into_iter()
        .rev()
        .map(|call| call.identity)
        .find(|identity| !identity.is_empty())?;
    let bytes = serde_json::to_vec(&identity).ok()?;
    Some(
        *blake3::Hasher::new()
            .update(CACHE_DOMAIN)
            .update(&bytes)
            .finalize()
            .as_bytes(),
    )
}

/// Whether the provider refused the request itself, as an oversized one is
/// refused: its spans go back to their own rungs.
pub(super) fn refused_request(error: &DurableStepError) -> bool {
    matches!(
        error,
        DurableStepError::Llm(LlmError::Fatal(FatalLlmError::InvalidRequest))
            | DurableStepError::SpentLlm {
                source: LlmError::Fatal(FatalLlmError::InvalidRequest),
                ..
            }
            | DurableStepError::ClassifiedLlm {
                source: LlmError::Fatal(FatalLlmError::InvalidRequest),
                ..
            }
    )
}
